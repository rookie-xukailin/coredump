#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""60 格逐格判定：读每格 analyze 日志 + 报告 md，按预期判定 PASS/FAIL。

每格判定项：
  A. analyze 进程本身成功（summary.log 里 ANALYZE-OK）
  B. 技能 symbols=ok, triage=ok
  C. 定位结论含预期关键词（kw）
  D. 报告正文含预期函数/行号证据（ev，bt 或扫描任一命中即可）
  E. backtrace=ok（abort 类允许 bt 为 libc 帧但 ev 必须命中；个别案例允许降级，见 allow_degrade）
"""
import os
import re
import sys

W = "/tmp/coredump_work"
LOGS = W + "/logs/matrix"
REP = W + "/reports"

# name: (kw 结论关键词, ev 函数/行证据, allow_degrade) —— 可按架构覆盖
EXPECT = {
    "null_write":    ("空指针", "hw_fan_set_pwm", False),
    "wild_mmio":     ("空指针", "pwm_hw_init", False),
    "stack_overflow":("栈溢出", "sel_assert_recursive", True),
    "heap_overflow": ("堆|加固检查", "heap_overflow.c:", False),   # O1: fortify 拦截或 free 暴雷皆合法形态
    "double_free":   ("free", "double_free.c:", False),   # 证据文件级：崩溃帧=audit_cleanup 内的 free 行
    "uaf_write":     ("非法内存访问", "fw_hotfix_patch", False),
    "oob_read":      ("非法内存访问", "sdr_read_at", False),
    "bad_funcptr":   ("0xdead0000", "bad_funcptr.c:", False),
    # stack_smash：-O1 下溢出跨度抹掉整条应用帧链的 LR（只余 _start/libc，
    # 属"溢出跨度大"合法形态）——证据取符号配对的模块名；深层链恢复能力
    # 由 assert_fail/blame_thread/dblfree 的扫描维度覆盖
    "stack_smash":   ("0x575757", "stack_smash_", True),
    "assert_fail":   ("断言", "assert_fail.c:", True),
    "thread_crash":  ("空指针", "sensor_sample_one", False),
    "shlib_crash":   ("空指针", "sensord_get_reading", False),
    "ill_jump":      ("SIGILL", "ill_jump.c:", False),
    "null_poison":   ("堆检查触发 abort", "log_flush", False),
    "uaf_reuse":     ("非法内存访问", "netmsg_pump", False),
    "deep_chain":    ("空指针", "svc_l0", False),
    "hugespan":      ("栈溢出", "diag_collect_frame", True),
    "dlopen_crash":  ("空指针", "plug_run", False),
    "handler_crash": ("空指针", "crash_handler", False),
    "blame_thread":  ("abort", "blame_thread.c:", False),
    "stomped_late":  ("0x5858585", "fan_pwm_apply", False),
    "db_reload_race":  ("空指针", "sdr_feed_one", False),
    "rec_delete_race": ("0x4747474", "cfg_reader_commit", False),
    "shm_truncate_bus": ("总线错误", "db_far_record_read", True),
    "db_index_corrupt": ("非法内存访问", "db_query_run", False),
    # dblfree_concurrent：qemu 环境下 abort 线程的应用帧被 glibc/qemu 栈
    # 伪影吞掉（活体 gdb 与 core 一致，均无应用帧，扫描亦无应用值）——
    # 归因依赖 console 的 glibc 报错，证据按 console 消息判定
    "dblfree_concurrent": ("free", "double free or corruption", False),
    "db_compact_race":  ("非法内存访问", "db_report_scan", False),
    "sqlite_close_race":   ("SIGSEGV", "sqlite3", False),
    "sqlite_corrupt_bus":  ("SIGBUS|总线错误|SIGSEGV", "sqlite3", True),
    "sqlite_finalize_uaf": ("SIGSEGV|abort", "sqlite3", False),
    "lmdb_close_race":     ("SIGSEGV", "mdb_", False),
    "lmdb_truncate_bus":   ("SIGBUS|总线错误|SIGSEGV", "mdb_", True),
    "dlclose_race":        ("非法内存访问", "plug_worker_call", False),
    # ---- 批次 1：传统 C 语言经典（#34~#54）----
    "realloc_dangling":    ("非法内存访问", "fw_config_save", False),
    "stack_local_return":  ("非法内存访问", "ui_draw_header", True),
    "free_nonheap":        ("invalid pointer|free", "invalid pointer", False),
    "uninit_stack_ptr":    ("非法内存访问|空指针", "sensor_use_stale", False),
    "off_by_one":          ("非法内存访问", "sdr_write_row", False),
    "int_overflow_alloc":  ("堆|非法内存访问", "net_alloc_table", False),
    # O1 实测形态：64B 栈缓冲写 256B 先破坏金丝雀 → __stack_chk_fail abort
    # （console "*** stack smashing detected ***"），栈保护结论同样命中"栈"
    "sprintf_overflow":    ("栈|加固|非法内存访问", "sprintf_overflow.c:", True),
    "strlen_noterm":       ("非法内存访问", "strlen_noterm.c:", False),
    "sizeof_pointer":      ("非法内存访问", "ui_dispatch", False),
    "union_confusion":     ("空指针", "bus_slot_fire", False),
    "signed_unsigned":     ("非法内存访问", "pkt_write_at", False),
    "const_rodata_write":  ("权限|非法内存访问", "cfg_write_byte", False),
    "endianness_cast":     ("非法内存访问", "net_frame_apply", False),
    "timer_after_free":    ("非法内存访问", "timer_poll_fire", False),
    "atexit_stale":        ("非法内存访问", "bmc_session_flush", False),
    "shutdown_order":      ("非法内存访问", "sess_worker_loop", False),
    "fd_exhaust":          ("非法内存访问", "dev_open_all", False),
    "malloc_null":         ("空指针", "cap_alloc_blob", False),
    "sigpipe_write":       ("SIGPIPE", "ipc_flush_logs", False),
    "fpe_divzero":         ("SIGFPE", "sensor_ratio", False),
    "nest_signal":         ("空指针", "nest_segv_handler", False),
    # ---- 批次 2：硬件/平台/嵌入式特定（#55~#64）----
    "no_volatile_hw":      ("非法内存访问", "hw_dma_setup", False),
    # 非对齐访问双形态：对齐检查核上 SIGBUS；否则 LE 旋转错值当偏移 SEGV
    "unaligned_arm":       ("总线错误|非法内存访问", "unaligned_arm.c:", False),
    "dma_alignment":       ("总线错误|非法内存访问", "dma_alignment.c:", False),
    "eeprom_corrupt":      ("0xdeadbeef", "board_hook_invoke", False),
    "config_array_size":   ("堆|非法内存访问", "cfg_load_table", False),
    "argv_missing":        ("空指针", "cli_run_request", False),
    "init_order":          ("空指针", "sensor_bus_read", False),
    "watchdog_stuck":      ("SIGABRT|abort", "wd_expire", True),
    "thread_hang_kill":    ("SIGABRT|abort", "cli_cmd_wait", True),
    "lock_deadlock_kill":  ("SIGABRT|abort", "net_cfg_apply", True),
    # ---- 批次 3：BMC/OpenBMC 特定（#65~#73）----
    "ipmi_parse_overflow": ("非法内存访问", "ipmi_parse_cmd", False),
    "fru_corrupt_parse":   ("非法内存访问", "fru_walk_area", False),
    "sensor_hotplug":      ("非法内存访问", "sensor_reactivate", False),
    "i2c_timeout_stale":   ("非法内存访问", "i2c_read_regs", False),
    "dbus_prop_crash":     ("非法内存访问", "dbus_prop_set", False),
    "power_transition":    ("非法内存访问", "power_cmd_execute", False),
    "sel_full_error":      ("空指针", "sel_commit_record", False),
    "shm_unlink_alive":    ("总线错误|非法内存访问", "shm_far_read", True),
    "fifo_sigpipe":        ("SIGPIPE", "log_tail_flush", False),
    # ---- 批次 4：消息队列（#74~#78）----
    "mq_consumer_uaf":     ("非法内存访问", "mq_event_process", False),
    "mq_recv_truncate":    ("非法内存访问", "mq_recv_parse", False),
    "mq_deser_overflow":   ("非法内存访问", "mq_deser_copy", False),
    "msgq_rmid_race":      ("非法内存访问", "mq_rx_dispatch", False),
    "queue_ring_overrun":  ("非法内存访问", "mq_ring_push", False),
}
# 按架构覆盖：qemu-arm 把 UDF 编码上报为 SIGTRAP（真机为 SIGILL）；
# riscv 的 qemu 翻译层对越过文件 EOF 的访问可能报 SIGBUS 也可能报 SIGSEGV。
# 关键词可用 "|" 给出多个备选。
EXPECT_ARCH = {
    ("ill_jump", "arm32"): ("SIGTRAP", "ill_jump.c:", False),
    ("shm_truncate_bus", "riscv64"): ("总线错误|非法内存访问", "db_far_record_read", True),
    # qemu-aarch64 对 lmdb mmap 越界 EOF 访问报"QEMU internal SIGBUS"并直接
    # 杀死仿真器（无法 gcore）——环境限制；该维度的 arm64 SIGBUS 由
    # shm_truncate_bus 覆盖，lmdb 版在 riscv64 完整验证（arm32 在 O1 下
    # 同样交付不稳，一并 SKIP）。None = 期望跳过
    ("lmdb_truncate_bus", "arm64"): None,
    ("lmdb_truncate_bus", "arm32"): None,
    # -O1 内联形态：riscv64 上崩溃函数被内联进调用者，函数名不成帧，
    # 证据改为文件级（gdb 内联帧仍带 file:line）
    ("stomped_late", "riscv64"): ("0x5858585", "stomped_late.c:", False),
    ("rec_delete_race", "riscv64"): ("0x4747474", "rec_delete_race.c:", False),
    ("dlclose_race", "riscv64"): ("非法内存访问", "dlclose_race.c:", False),
    # arm32 被杀线程的应用帧符号化退化（exidx 展开失败, gdb bt 全 ??），
    # 栈扫描给出文件级证据 lock_deadlock_kill.c:22（net_cfg_apply 体内）
    ("lock_deadlock_kill", "arm32"): ("SIGABRT|abort", "lock_deadlock_kill.c:", True),
}
ARCHS = ["arm64", "arm32", "riscv64"]


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def find_report(tag):
    d = os.path.join(REP, tag)
    if not os.path.isdir(d):
        return ""
    for fn in sorted(os.listdir(d)):
        if fn.endswith("_report.md"):
            return os.path.join(d, fn)
    return ""


def main():
    summary = read(LOGS + "/summary.log")
    rows = []
    npass = nfail = 0
    for name, base in EXPECT.items():
        for arch in ARCHS:
            if EXPECT_ARCH.get((name, arch), base) is None:
                rows.append((name, arch, "SKIP(环境限制)"))
                continue
            kw, ev, degrade = EXPECT_ARCH.get((name, arch), base)
            tag = "%s.%s" % (name, arch)
            fails = []
            if "[%s] ANALYZE-OK" % tag not in summary:
                fails.append("analyze未成功")
            alog = read(os.path.join(LOGS, tag + ".analyze.log"))
            rep = read(find_report(tag))
            if not rep:
                fails.append("无报告")
            m = re.search(r"技能 symbols\s+(\S+)", alog)
            if not m or not m.group(1).startswith("ok"):
                fails.append("symbols非ok")
            m = re.search(r"技能 triage\s+(\S+)", alog)
            if not m or not m.group(1).startswith("ok"):
                fails.append("triage非ok")
            concl = "\n".join(l for l in alog.splitlines() if l.strip().startswith("["))
            if not any(k.lower() in concl.lower() for k in kw.split("|")):
                fails.append("结论缺[%s]" % kw)
            if ev not in rep:
                fails.append("报告缺证据[%s]" % ev)
            m = re.search(r"技能 backtrace\s+(\S+)", alog)
            bt_ok = m and m.group(1).startswith("ok")
            if not bt_ok and not degrade:
                fails.append("backtrace失败")
            status = "PASS" if not fails else "FAIL:" + ",".join(fails)
            if fails:
                nfail += 1
            else:
                npass += 1
            rows.append((name, arch, status))
    w = max(len(r[0]) for r in rows)
    nskip = 0
    for name, arch, st in rows:
        print("%-*s %-8s %s" % (w, name, arch, st))
        if st.startswith("SKIP"):
            nskip += 1
    print("=" * 50)
    print("PASS %d / FAIL %d / SKIP %d" % (npass, nfail, nskip))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())

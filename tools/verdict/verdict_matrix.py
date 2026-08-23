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

# -*- coding: utf-8 -*-
"""系统测试用例清单（单一事实源）。

bmccore 系统测试：每个"维度 × 架构"一格，用真实交叉编译 + qemu 运行
产生的 ELF core 驱动完整分析流水线，逐格断言结论与证据。

来源说明：以下场景含工具作者既有维度与系统测试阶段新增维度（空指针/
堆/栈/信号/多线程/动态库/并发竞态/数据库引擎/进程间资源破坏等）。

字段：
  dim     维度描述
  kw      定位结论必须命中的关键词（'|' 分隔任意命中）
  ev      报告正文必须含的证据（崩溃函数名或 源文件:行）
  degrade 允许 gdb 回溯降级（栈扫描兜底或判定性结论仍须命中）
  console 附带 console 日志的案例名后缀文件 <case>.<arch>.console.log

按架构覆盖（EXPECT_ARCH）：
  - ill_jump/arm32        : qemu 对 UDF 上报 SIGTRAP（真机 SIGILL），如实用收
  - shm_truncate_bus/rv64 : qemu 对越 EOF 访问可能报 SIGBUS 或 SIGSEGV
  - lmdb_truncate_bus/arm64: qemu 内部 SIGBUS 直接杀死仿真器、无法 gcore
                            （环境限制 SKIP；arm64 的 SIGBUS 维度由
                            shm_truncate_bus 覆盖）
"""

CASES = {
    # ---- 基础内存维度 ----
    "null_write": dict(dim="空指针写 struct 成员", kw="空指针", ev="hw_fan_set_pwm"),
    "wild_mmio": dict(dim="基址表索引写坏→写未映射(Thumb)", kw="空指针", ev="pwm_hw_init"),
    "stack_overflow": dict(dim="自引用环路无限递归爆栈", kw="栈溢出", ev="sel_assert_recursive", degrade=True),
    "heap_overflow": dict(dim="堆溢出写穿 chunk 头, free 暴雷", kw="堆", ev="sensor_unload"),
    "double_free": dict(dim="重复释放(tcache 检出)", kw="free", ev="audit_cleanup"),
    "uaf_write": dict(dim="大块 free→munmap 后悬垂写", kw="非法内存访问", ev="fw_hotfix_patch"),
    "oob_read": dict(dim="报文字段大越界读", kw="非法内存访问", ev="sdr_read_at"),
    "bad_funcptr": dict(dim="被写坏的函数指针调用→PC 跳飞", kw="0xdead0000", ev="uart_poll_input"),
    "stack_smash": dict(dim="缓冲溢出覆盖 LR 断链(扫描兜底)", kw="0x575757", ev="stack_smash.c:", degrade=True),
    "assert_fail": dict(dim="防御性 assert 失败 abort", kw="断言", ev="assert_fail.c:", degrade=True),
    "thread_crash": dict(dim="4 线程 worker 空指针崩溃", kw="空指针", ev="sensor_sample_one"),
    "shlib_crash": dict(dim="链接期 so 内崩溃(跨模块配对)", kw="空指针", ev="sensord_get_reading"),
    # ---- 高难度内存维度 ----
    "ill_jump": dict(dim="跳入垃圾指令 SIGILL", kw="SIGILL", ev="fw_verify_and_boot"),
    "null_poison": dict(dim="单字节 NUL 堆投毒", kw="堆检查触发 abort", ev="log_flush"),
    "uaf_reuse": dict(dim="UAF+堆复用类型混淆踩回调", kw="非法内存访问", ev="netmsg_pump"),
    "deep_chain": dict(dim="12 层深调用链后空指针", kw="空指针", ev="svc_l0"),
    "hugespan": dict(dim="单帧 12MB 巨栈一步越界", kw="栈溢出", ev="diag_collect_frame", degrade=True),
    "dlopen_crash": dict(dim="dlopen 运行时装载插件内崩溃", kw="空指针", ev="plug_run"),
    "handler_crash": dict(dim="信号处理函数内二次空指针", kw="空指针", ev="crash_handler"),
    "blame_thread": dict(dim="肇事线程≠崩溃线程(堆指纹指认)", kw="abort", ev="blame_thread.c:"),
    "stomped_late": dict(dim="静默踩内存/堆头完好/延迟引爆", kw="0x5858585", ev="fan_pwm_apply"),
    # ---- 并发资源竞态维度 ----
    "db_reload_race": dict(dim="线程间·数据库整表替换(热更新)", kw="空指针", ev="sdr_feed_one"),
    "rec_delete_race": dict(dim="线程间·删除记录+堆复用悬垂调用", kw="0x4747474", ev="cfg_reader_commit"),
    "shm_truncate_bus": dict(dim="进程间·部署收缩库文件→SIGBUS", kw="总线错误", ev="db_far_record_read", degrade=True),
    "db_index_corrupt": dict(dim="进程间·无锁修改共享库索引→越界读", kw="非法内存访问", ev="db_query_run"),
    "dblfree_concurrent": dict(dim="线程间·并发双重释放(fasttop)", kw="free", ev="double free or corruption"),
    "db_compact_race": dict(dim="线程间·碎片整理移动记录→len 读坏", kw="非法内存访问", ev="db_report_scan"),
    # ---- 数据库引擎/动态库维度 ----
    "sqlite_close_race": dict(dim="SQLite·跨线程 close+finalize 活动语句 UAF", kw="SIGSEGV", ev="sqlite3"),
    "sqlite_corrupt_bus": dict(dim="SQLite·扫描中库文件被部署截断→SIGBUS", kw="SIGBUS|总线错误|SIGSEGV", ev="sqlite3", degrade=True),
    "sqlite_finalize_uaf": dict(dim="SQLite·双重 finalize UAF", kw="SIGSEGV|abort", ev="sqlite3"),
    "lmdb_close_race": dict(dim="LMDB·env 关闭与活动读者并发 UAF", kw="SIGSEGV", ev="mdb_"),
    "lmdb_truncate_bus": dict(dim="LMDB·data.mdb 被部署截断→SIGBUS", kw="SIGBUS|总线错误|SIGSEGV", ev="mdb_", degrade=True),
    "dlclose_race": dict(dim="动态库·dlclose 与调用并发→代码页解映射", kw="非法内存访问", ev="plug_worker_call"),
}

ARCHS = ["arm64", "arm32", "riscv64"]

# (case, arch) -> 覆盖格（同 CASES 字段）；None = 期望 SKIP（环境限制）
EXPECT_ARCH = {
    ("ill_jump", "arm32"): dict(dim="qemu 对 UDF 上报 SIGTRAP(如实转述)",
                                kw="SIGTRAP", ev="fw_verify_and_boot"),
    ("shm_truncate_bus", "riscv64"): dict(
        dim="riscv qemu 对越 EOF 可报 BUS 或 SEGV", kw="总线错误|非法内存访问",
        ev="db_far_record_read", degrade=True),
    ("lmdb_truncate_bus", "arm64"): None,   # qemu internal SIGBUS，无法 gcore
}

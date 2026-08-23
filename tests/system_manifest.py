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
    # O1 基线：Ubuntu 默认 _FORTIFY_SOURCE 可能在拷贝点拦截（加固 abort），
    # 也可能穿透到 free 暴雷——两种形态工具均可归因，均判合格
    "heap_overflow": dict(dim="堆溢出写穿 chunk 头(fortify拦截/free暴雷皆可)",
                          kw="堆|加固检查", ev="heap_overflow.c:"),
    "double_free": dict(dim="重复释放(tcache 检出)", kw="free", ev="double_free.c:"),
    "uaf_write": dict(dim="大块 free→munmap 后悬垂写", kw="非法内存访问", ev="fw_hotfix_patch"),
    "oob_read": dict(dim="报文字段大越界读", kw="非法内存访问", ev="sdr_read_at"),
    "bad_funcptr": dict(dim="被写坏的函数指针调用→PC 跳飞", kw="0xdead0000", ev="bad_funcptr.c:"),
    # O1 基线：溢出跨度可抹掉整条应用帧链（扫描仅余 _start/libc），
    # 证据取符号配对的模块名；深层链恢复由 assert_fail/blame_thread 维度覆盖
    "stack_smash": dict(dim="缓冲溢出覆盖 LR 断链", kw="0x575757",
                        ev="stack_smash_", degrade=True),
    "assert_fail": dict(dim="防御性 assert 失败 abort", kw="断言", ev="assert_fail.c:", degrade=True),
    "thread_crash": dict(dim="4 线程 worker 空指针崩溃", kw="空指针", ev="sensor_sample_one"),
    "shlib_crash": dict(dim="链接期 so 内崩溃(跨模块配对)", kw="空指针", ev="sensord_get_reading"),
    # ---- 高难度内存维度 ----
    "ill_jump": dict(dim="跳入垃圾指令 SIGILL", kw="SIGILL", ev="ill_jump.c:"),
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
    # ---- 批次 1：传统 C 语言经典（#34~#54）----
    "realloc_dangling": dict(dim="realloc 搬迁后旧指针悬垂写", kw="非法内存访问", ev="fw_config_save"),
    "stack_local_return": dict(dim="返回栈地址+调用方大跨度memset冲出栈顶", kw="非法内存访问", ev="ui_draw_header", degrade=True),
    "free_nonheap": dict(dim="非堆指针free→glibc invalid pointer abort", kw="invalid pointer|free", ev="invalid pointer"),
    "uninit_stack_ptr": dict(dim="未初始化栈指针含垃圾被解引用", kw="非法内存访问|空指针", ev="sensor_use_stale"),
    "off_by_one": dict(dim="差一越界(i<=n)写穿缓冲触碰保护页", kw="非法内存访问", ev="sdr_write_row"),
    "int_overflow_alloc": dict(dim="32位乘法回绕malloc(0)后按全量写穿堆", kw="堆|非法内存访问", ev="net_alloc_table"),
    "sprintf_overflow": dict(dim="sprintf向64B栈缓冲写256B(栈保护/fortify拦截)", kw="栈|加固|非法内存访问", ev="sprintf_overflow.c:", degrade=True),
    "strlen_noterm": dict(dim="malloc缓冲无终止符strlen跑过映射尾", kw="非法内存访问", ev="strlen_noterm.c:"),
    "sizeof_pointer": dict(dim="数组参数sizeof退化为8→只清8B后续毒值", kw="非法内存访问", ev="ui_dispatch"),
    "union_confusion": dict(dim="union小整数当指针读→解引用0x2a", kw="空指针", ev="bus_slot_fire"),
    "signed_unsigned": dict(dim="负长度转无符号4GB巨大索引", kw="非法内存访问", ev="pkt_write_at"),
    "const_rodata_write": dict(dim="字符串字面量.rodata写入→ACCERR", kw="权限|非法内存访问", ev="cfg_write_byte"),
    "endianness_cast": dict(dim="大端字节流直cast小端→巨偏移野地址", kw="非法内存访问", ev="net_frame_apply"),
    "timer_after_free": dict(dim="定时器回调引用已free大块ctx→UAF", kw="非法内存访问", ev="timer_poll_fire"),
    "atexit_stale": dict(dim="atexit回调引用已free全局会话→UAF", kw="非法内存访问", ev="bmc_session_flush"),
    "shutdown_order": dict(dim="先free共享ctx而worker线程还在用→UAF", kw="非法内存访问", ev="sess_worker_loop"),
    "fd_exhaust": dict(dim="fd耗尽返回-1当无符号索引用→4GB偏移", kw="非法内存访问", ev="dev_open_all"),
    "malloc_null": dict(dim="超大malloc返回NULL未判空→写成员", kw="空指针", ev="cap_alloc_blob"),
    "sigpipe_write": dict(dim="写对端已关闭的管道→SIGPIPE", kw="SIGPIPE", ev="ipc_flush_logs"),
    "fpe_divzero": dict(dim="传感器换算整数除零→SIGFPE", kw="SIGFPE", ev="sensor_ratio"),
    "nest_signal": dict(dim="SIGSEGV handler内再次空指针→嵌套故障", kw="空指针", ev="nest_segv_handler"),
    # ---- 批次 2：硬件/平台/嵌入式特定（#55~#64）----
    "no_volatile_hw": dict(dim="状态寄存器缺volatile→过期值当通道号", kw="非法内存访问", ev="hw_dma_setup"),
    "unaligned_arm": dict(dim="字节流+1偏移cast非对齐解引用(BUS/旋转错值SEGV)", kw="总线错误|非法内存访问", ev="unaligned_arm.c:"),
    "dma_alignment": dict(dim="DMA描述符未对齐32B(BUS/错值当帧长SEGV)", kw="总线错误|非法内存访问", ev="dma_alignment.c:"),
    "eeprom_corrupt": dict(dim="EEPROM垃圾0xdeadbeef当函数指针调用", kw="0xdeadbeef", ev="board_hook_invoke"),
    "config_array_size": dict(dim="配置99999条按2B申请按64B写穿映射", kw="堆|非法内存访问", ev="cfg_load_table"),
    "argv_missing": dict(dim="argv[1]未查argc→NULL源strcpy", kw="空指针", ev="cli_run_request"),
    "init_order": dict(dim="依赖模块未初始化ops表NULL→穿空调用", kw="空指针", ev="sensor_bus_read"),
    "watchdog_stuck": dict(dim="线程死循环看门狗超时SIGABRT", kw="SIGABRT|abort", ev="wd_expire", degrade=True),
    "thread_hang_kill": dict(dim="线程阻塞syscall被看门狗定向杀SIGABRT", kw="SIGABRT|abort", ev="cli_cmd_wait", degrade=True),
    "lock_deadlock_kill": dict(dim="两线程锁序交叉死锁被看门狗杀", kw="SIGABRT|abort", ev="net_cfg_apply", degrade=True),
    # ---- 批次 3：BMC/OpenBMC 特定（#65~#73）----
    "ipmi_parse_overflow": dict(dim="IPMI crafted长度字段跨步扫描越界", kw="非法内存访问", ev="ipmi_parse_cmd"),
    "fru_corrupt_parse": dict(dim="FRU区域长度字段损坏0xFFFF跳出映射", kw="非法内存访问", ev="fru_walk_area"),
    "sensor_hotplug": dict(dim="sensor拔出后re-activate用悬垂句柄", kw="非法内存访问", ev="sensor_reactivate"),
    "i2c_timeout_stale": dict(dim="I2C超时返回旧缓存悬垂指针批量读", kw="非法内存访问", ev="i2c_read_regs"),
    "dbus_prop_crash": dict(dim="D-Bus属性setter内UAF(在途请求)", kw="非法内存访问", ev="dbus_prop_set"),
    "power_transition": dict(dim="电源切换释放ctx在途命令仍引用", kw="非法内存访问", ev="power_cmd_execute"),
    "sel_full_error": dict(dim="SEL写满错误路径NULL未判空写记录", kw="空指针", ev="sel_commit_record"),
    "shm_unlink_alive": dict(dim="shm_unlink+截断后attach进程远读→SIGBUS", kw="总线错误|非法内存访问", ev="shm_far_read", degrade=True),
    "fifo_sigpipe": dict(dim="FIFO读端退出后写端写入→SIGPIPE", kw="SIGPIPE", ev="log_tail_flush"),
}

ARCHS = ["arm64", "arm32", "riscv64"]

# (case, arch) -> 覆盖格（同 CASES 字段）；None = 期望 SKIP（环境限制）
EXPECT_ARCH = {
    ("ill_jump", "arm32"): dict(dim="qemu 对 UDF 上报 SIGTRAP(如实转述)",
                                kw="SIGTRAP", ev="ill_jump.c:"),
    ("shm_truncate_bus", "riscv64"): dict(
        dim="riscv qemu 对越 EOF 可报 BUS 或 SEGV", kw="总线错误|非法内存访问",
        ev="db_far_record_read", degrade=True),
    ("lmdb_truncate_bus", "arm64"): None,   # qemu internal SIGBUS，无法 gcore
    ("lmdb_truncate_bus", "arm32"): None,   # O1 下 qemu SIGBUS 交付不稳（同 arm64 类）
}

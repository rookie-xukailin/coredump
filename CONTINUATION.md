# 任务完成：78 维度 × 3 架构 = 234 格全量系统测试

> 本文件是跨会话任务清单。**当前任务已全部完成**（2026-08-24，含消息队列批次）。

## 最终状态

- ✅ 33 旧维度 + 45 新维度（#34~#78）全部实现，三平台（arm64/arm32/riscv64）测试通过
- ✅ 判定结果：**PASS 232 / FAIL 0 / SKIP 2**
  - 2 个 SKIP 为既有环境限制（lmdb_truncate_bus arm64/arm32：qemu 内部 SIGBUS 无法 gcore，
     manifest 已登记；该维度的 riscv64 格完整验证）
- ✅ 可视化校验：233 格（全部有 core 的格）面板数据构建+结构断言 **VIZ PASS 233 / FAIL 0**
- ✅ 浏览器抽查：索引页 + 每批次每平台代表格 + 全部特殊信号（SIGPIPE/SIGFPE/SIGBUS/SIGABRT/SIGILL/SIGTRAP）
  面板渲染无异常；画廊服务 `python3 tools/viz_gallery.py`（localhost:8080）可浏览全部格
- ✅ `python tests/run_all.py` 全过（含 BMCCORE_SYSTEM_WORK 系统测试）

## 40 个新增维度（实现要点）

### 批次 1：传统 C 语言经典（21 个，#34~#54）
| 名称 | 机理 | 实现要点 |
|---|---|---|
| realloc_dangling | realloc 搬迁 munmap 旧块后写旧指针 | 2MB→8MB 搬迁必触发 |
| stack_local_return | 返回栈地址被后续调用复用成垃圾 | memcpy 逃逸防 GCC NULL 改写；0xAB 垃圾按 char** 解引用 |
| free_nonheap | 全局数组中间偏移 free | +4 偏移不对齐必触发 glibc abort |
| uninit_stack_ptr | 未初始化栈指针解引用 | 4 层递归 16KB 播撒 0xB5 保证毒化 |
| off_by_one | i<=n 差一写 | 3 页 PROT_NONE 中间页做缓冲，越一步即触保护页 |
| int_overflow_alloc | 32 位乘法回绕 malloc(0) | 逐字节 volatile 写绕开 fortify3，写穿堆顶 |
| sprintf_overflow | 64B 栈缓冲写 256B | 实测触发栈金丝雀（smashing），结论栈保护命中 |
| strlen_noterm | 无终止符 strlen 跑过映射尾 | 1MB mmap 块填满非零，FAULT_ADDR=映射尾精确 |
| sizeof_pointer | 参数退化 sizeof=8 只清 8B | noinline msg_clear + 毒化指针 0x68 基址（32/64 位均野） |
| union_confusion | uint32 当指针解引用 0x2a | 低地址→空指针结论 |
| signed_unsigned | 负数转无符号块索引 | ×64KB 块偏移：64 位 +4GB / 32 位回绕 -64KB 落空 |
| const_rodata_write | 写 .rodata | ACCERR 注入 code=2 |
| endianness_cast | 大端直 cast 小端巨偏移 | 字节选 0x0080000010000000：64 位非规范/32 位 +256MB |
| timer_after_free | 定时器回调 UAF | handler 只置标志（qemu 丢 handler 上下文），主线程轮询解引用 |
| atexit_stale | atexit 回调 UAF | 2MB mmap 块 free 即 munmap |
| shutdown_order | 先 free 共享 ctx worker 还在用 | volatile 读循环必踩 munmap |
| fd_exhaust | fd 耗尽 -1 当无符号块索引 | 软件配额 4 次（gdb 对宿主 fd 数>128 敏感会崩） |
| malloc_null | malloc(-1) 返回 NULL 未判空 | size_t -1 三架构均必失败 |
| sigpipe_write | 写无读端管道 | qemu 限制适配见下表 |
| fpe_divzero | 整数除零 | arm64/riscv 除法不陷阱→换算层检测后 raise(SIGFPE) |
| nest_signal | SEGV handler 内再空指针 | 嵌套故障内核击杀，bt 显示 handler 帧 |

### 批次 2：硬件/平台/嵌入式（10 个，#55~#64）
no_volatile_hw（LICM 过期值当通道号）、unaligned_arm/dma_alignment（非对齐双形态：对齐核 SIGBUS / 否则错位巨值 SEGV）、
eeprom_corrupt（0xdeadbeef 当函数指针）、config_array_size（99999 条按 2B 申请按 64B 写穿）、
argv_missing（NULL 源 strcpy）、init_order（ops 表 NULL 穿空）、
watchdog_stuck / thread_hang_kill / lock_deadlock_kill（看门狗三态：死循环超时/挂死线程定向杀/锁序死锁，均 SIGABRT）

### 批次 3：BMC/OpenBMC（9 个，#65~#73）
ipmi_parse_overflow（crafted 长度跨步扫描）、fru_corrupt_parse（区域长度 0xFFFF 跳出+逐页走查）、
sensor_hotplug（悬垂句柄）、i2c_timeout_stale（旧缓存指针）、dbus_prop_crash（在途属性请求 UAF）、
power_transition（S5 切换释放在途命令）、sel_full_error（写满 NULL 未判空）、
shm_unlink_alive（对象移除+收缩后远读 SIGBUS）、fifo_sigpipe（FIFO 对端退出 SIGPIPE）

### 批次 4：消息队列（5 个，#74~#78）
| 名称 | 机理 | 实现要点 |
|---|---|---|
| mq_consumer_uaf | POSIX mq 消费者线程阻塞接收，停止路径先 free 大块 ctx 再投唤醒消息 | qemu 未实现 mq_notify(ENOSYS)，通知语义以阻塞消费者线程实现；崩溃线程=消费者 |
| mq_recv_truncate | 接收缓冲按旧版 8B 分配，mq_receive 以 EMSGSIZE 拒收且返回值未检查 | 残留旧消息的长度字段(0x77000000)被当新消息解析 → 野偏移读 |
| mq_deser_overflow | 消息载荷长度字段由对端控制且未校验上限 | crafted len=0x7770 反序列化拷贝越过数据页触保护页 |
| msgq_rmid_race | SysV 队列被 fork 出的管理进程 IPC_RMID，阻塞中 msgrcv 以 EIDRM 返回 -1 | -1 未检查被当消息长度，转无符号 64KB 块偏移 |
| queue_ring_overrun | 自研环形队列满判断在批量路径被绕过 | 64B×100 连续入队越过数据页，[元数据页][数据页][保护页]布局 |

## qemu-user 环境适配（生成层，不影响真机语义）

| 适配 | 根因 | 方案 |
|---|---|---|
| SIGPIPE 断点取核 | qemu gdbstub 不拦截宿主 SIGPIPE（直接杀仿真器，连 raise 也不回停） | 案例经 poll 探测 EPIPE（BMC_QEMU_EPIPE_PROBE=1 环境门控）后走 ipc_sigpipe_default；gen 在该函数断点 gcore，再注入 NT_SIGINFO(13)+修补 pr_cursig |
| shm 移除用 rename | unlink 后（即使有硬链接）孤儿路径下 gcore 读取截断区会击杀仿真器 | 生成环境 rename 移除对象名（真机仍 unlink） |
| fd 软件配额 | gdb 对 qemu 宿主 fd 数敏感（>128 时 gdb 自身 SIGSEGV） | 软件配额 4 次模拟 EMFILE |
| gcore 前置 | 个别 core 状态使 gdb 在 bt 时自身崩溃 | gcore 排在 REGS/BT 之前执行 |
| SIG34 透传 | RT 定时器信号默认 stop 卡住流程 | handle SIG34 nostop noprint pass |
| 旧核清理 | 重生成后多份 tar 使分析取旧核 | gen_cell 开头清掉该格旧 core |

## 关键路径

| 文件 | 说明 |
|---|---|
| `tools/make_cases3/4/5.sh` | 40 个新维度案例源码生成（批次 1/2/3） |
| `tools/gen_matrix.sh` | 219 格生成主入口（含全部 qemu 适配） |
| `tools/corefix/inject_siginfo.py` | NT_SIGINFO 注入 + 可选 pr_cursig 修补 |
| `tests/system_manifest.py` | 73 维度清单（仓库测试的事实源） |
| `tools/verdict/verdict_matrix.py` | 219 格程序化判定 |
| `tools/viz_check.py` | 全量面板数据校验（产出 viz/*.json） |
| `tools/viz_gallery.py` | localhost:8080 全量格画廊 |
| `tools/README.md` | 完整流水线使用说明 |

## 已知环境限制（不需修复）

| 限制 | 处置 |
|---|---|
| lmdb_truncate_bus arm64/arm32 qemu 内部 SIGBUS | SKIP（riscv64 格完整验证；arm64 SIGBUS 由 shm_truncate_bus/shm_unlink_alive 覆盖） |
| ill_jump arm32 报 SIGTRAP | 按真实信号断言 |
| riscv 越文件 EOF 可报 BUS/SEGV | 结论关键词双匹配 |
| arm32 lock_deadlock_kill 应用帧符号化退化 | 栈扫描文件级证据（EXPECT_ARCH 覆盖） |

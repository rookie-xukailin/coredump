# 续接任务：73 维度 × 3 架构 = 219 格全量系统测试

> 本文件是跨会话续接的任务清单。任何新会话读此文件即可接续工作，不依赖前一会话的上下文。

## 当前进度

- ✅ 已完成 33 维度 × 3 架构 = 99 格（97 PASS / 0 FAIL / 2 SKIP）
- ✅ 已提交推送至 GitHub develop/rookie/coredump（36 个提交）
- ✅ 编译基线 -g -O1，Python 3.8+，符号表模式（--symbol-table）
- ❌ 待完成 40 个新维度（本文档详述）
- ❌ 待完成新维度的可视化面板验证

## 新会话快速上手

```bash
# 1. 环境（WSL Ubuntu 24.04）
apt install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf \
            gcc-riscv64-linux-gnu gdb-multiarch qemu-user-static

# 2. 三方库
./tools/build_third.sh

# 3. 生成已有 33 维度源码
bash tools/make_cases.sh && bash tools/make_cases2.sh && \
bash tools/make_cases_conc.sh && bash tools/make_cases_db.sh && \
bash tools/make_case21.sh

# 4. 生成 99 格 core
bash tools/gen_matrix.sh

# 5. 符号表
bash tools/make_symtables2.sh

# 6. 分析 + 判定
bash tools/analyze_matrix.sh
python3 tools/verdict/verdict_matrix.py

# 7. 运行仓库测试
python tests/run_all.py
# 设 BMCCORE_SYSTEM_WORK=<工作目录> 后自动含系统测试
```

## 工作规约（AGENTS.md 摘要）

1. 改码后必须 `python tests/run_all.py` 全过
2. 有 core 环境时必须跑系统测试
3. 提交到 develop/rookie/coredump，按逻辑单元拆小提交
4. 提交信息四节式：背景/根因/修改/验证
5. Python 3.8+ 基线，不得引入 3.9+ 语法
6. 编译基线 -g -O1，案例需抗优化加固

## 40 个新增维度完整规格

### 批次 1：传统 C 语言经典（20 个）

| # | 名称 | 崩溃机理 | 源码要点 | 预期信号 | 预期结论关键词 |
|---|---|---|---|---|---|
| 34 | realloc_dangling | p=malloc(); q=realloc(p,big); p->field=x → 悬垂 | 先 malloc 小块，再 realloc 扩大（返回新地址），旧指针悬垂后写入 | SEGV | 非法内存访问 |
| 35 | stack_local_return | char* f(){char b[64];return b;} 调用方使用 | 函数返回栈上 buffer 地址，调用方 memset | SEGV | 非法内存访问（栈已回退） |
| 36 | free_nonheap | int x; free(&x); → glibc 检测非堆指针 | 在栈上/全局变量上调用 free | ABRT | invalid pointer |
| 37 | uninit_stack_ptr | 未初始化的局部指针变量恰好含垃圾地址 | 声明指针不赋值，直接解引用（需 volatile 防编译器警告拦截） | SEGV | 非法内存访问 |
| 38 | off_by_one | for(i=0;i<=n;i++) a[i]=x → 写 a[n] 越界 | 精确越界 1 个元素，不踩 chunk 头（栈上数组） | SEGV | 非法内存访问 |
| 39 | int_overflow_alloc | malloc(count*size) 乘法回绕 → 分配 4B → 写 1KB | count=0x10000, size=0x10000 → 乘积回绕为 0 → malloc(0) | SEGV | 堆溢出（写穿多个 chunk） |
| 40 | sprintf_overflow | sprintf(buf,"%s",huge) → 栈溢出 | 小栈 buffer 64B，格式化写入 256B | SEGV/ABRT | 栈溢出或 fortify |
| 41 | strlen_noterm | buffer 无 \0 → strlen 跑过末尾 | malloc 的 buffer 不清零，直接 strlen | SEGV | 非法内存访问（读越界） |
| 42 | sizeof_pointer | 函数参数 sizeof(buf) 返回 8 不 64 | void f(char buf[64]) { memset(buf,0,sizeof(buf)); } → 只清 8B | 逻辑错误→后续崩 | 可能不崩，改为：memset 只清 8B，后续读 64B 时后半是垃圾 |
| 43 | union_confusion | 写 union 为 uint32，读为指针 → 高位垃圾 | union { uint32_t small; void *ptr; }; small=42; ptr 使用 | SEGV | 非法内存访问（0x2a 附近） |
| 44 | signed_unsigned | (unsigned)len < 0 永假 → 负数索引变巨大 | int len=-1; unsigned idx=len; buf[idx]=x → buf[0xFFFFFFFF] | SEGV | 非法内存访问 |
| 45 | const_rodata_write | (char*)"hello" 然后写入 → .rodata SEGV ACCERR | char *s = "config"; s[0] = 'X'; | SEGV | 权限错误 |
| 46 | endianness_cast | 网络字节流直接 cast 成 struct → 字段值错 | 大端网络数据 cast 成小端 struct → 值完全错误 → 用作偏移 | SEGV | 非法内存访问（偏移错误） |
| 47 | timer_after_free | 定时器回调触发时对象已 free → UAF | timer_create/timer_settime 回调使用已 free 的 ctx | SEGV | UAF |
| 48 | atexit_stale | atexit 回调引用已 free 的全局 | atexit(handler); free(g_ptr); exit(0); handler 里用 g_ptr | SEGV | UAF |
| 49 | shutdown_order | 先 free 共享→另一线程还在用 | 线程 A free 共享 ctx，线程 B 正在使用 | SEGV/ABRT | UAF 或堆检查 |
| 50 | fd_exhaust | 耗尽 fd → open() 返回 -1 → 当索引用 | 循环 open 直到 fd 用尽，然后 buf[fd] 访问 | SEGV | 非法内存访问 |
| 51 | malloc_null | malloc 返回 NULL → 没判空直接用 | 设 RLIMIT_AS 限制内存，大 malloc 返回 NULL | SEGV | 空指针解引用 |
| 52 | sigpipe_write | 写已断开的管道 → SIGPIPE | pipe(); close(read_fd); write(write_fd,...) | SIGPIPE | 崩溃信号 SIGPIPE |
| 53 | fpe_divzero | sensor 计算 (a-b)/(c-c) → SIGFPE | volatile int a=100,b=100,c=100; (a-b)/(c-c) | SIGFPE | 崩溃信号 SIGFPE |
| 54 | nest_signal | SIGSEGV handler 里又触发 SIGSEGV | handler 里解引用另一个 NULL → 嵌套故障 | SEGV | 信号处理函数内崩溃 |

### 批次 2：硬件/平台/嵌入式特定（10 个）

| # | 名称 | 崩溃机理 | 源码要点 | 预期信号 |
|---|---|---|---|---|
| 55 | no_volatile_hw | 硬件寄存器没 volatile → 编译器缓存 → 过期值 | 读取状态寄存器（模拟），编译器优化掉重读 → 用过期值算偏移 | SEGV |
| 56 | unaligned_arm | 网络字节流 (uint32_t*)(buf+1) → 非对齐 | memcpy 到 char[]，然后 +1 偏移 cast 成 uint32_t* 并解引用 | SIGBUS |
| 57 | dma_alignment | DMA 要求 32B 对齐但驱动没保证 | 模拟 DMA buffer 非对齐访问 | SIGBUS |
| 58 | eeprom_corrupt | EEPROM 读出垃圾 → 当函数指针用 | 模拟 EEPROM 读出 0xDEADBEEF → call 它 | SEGV |
| 59 | config_array_size | 配置文件值 99999 当数组大小 | 读"配置"值为巨大 size → 分配失败或越界 | SEGV/ABRT |
| 60 | argv_missing | argv[1] 没检查 argc → NULL 字符串 | strcpy(argv[1],buf) 当 argc==1 | SEGV |
| 61 | init_order | 驱动 A 先于依赖它的 B 初始化 | B 用了 A 未初始化的全局指针 | SEGV |
| 62 | watchdog_stuck | 线程死循环 → 看门狗超时 → SIGABRT | while(1) 循环，模拟 watchdog 超时后 raise(SIGABRT) | ABRT |
| 63 | thread_hang_kill | 线程阻塞在 syscall → watchdog kill | read() 从无数据的 fd → 超时后 abort | ABRT |
| 64 | lock_deadlock_kill | 两线程互等锁 → 外部杀 | mutex A→B 和 B→A 交叉 → 模拟 watchdog kill | ABRT |

### 批次 3：BMC/OpenBMC 特定（10 个）

| # | 名称 | 崩溃机理 | 源码要点 | 预期信号 |
|---|---|---|---|---|
| 65 | ipmi_parse_overflow | 构造 IPMI 报文字段越界 | 模拟 IPMI 命令解析器收到 crafted 报文 | SEGV |
| 66 | fru_corrupt_parse | FRU 二进制损坏 → parser NULL | 模拟 FRU area 长度字段为 0xFFFF → 越界 | SEGV |
| 67 | sensor_hotplug | sensor 拔出后 re-activate → crash | 模拟 OpenBMC dbus-sensors #31 | SEGV |
| 68 | i2c_timeout_stale | I2C 超时 → 过期缓存 → 野指针 | 模拟 I2C 读取失败返回旧缓存指针 | SEGV |
| 69 | dbus_prop_crash | D-Bus 属性 setter 内 UAF | 模拟 OpenBMC #986 sdbusplus 属性设置 | SEGV |
| 70 | power_transition | 电源状态切换中命令处理引用已释放上下文 | 模拟 S0→S5 切换时 S0 命令还在执行 | SEGV |
| 71 | sel_full_error | SEL 存储满 → 错误路径没判空 | 模拟 SEL 写满后错误处理路径 NULL | SEGV |
| 72 | shm_unlink_alive | shm_unlink 后已 attach 的进程访问 | fork 子进程 shm_open+attacker 删除 | SIGBUS |
| 73 | fifo_sigpipe | FIFO reader 崩溃 → writer SIGPIPE | mkfifo; reader exit; writer write | SIGPIPE |

## 实施步骤

### 第 1 步：编写 40 个案例源码
```bash
# 写 C 源码到 tools/cases/，每个维度一个 .c 文件
# 源码要求：
#   - -g -O1 抗优化加固（volatile/noinline/静态载荷）
#   - FAULT_ADDR 打印（stderr，崩溃前一行）
#   - 确定性（不依赖时序/随机数）
#   - 多级调用链（≥3 层，便于回溯）
#   - 注释说明崩溃机理
```

### 第 2 步：更新 gen_matrix.sh
```bash
# 在 CASES 变量中追加 40 行，格式：
# name|src.c|signo|code|addrsrc|fmt|fx|ld|console
```

### 第 3 步：更新 system_manifest.py
```python
# 在 CASES dict 中追加 40 项，格式：
# "name": dict(dim="描述", kw="结论关键词", ev="证据", degrade=False)
```

### 第 4 步：生成 + 分析 + 判定
```bash
bash tools/gen_matrix.sh          # 生成 219 格
bash tools/analyze_matrix.sh     # 全量分析
python3 tools/verdict/verdict_matrix.py  # 判定
```

### 第 5 步：可视化验证
```bash
# 选 3 个代表性新维度展示可视化效果
python3 -c "..."  # 启动 viz，验证面板展示
```

### 第 6 步：提交推送
```bash
git add tools/ tests/ bmccore/
git commit  # 四节式详细信息
git push origin develop/rookie/coredump  # SSH 443
```

## 新会话启动指令模板

在新 ZCode 会话中输入：

```
读取 D:\AI_Workspace\Coredump\coredump\CONTINUATION.md 并按其中的任务计划继续执行。
当前状态：33 维度已完成，需要实现 CONTINUATION.md 中定义的 40 个新维度（#34~#73）。
按批次顺序执行：先做批次 1（传统 C 语言 20 个），再批次 2（嵌入式 10 个），最后批次 3（BMC 10 个）。
每完成一个批次：生成 core → 分析 → 判定 → 可视化验证 → 提交推送。
```

## 关键路径

| 文件 | 说明 |
|---|---|
| `CONTINUATION.md` | 本文件——跨会话任务计划 |
| `AGENTS.md` | 项目工作规约 |
| `tools/README.md` | 测试基础设施使用说明 |
| `tools/gen_matrix.sh` | core 生成主入口（CASES 变量在顶部） |
| `tools/cases/` | 已有 33 个案例源码（新增也放这里） |
| `tests/system_manifest.py` | 系统测试维度清单（新增也改这里） |
| `tools/verdict/verdict_matrix.py` | 程序化判定 |
| `bmccore/visualize.py` | 可视化面板（需要传新维度数据验证） |

## 已知环境限制（不需要修复）

| 限制 | 原因 | 处置 |
|---|---|---|
| lmdb_truncate arm64/arm32 SKIP | qemu SIGBUS 交付不稳 | manifest 登记 SKIP |
| ill_jump arm32 报 SIGTRAP | qemu 对 UDF 的上报差异 | 按真实信号断言 |
| riscv 越文件 EOF 可报 BUS/SEGV | qemu 翻译层差异 | 结论关键词双匹配 |

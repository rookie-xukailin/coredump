---
name: swrd-skill-coredump-analyze
description: 分析 BMC/嵌入式 coredump 文件，结合符号表和源码给出根因分析与修复建议。当用户提供 core 文件、tar.gz 崩溃包、或提到"进程崩了/段错误/abort/内存被踩"时触发。
version: 3.11.1
---

# Coredump 智能分析

## 技能包结构（自带完整引擎，无需单独部署工具）

本技能是自包含的——分析引擎随技能包一起分发，就放在本 SKILL.md 所在目录（下称**技能根目录**）：

```
<技能根目录>/
├── SKILL.md               ← 本文件（入口）
├── bmccore.py             ← 引擎 CLI 入口（python3.8 直接调用）
├── bmccore/               ← 引擎包（解析/回溯/堆取证/结论）
├── open/pyelftools        ← 内置依赖（无需 pip 安装）
├── scripts/
│   └── coredump_analyze.py  ← 报告 JSON → 结构化数据 的辅助脚本
├── bmccore.toml.example   ← 配置模板
└── workspace/             ← 工作区（自带 bmccore.toml 配置模板；解包/中间产物/报告也在此）
```

**定位技能根目录**：加载技能时系统会告知本 SKILL.md 的路径（base directory），
其所在目录即技能根目录。不确定时 `ls` 确认该目录下存在 `bmccore.py`。
若不存在，说明技能包不完整，请用户重新获取完整包（不要猜测其他路径）。

环境要求：Python 3.8+（纯标准库 + 内置依赖，零 pip 安装，适配内网/离线环境）。
**命令统一用 `python3.8` 调用**——部分机器默认 `python3` 版本不一；
仅当机器没有 `python3.8` 可执行文件且默认 `python3` 已是 3.8+ 时才用 `python3`。

注：源码仓库中的开发资产（tests/、tools/、docs/、README 等）位于本技能
目录之外，不随技能分发；技能包内即上述自包含结构。

## 你是什么

你是一个 **BMC/嵌入式 coredump 分析专家**。你的职责不是简单地跑一个工具，而是像资深嵌入式工程师一样：

1. **调用工具获取结构化数据**（崩溃位置、回溯、堆状态）
2. **深入源码理解崩溃上下文**（读完整函数、追赋值链、查数据结构）
3. **给出人能直接执行的修复方案**（代码 diff 级别）

工具只是你的"眼睛"，分析和判断是你的核心价值。

## 用户输入识别

用户可能用以下方式触发你（都能识别）：

| 用户说的话 | 你提取的信息 |
|---|---|
| "帮我分析这个 coredump，core 在 /tmp/xxx.tar.gz，符号表在 /home/bmc/symbols/" | core=xxx.tar.gz, symtab=/home/bmc/symbols/ |
| "remotexdp 进程又崩了，core 在 /var/crash/ 下面" | 需要问：符号表在哪？源码在哪？ |
| "/tmp/core-2078599821-remotexdp-6759 这个文件帮我看看" | core 路径明确，需追问符号表和源码 |
| "段错误了，有 core 文件" | 需要用户提供所有路径 |
| "内存被踩了，帮忙查一下" | 可能不是 core 分析（是在线调试），先确认有没有 core 文件 |

**你需要的四个路径**（缺哪个问哪个，不要猜、不要跳过分析）：

1. **core 文件路径**（必需）：ELF core / .gz / tar.gz 包
2. **符号表**（必需）：编译阶段单独产出的未 strip ELF——目录、单个文件、
   或 `rootfs_symbol.tgz` 之类 tar 包均可（包会自动解压到 workspace 缓存复用）
3. **工程源码路径**（必需）：崩溃进程的源代码根目录——没有它你只能做
   "哪里崩了"的定位，做不了"为什么崩"的根因分析和修复建议
4. **串口日志**（可选但强烈建议）：glibc 堆报错只打印在 stderr，core 里没有

如果用户只给了 core 文件，你要追问：
> "符号表目录在哪？工程源码路径是什么？有了源码我才能帮你分析根因和给修复建议。"

## 工作流

### 第 1 步：确认输入

从用户处获取以下信息（缺什么问什么）：

| 必需 | 说明 | 示例 |
|---|---|---|
| core 文件 | 崩溃转储（裸 ELF / .gz / tar.gz） | `1_core-2078599821-remotexdp-6759.tar.gz` |
| 符号表 | 目录/单个 ELF/rootfs_symbol.tgz 包均可（自动解压缓存） | `/home/bmc/build/rootfs_symbol.tgz` |
| 源码树 | 崩溃进程的源代码 | `/home/bmc/src/bmc-project/` |
| 串口日志（可选但强烈建议） | 设备 stderr 输出 | `console.log` |

### 第 2 步：调用 bmccore 获取结构化数据

```bash
BMCORE="<技能根目录>/bmccore.py"    # 技能根目录 = 本 SKILL.md 所在目录（绝对路径）
WS="<技能根目录>/workspace"
```

**首次分析（或路径变化时）填一次配置**——技能自带模板
`$WS/bmccore.toml`（变量齐全、路径留空），把各项路径填成绝对路径即可；
之后每次分析只需一条短命令，不再拼长参数：

```toml
# <技能根目录>/workspace/bmccore.toml
symbol_table = "/绝对路径/符号表目录或rootfs_symbol.tgz"  # tar 包自动解到 workdir 缓存
source_root  = "/绝对路径/源码树"
workdir      = "<技能根目录>/workspace/intake"            # 解包/中间产物
output       = "<技能根目录>/workspace/report"            # 报告输出
offline      = false   # 无交叉工具链设 true（纯Python零外部依赖）；配了工具链设 false

# 有交叉工具链时配上（原生 addr2line 比纯 Python 建行号表快一个量级）：
# [toolchain.riscv64]
# path = "/opt/xxx/riscv-toolchain"    # 只给一个路径（根目录或 bin 目录），
#                                      # 其下 riscv64-*-gdb 等自动发现配对
```

**日常分析就一条短命令**（配置收拢全部参数；CLI 参数仍可临时覆盖配置。
core 也可写进 toml 的 `core =`，那样连位置参数都不用带，换对象时改配置
或命令行传参均可）：

```bash
python3.8 "$BMCORE" analyze <core文件> --config "$WS/bmccore.toml" \
    [--console-log <串口日志>]
```

**确认技能根目录下存在 `bmccore.py`**；不存在说明技能包不完整，
请用户重新获取，不要猜测其他路径。

**工具会输出**：
- `*_report.md`（人读格式，含源码片段）
- `*_report.json`（机读格式，结构化数据）

### 第 3 步：解析工具输出

读 JSON 报告，提取关键数据：

```bash
# 辅助脚本同样随技能包自带（报告在 workspace/report/ 下）
python3.8 <技能根目录>/scripts/coredump_analyze.py "<技能根目录>/workspace/report/"*_report.json

# 或者直接读 JSON
cat "<技能根目录>/workspace/report/"*_report.json
```

**你需要关注的字段**：

| 字段 | 含义 | 后续动作 |
|---|---|---|
| `定位结论.conclusions` | 最终判定（确认/疑似） | 这是分析的起点 |
| `回溯.frames` | 调用栈（file:line） | → 去读这些源码 |
| `堆取证.notes` | chunk 损坏/受害对象/指纹 | → 去源码 grep 指纹 |
| `栈扫描.scan_frames` | gdb 断链时的降级回溯 | → 验证帧是否合理 |
| `符号配对.modules` | 哪些模块配上了/missing | → 提醒用户补符号表 |
| `console 关键行` | glibc abort 消息 | → 定位是堆检查还是 assert |

### 第 4 步：深入源码分析（你的核心价值）

工具告诉你"崩在哪"，你要告诉用户"为什么"和"怎么修"。

#### 4a. 读取崩溃帧的完整函数

工具只贴 ±5 行片段。你需要：

```bash
# 从报告提取 file:line，然后读整个函数
# 例如报告说 fan_pwm_apply @ stomped_late.c:49
# → 打开文件，从函数声明读到闭括号，理解上下文
```

**关键问题**：
- 崩溃行的变量从哪来的？（参数？全局？返回值？）
- 谁调用了这个函数？调用链上有没有条件分支导致异常路径？
- 这个函数持有的资源（锁/引用/内存）在崩溃时的状态？

#### 4b. 按崩溃类型深入分析

| 工具结论 | 你要做的 |
|---|---|
| **空指针** (addr < 0x1000) | 追溯指针的赋值链：全局变量在哪初始化？参数谁传的？是不是初始化顺序问题？ |
| **堆溢出** (chunk 损坏 + 前块嫌疑) | 读前块对应的数据结构定义，找所有写入该区域的代码（memcpy/strcpy/循环赋值），判断为什么越界 |
| **UAF/悬垂写** (受害对象 + 相邻块嫌疑) | 追溯对象的 free/释放路径，找谁还持有 stale 引用（报告"引用搜索"给了线索） |
| **栈溢出** (SP 出界) | 读递归函数的终止条件，或大局部变量的大小 |
| **坏函数指针** (pc = 野地址) | 追溯函数指针的赋值点，谁可能踩到它（堆溢出/UAF/竞态） |
| **竞态** (多线程 + 数据被踩) | 分析两个线程的同步原语，找缺失的锁/原子操作/内存屏障 |
| **SIGABRT + console 有 glibc 消息** | 直接从消息定位（"double free"/"invalid next size"/"assert"），再追溯触发条件 |

#### 4c. 工程代码取证搜索（核心能力——规范与技巧）

以下是你在源码树中系统化搜索线索的方法论。按崩溃类型分类，每种给出
具体的搜索模式和判断标准。

##### 4c-1. 堆指纹搜索（内存被踩场景）

工具报告"内容指纹"给出的字符串/字节模式，在源码中找出写入者：

```bash
# 策略 1：搜指纹字符串（最直接）
# 报告说指纹是 'fan0'、'SSSS...'、'GGGG...' 等
grep -rn "fan0" --include="*.c" --include="*.h" <源码树>/
grep -rn "0x53" --include="*.c" <源码树>/   # 0x53='S' 的十六进制

# 策略 2：搜填充值的写入操作
grep -rn "memset.*0x53\|memset.*0x47\|memset.*0x58" --include="*.c" <源码树>/
grep -rn "'S'\|'G'\|'X'" --include="*.c" <源码树>/ | grep -i "memset\|fill\|pad"

# 策略 3：搜相同长度的数组/缓冲区声明
# 报告说受害对象 48 字节 → 搜 sizeof 为 48 或 0x30 的结构
grep -rn "sizeof.*48\|sizeof.*0x30" --include="*.c" <源码树>/
grep -rn "\[48\]\|\[0x30\]" --include="*.c" --include="*.h" <源码树>/

# 策略 4：搜 victim 结构体的字段名（从块头身份指纹提取）
# 报告说块头含 'fan0' → 搜索含 name 字段的结构体
grep -rn "char.*name\[.*\]" --include="*.h" <源码树>/ | grep -B5 -A5 "fan\|pwm\|ctrl"
```

**判断标准**：命中 ≥2 个指纹特征（字符串 + 大小 + 字段名）→ 高置信肇事者。

##### 4c-2. 反向数据流追踪（空指针/野指针场景）

从崩溃变量出发，追溯它的来源：

```bash
# 第 1 步：找变量定义
grep -rn "g_fan\|struct fan_ctrl" --include="*.h" --include="*.c" <源码树>/
# 结果: static struct fan_ctrl *g_fan;  ← 全局指针

# 第 2 步：找所有赋值点（谁给它赋值的？）
grep -rn "g_fan\s*=" --include="*.c" <源码树>/
# 结果: g_fan = malloc(...) @ init.c:42
#        g_fan = NULL @ cleanup.c:20   ← 这里置空了！

# 第 3 步：找所有使用点（谁在读它？）
grep -rn "g_fan" --include="*.c" <源码_tree>/
# 结果: fan_pwm_apply(g_fan, 128) @ main.c:79  ← 崩溃行
#        g_fan->set_pwm(...) @ ctrl.c:33

# 第 4 步：找初始化函数（是否被正确调用？）
grep -rn "fan_init\|fan_register\|fan_create" --include="*.c" <源码树>/
# 结果: int fan_init(void) @ fan.c:120  ← 函数存在
grep -rn "fan_init()" --include="*.c" <源码树>/
# 结果: main() 里没有调用！  ← 根因：初始化遗漏
```

**关键模式**：
- `变量名 =` → 找赋值
- `变量名->` 或 `变量名.` → 找使用
- `变量名 = NULL\|free(变量名)` → 找释放/置空
- `init.*变量名\|register.*变量名` → 找初始化

##### 4c-3. 写入者搜索（堆溢出/内存踩踏场景）

找出所有可能写入受害内存区域的代码：

```bash
# 第 1 步：确定受害结构体类型（从堆取证身份指纹推断）
# 报告说受害对象 48 字节，含 name/pwm/set_pwm 字段
grep -rn "struct.*fan_ctrl\|typedef.*fan_ctrl" --include="*.h" <源码树>/

# 第 2 步：找受害对象的分配位置
grep -rn "malloc.*fan_ctrl\|sizeof.*fan_ctrl\|new.*fan_ctrl" --include="*.c" <源码树>/

# 第 3 步：找受害对象前后的相邻分配（工具说"相邻块是嫌疑"）
# 在分配点附近，看前后各 malloc 了什么
# 如果代码是: a = malloc(sizeof(struct X)); b = malloc(sizeof(struct Y));
# 则 a 溢出会踩 b，b 下溢会踩 a

# 第 4 步：找所有可能越界的写入操作
# 方法 A：搜无边界检查的拷贝
grep -rn "strcpy\|strcat\|sprintf\|memcpy" --include="*.c" <源码_tree>/ | \
    grep -v "strncpy\|strncat\|snprintf\|memmove"

# 方法 B：搜循环写入（数组越界模式）
grep -rn "for.*\[\|while.*\[" --include="*.c" <源码树>/ | grep -v "bounds\|limit\|max"

# 方法 C：搜指针运算（负偏移/过大偏移模式）
grep -rn "\-\s*0x[0-9a-f]\+\|+\s*0x[0-9a-f]\{3,\}" --include="*.c" <源码树>/

# 第 5 步：搜受害字段名的写入
grep -rn "set_pwm\s*=\|->set_pwm" --include="*.c" <源码树>/
# 这找到所有写 set_pwm 字段的代码——肇事者必在其中
```

**判断标准**：能画出"受害 chunk 的地址空间 ← 谁在什么条件下写入"的完整图。

##### 4c-4. 生命周期追踪（UAF/双释放场景）

```bash
# 第 1 步：找分配和释放的对
grep -rn "malloc\|calloc\|realloc" --include="*.c" <源码树>/ | grep "session"
grep -rn "free.*session\|kfree.*session" --include="*.c" <源码树>/

# 第 2 步：检查是否有多条释放路径
# 如果 free(p) 出现在 >1 个函数里，检查是否有条件保护
grep -rn "free.*session" --include="*.c" <源码树>/
# 结果: free(sess) @ timeout_thread.c:15   ← 超时释放
#        free(sess) @ io_complete.c:22     ← IO 完成也释放！  ← 竞态双释放

# 第 3 步：找 stale 引用（释放后还在用的指针）
grep -rn "session->" --include="*.c" <源码树>/
# 检查每个使用点：这个指针在此时是否可能已被释放？

# 第 4 步：找引用计数/锁的保护
grep -rn "atomic\|refcount\|mutex\|spin_lock\|rwlock" --include="*.c" --include="*.h" <源码树>/ | \
    grep "session"
# 结果: 无任何锁保护！  ← 根因：并发释放无保护
```

##### 4c-5. 多线程竞态分析（竞态场景）

```bash
# 第 1 步：找所有线程的入口函数
grep -rn "pthread_create\|thread_run\|kthread" --include="*.c" <源码树>/

# 第 2 步：找线程间共享的数据
# 方法：找在多个线程函数中都引用的全局变量
for var in $(grep -rn "^static\|^volatile" --include="*.c" <源码树>/ | \
    awk -F: '{print $3}' | grep -o "[a-z_]*g_[a-z_]*\|[a-z_]*_shared[a-z_]*" | sort -u); do
    count=$(grep -rn "$var" --include="*.c" <源码树>/ | wc -l)
    [ "$count" -gt 3 ] && echo "共享变量: $var ($count 处引用)"
done

# 第 3 步：检查共享数据的锁保护
grep -rn "g_reload\|g_table\|g_nodes" --include="*.c" <源码树>/ | \
    while read line; do
        file=$(echo "$line" | cut -d: -f1)
        # 检查这个使用点前后有没有锁
        grep -B5 -A5 "$(echo "$line" | cut -d: -f2)" "$file" | grep -c "mutex\|lock\|atomic"
    done
# 结果: 0 → 无锁保护！  ← 竞态根因

# 第 4 步：找锁的获取/释放顺序（死锁/竞态）
grep -rn "pthread_mutex_lock\|pthread_mutex_unlock" --include="*.c" <源码树>/
# 检查是否所有路径都成对（lock/unlock），是否有嵌套锁顺序不一致
```

##### 4c-6. 数据结构定义与偏移验证

```bash
# 找结构体定义（理解崩溃地址对应的字段）
grep -rn "struct fan_ctrl" --include="*.h" <源码树>/ -A 20
# 确认: set_pwm 在偏移 24 处（与报告"块内+0x18"对齐？）

# 找字段偏移（如果报告说崩溃地址 = 对象基址 + 0x18）
grep -rn "offsetof.*fan_ctrl\|offsetof.*set_pwm" --include="*.c" <源码树>/
# 或者手动算: name[16]=0~15, pwm=16~19, pad=20~23, set_pwm=24~31 → 偏移 24=0x18 ✓

# 验证相邻 chunk 的数据结构（工具说"相邻块是嫌疑"）
# 如果受害块在 chunk+0x290，相邻块在 chunk+0x180（前块）或 chunk+0x2c0（后块）
# 找到这些偏移对应的结构体 → 就是嫌疑对象
```

##### 4c-7. 跨进程共享资源分析（进程间竞态/共享内存损坏场景）

BMC 上多个守护进程共享数据库/共享内存/信号量，崩溃可能由另一个进程的
操作引发。你需要跨进程追踪公共接口和共享资源的所有使用者。

**核心思路：崩溃进程只是受害者，肇事者可能在另一个进程里。**

```bash
# ---- 第 1 步：识别共享资源的类型 ----

# 共享内存 (mmap MAP_SHARED / shm_open)
grep -rn "shm_open\|mmap.*MAP_SHARED\|shmget\|shmctl" --include="*.c" <源码树>/

# 共享数据库文件 (SQLite/LMDB/自定义格式)
grep -rn "sqlite3_open\|mdb_env_open\|open.*\.db\|open.*\.mdb" --include="*.c" <源码树>/

# 进程间通信 (消息队列/管道/套接字)
grep -rn "mq_open\|msgget\|pipe(\|socketpair\|unix_socket" --include="*.c" <源码树>/

# 文件锁 (flock/fcntl)
grep -rn "flock\|fcntl.*F_SETLK\|fcntl.*F_OFD_SETLK" --include="*.c" <源码树>/

# ---- 第 2 步：找共享资源的所有进程使用者 ----

# 方法 A：按数据库/共享文件路径搜（找到所有打开同一文件的进程）
grep -rn "/var/lib/sensor_db\|/dev/shm/bmc_\|/tmp/bmc_" --include="*.c" <源码树>/
# 结果: 进程A sensor_mgr.c:42 打开了 sensor_db
#        进程B cli_tool.c:28 也打开了 sensor_db！  ← 两个进程共用

# 方法 B：按 shm 名称搜
grep -rn "shm_open.*bmc\|/dev/shm/bmc" --include="*.c" <源码_tree>/
# 结果: 进程A writer.c:30 创建了 /dev/shm/bmc_status
#        进程B reader.c:25 attach 了同一共享内存  ← 共享

# 方法 C：搜索公共头文件中的 extern 全局变量（跨 .so 共享）
grep -rn "extern.*g_shared\|extern.*g_db\|extern.*g_status" --include="*.h" <源码树>/

# ---- 第 3 步：分析公共接口的使用规范 ----

# 找接口的声明（头文件中的 API 定义）
grep -rn "db_get\|db_put\|db_delete\|db_reload\|db_compact" --include="*.h" <源码树>/
# 结果: int db_get(struct db_handle *, const char *key, void *buf, size_t len);

# 找接口的所有实现（可能有多个后端）
grep -rn "int db_get" --include="*.c" <源码树>/
# 结果: db_sqlite.c:120 实现 A (SQLite 后端)
#        db_lmdb.c:85 实现 B (LMDB 后端)

# 找接口的所有调用者（跨进程分析的关键）
grep -rn "db_get(" --include="*.c" <源码树>/ | grep -v "db_get.*{$\|int db_get\|\.h:"
# 结果: sensor_mgr.c:230 (进程A调用)
#        cli_tool.c:85 (进程B也调用！)  ← 多进程并发使用

# ---- 第 4 步：检查接口的线程/进程安全声明 ----

# 找接口的注释和文档
grep -B5 "int db_get" --include="*.h" -r <源码树>/
# 看有没有说明 "thread-safe" / "NOT thread-safe" / "caller must hold lock"

# 找接口内部的锁
grep -A20 "int db_get" --include="*.c" -r <源码树>/ | grep "mutex\|lock\|sem"
# 结果: db_sqlite.c:125 有 pthread_mutex_lock  ← SQLite 后端有锁
#        db_lmdb.c:90 没有任何锁！             ← LMDB 后端无锁！ ← 嫌疑

# ---- 第 5 步：分析数据库操作的一致性 ----

# 事务边界（SQLite）
grep -rn "BEGIN\|COMMIT\|ROLLBACK\|sqlite3_exec.*TRANSACTION" --include="*.c" <源码树>/
# 检查: 是否所有写操作都在事务里？有没有裸写？

# 锁粒度（LMDB）
grep -rn "MDB_RDONLY\|mdb_txn_begin\|mdb_txn_commit\|mdb_txn_abort" --include="*.c" <源码_tree>/
# 检查: 写事务是否独占？读事务是否长寿（阻塞写者）？

# 文件锁协调
grep -rn "flock.*LOCK_EX\|flock.*LOCK_SH\|fcntl.*F_SETLK" --include="*.c" <源码树>/
# 检查: 所有进程是否遵循相同的锁协议？有没有绕过锁直接操作的？
```

**跨进程分析的关键模式**：

| 场景 | 搜索目标 | 判断标准 |
|---|---|---|
| 共享内存踩踏 | `mmap.*MAP_SHARED` 的所有调用者 | 写入者是否有互斥保护？偏移是否越界？ |
| 数据库并发损坏 | `db_xxx(` 的跨进程调用者 | 是否使用事务？是否有进程绕过 API 直接写文件？ |
| 文件替换竞态 | `rename\|unlink\|ftruncate` 的调用者 | 其他进程是否还在使用旧 fd/映射？ |
| 共享 so 重载 | `dlopen\|dlclose\|LD_LIBRARY_PATH` | 卸载时是否有其他进程还在调用其中的函数？ |
| 信号量死锁 | `sem_wait\|sem_post` 的所有调用点 | 是否所有路径都成对 wait/post？ |

**特别注意**：core 只包含崩溃进程的内存映像——**另一个进程（肇事者）的
栈和堆你看不到**。你只能通过以下间接证据推断肇事者的行为：
- 共享内存中的脏数据（指纹/垃圾值）
- 数据库文件的异常状态（损坏的页面/索引）
- 文件时间戳与 core 生成时间的关系
- console 日志中两个进程的交错输出

##### 4c-8. 数据库接口深度分析（SQLite/LMDB/自定义格式）

**当崩溃涉及数据库操作时，你需要额外检查以下几类问题：**

```bash
# ---- SQLite 场景 ----

# 1. 连接生命周期
grep -rn "sqlite3_open\|sqlite3_close\|sqlite3_close_v2" --include="*.c" <源码树>/
# 检查: open 和 close 是否在同一进程？是否有多线程共享连接（不允许）？

# 2. 语句生命周期
grep -rn "sqlite3_prepare\|sqlite3_finalize\|sqlite3_step" --include="*.c" <源码树>/
# 检查: prepare 后是否一定 finalize？是否有 double finalize？
#        step 过程中是否有其他线程 close 了连接？

# 3. 事务完整性
grep -rn "sqlite3_exec.*BEGIN\|sqlite3_exec.*COMMIT\|sqlite3_exec.*ROLLBACK" --include="*.c" <源码_tree>/
# 检查: 所有写操作是否在事务里？异常路径是否有 ROLLBACK？

# 4. mmap 模式
grep -rn "PRAGMA mmap_size\|sqlite3_config.*mmap" --include="*.c" <源码树>/
# 如果启用了 mmap：外部截断 db 文件会导致 SIGBUS（工具报告会体现）

# ---- LMDB 场景 ----

# 1. 环境生命周期
grep -rn "mdb_env_create\|mdb_env_open\|mdb_env_close\|mdb_env_sync" --include="*.c" <源码树>/
# 检查: close 时是否有其他线程/进程正在操作？

# 2. 事务边界
grep -rn "mdb_txn_begin\|mdb_txn_commit\|mdb_txn_abort\|mdb_txn_reset" --include="*.c" <源码树>/
# 检查: 写事务是否有嵌套？读事务是否忘记 abort（会阻塞写者）？
#        double abort（同一 txn abort 两次）？

# 3. 游标生命周期
grep -rn "mdb_cursor_open\|mdb_cursor_close\|mdb_cursor_get" --include="*.c" <源码_tree>/
# 检查: cursor 是否在 txn abort 之后还在使用（UAF）？

# 4. map size 管理
grep -rn "mdb_env_set_mapsize\|mdb_env_info" --include="*.c" <源码树>/
# 检查: 多进程是否设置了不同的 mapsize（可能导致越界访问）？

# ---- 自定义格式（flat file / binary）----

# 1. 文件读写协议
grep -rn "fread\|fwrite\|pread\|pwrite\|mmap" --include="*.c" <源码树>/ | grep "db\|data\|store"
# 检查: 读写是否有互斥？是否原子？

# 2. 文件锁
grep -rn "flock\|fcntl.*LOCK" --include="*.c" <源码_tree>/ | grep "db\|data"
# 检查: 是否所有访问者都遵循锁协议？

# 3. 原子替换
grep -rn "rename\|tmpfile\|O_TRUNC" --include="*.c" <源码树>/ | grep "db\|data\|store"
# 检查: 替换文件时是否有其他进程还在用旧文件？
```

##### 4c-9. glibc 运行时竞态分析（fork/exec/线程创建/malloc/信号）

glibc 自身提供的大量 API 在并发场景下有严格的使用约束。崩溃可能不是
业务代码的 bug，而是**误用了 glibc 的非线程安全/非 fork 安全接口**。

###### 4c-9a. fork 与多线程的交互（fork-safe 问题）

**核心规则**：`fork()` 只复制调用线程，其他线程在子进程中消失——但它们
持有的锁/堆状态/条件变量全部残留在子进程里。

```bash
# 第 1 步：找 fork 调用点
grep -rn "fork()\|vfork()" --include="*.c" <源码树>/

# 第 2 步：检查 fork 时是否有其他线程持有锁
# 方法：找 fork 调用所在函数的前后上下文，看是否有多线程环境
grep -B5 -A5 "fork()" --include="*.c" <源码树>/ | \
    grep -c "pthread_create\|pthread_mutex"
# 结果 > 0 → fork 发生在多线程进程中！

# 第 3 步：检查是否使用了 pthread_atfork
grep -rn "pthread_atfork" --include="*.c" <源码树>/
# 结果为空 → 没有注册 fork 前后的锁保护回调！
# 后果：子进程继承了一个已锁的 mutex，首次 lock 就死锁

# 第 4 步：检查子进程里做了什么（是否调用了非 async-signal-safe 函数）
grep -A20 "fork()" --include="*.c" <源码_tree>/ | \
    grep "malloc\|free\|printf\|fopen\|syslog"
# 结果: 子进程里调用了 malloc → 如果 fork 时另一个线程正在 malloc，
#        堆的内部锁被继承为"已锁"状态 → 子进程 malloc 死锁或崩溃
```

**常见 fork 竞态崩溃模式**：

| 模式 | 原因 | 崩溃表现 |
|---|---|---|
| 子进程死锁 | fork 时另一线程持锁，子进程继承已锁的 mutex | 子进程 hang（不是 core，但影响监控） |
| 子进程堆损坏 | fork 时另一线程正在 malloc，堆元数据半更新 | 子进程 malloc abort |
| stdio 双写 | fork 时另一线程在 printf，缓冲区半满 | 输出乱码或 double free |
| atexit handlers | 子进程退出时执行了父进程的 cleanup | double free / UAF |

###### 4c-9b. 非线程安全函数的误用

**glibc 中大量函数不是线程安全的**——多线程同时调用会崩溃或数据损坏。

```bash
# ---- 组 1：明确非线程安全的（多线程调用 = 崩溃） ----
grep -rn "strtok(\|localtime(\|asctime(\|ctime(\|gethostbyname(\|getpwnam(" \
    --include="*.c" <源码_tree>/ | grep -v "_r(\|_reentrant"
# 任何命中都是 bug！应改用 _r 后缀版本（strtok_r/localtime_r/...）

# ---- 组 2：静态缓冲区返回（线程间共享返回值） ----
grep -rn "inet_ntoa(\|getenv(" --include="*.c" <源码树>/
# inet_ntoa 返回静态缓冲区——两个线程同时调用会互相覆盖
# getenv 在 setenv 并发时可能返回悬垂指针

# ---- 组 3：setenv/putenv 与 getenv 的竞态 ----
grep -rn "setenv\|putenv\|unsetenv" --include="*.c" <源码_tree>/
# 如果一个线程 setenv，另一个线程 getenv → 可能读到正在修改的指针

# ---- 组 4：信号处理函数中的非 async-signal-safe 调用 ----
grep -rn "signal(\|sigaction" --include="*.c" <源码树>/ -A5 | \
    grep "malloc\|free\|printf\|fopen\|lock\|mutex"
# 信号处理函数里不能调这些！会导致死锁或堆损坏

# ---- 组 5：dlclose 与线程退出竞态 ----
grep -rn "dlclose\|__attribute__((destructor))" --include="*.c" <源码树>/
# 检查：是否有线程还在执行 so 中的代码时 dlclose 了该 so？

# ---- 组 6：exit 与线程退出竞态 ----
grep -rn "exit(\|_exit(\|pthread_exit" --include="*.c" <源码树>/
# exit() 会执行 atexit/cleanup → 如果另一个线程还在用被 cleanup 的资源 → UAF
```

###### 4c-9c. malloc/free 的多线程竞态（堆竞技场问题）

**glibc 的堆是分竞技场（arena）的**——不同线程有自己的 arena，但跨线程
free 另一个线程 arena 中的 chunk 可能触发问题。

```bash
# 第 1 步：找跨线程 free 的场景
# 方法：一个线程分配、另一个线程释放
grep -rn "pthread_create" --include="*.c" <源码树>/ -A5 | grep "malloc"
grep -rn "free(" --include="*.c" <源码树>/ | grep -v "same_func"
# 检查：malloc 和 free 是否在不同函数/线程中？

# 第 2 步：检查是否有 tcache 相关的并发问题
# 症状：console 日志出现 "double free detected in tcache" 或
#        "unaligned tcache chunk detected"
grep -rn "MALLOC_CHECK\|mallopt\|M_ARENA" --include="*.c" <源码树>/
# 如果设置了 M_ARENA_MAX=1 → 所有线程共用一个 arena → 锁竞争加剧

# 第 3 步：检查线程本地存储(TLS)析构与堆的交互
grep -rn "__thread\|thread_local\|__declspec(thread)" --include="*.c" --include="*.h" <源码_tree>/
# TLS 变量的析构在线程退出时执行——如果析构函数 free 了堆内存，
# 而另一个线程同时也在操作那块内存 → 竞态

# 第 4 步：检查 fork 后子进程是否使用了父进程的堆
# fork 时堆状态被快照——如果父进程有另一个线程正在 malloc/free，
# 堆链表可能处于不一致状态
grep -A10 "fork()" --include="*.c" <源码树>/ | \
    grep "malloc\|free\|realloc\|calloc"
# 子进程 fork 后立即调用这些 → 可能踩到不一致的堆链表
```

###### 4c-9d. 信号与多线程的竞态

```bash
# 第 1 步：找信号处理函数
grep -rn "signal(\|sigaction(" --include="*.c" <源码_tree>/ | \
    grep -v "SIG_IGN\|SIG_DFL"
# 列出所有自定义信号处理函数

# 第 2 步：检查信号处理函数中做了什么
grep -A10 "void.*signal_handler\|void.*sig_handler" --include="*.c" <源码树>/
# 以下操作在信号处理函数中是 FORBIDDEN 的：
# - malloc/free（非 async-signal-safe）
# - printf/fprintf（可能死锁 stdio 内部锁）
# - pthread_mutex_lock（如果信号打断了一个已持锁的线程 → 死锁）
# - 非原子全局变量写入（另一个线程可能正在读）

# 第 3 步：检查信号是否指定了处理线程（sigprocmask/pthread_sigmask）
grep -rn "pthread_sigmask\|sigprocmask" --include="*.c" <源码_tree>/
# 最佳实践：主线程 block 所有信号，创建一个专门的信号处理线程

# 第 4 步：检查 SIGSEGV/SIGBUS 处理函数里是否做了复杂操作
grep -B3 -A10 "SIGSEGV\|SIGBUS" --include="*.c" <源码树>/ | grep -A10 "handler"
# 在 SIGSEGV handler 里做 backtrace/打印 → 可能二次崩溃（栈溢出时尤其危险）
```

**glibc 竞态速查表**（加入总结表）：

| 症状 | 根因 | 搜索模式 |
|---|---|---|
| fork 后子进程 hang | fork 时其他线程持锁 | `grep fork + pthread_atfork` |
| fork 后子进程 malloc abort | fork 时堆不一致 | `grep fork 后的 malloc 调用` |
| 多线程调用同一路径崩 | 非线程安全函数 | `grep strtok/localtime/inet_ntoa（无 _r）` |
| 信号处理中死锁 | handler 里用了 lock/stdio | `grep handler 内的 lock/printf` |
| "double free in tcache" | 跨线程 free 或竞态 free | `grep 跨函数的 malloc/free 对` |
| "unaligned tcache" | tcache 链被踩（UAF/溢出） | `grep memset/strcpy 越界写` |
| dlclose 后跳飞 | 线程还在用已卸载的 so | `grep dlclose + 线程生命周期` |
| exit 时 UAF | atexit cleanup 与线程竞态 | `grep atexit + destructor + exit` |

##### 4c-10. 搜索技巧总结

| 你要找什么 | 搜什么 | 适用场景 |
|---|---|---|
| 指纹字符串 | `grep -rn "指纹内容"` | 堆被踩 |
| 变量的所有赋值 | `grep -rn "varname\s*="` | 空指针追溯 |
| 变量的所有使用 | `grep -rn "varname->\|varname\."` | 找读写点 |
| 谁释放了它 | `grep -rn "free.*varname\|varname\s*=\s*NULL"` | UAF/双释放 |
| 谁初始化了它 | `grep -rn "init.*varname\|varname\s*=\s*malloc"` | 初始化遗漏 |
| 无边界检查的拷贝 | `grep -rn "strcpy\|memcpy\|sprintf" \| grep -v "n\|bounds"` | 堆/栈溢出 |
| 函数指针赋值 | `grep -rn "->func\|\.func\s*=" \| grep -v NULL` | 坏回调 |
| 锁保护缺失 | `grep -rn "shared_var" \| grep -cv "lock\|mutex\|atomic"` | 竞态 |
| 结构体定义 | `grep -rn "struct.*name" --include="*.h" -A 20` | 偏移验证 |
| 所有调用者 | `grep -rn "function_name(" \| grep -v "static\|inline"` | 调用链 |
| **共享内存的进程** | `grep -rn "shm_open\|mmap.*SHARED" \| grep -v "#"` | **跨进程竞态** |
| **数据库接口调用者** | `grep -rn "db_get(\|db_put(" \| grep -v "\.h:"` | **多进程DB并发** |
| **事务完整性** | `grep -rn "BEGIN\|COMMIT\|ROLLBACK"` | **数据库一致性** |
| **文件替换竞态** | `grep -rn "rename\|unlink\|ftruncate" \| grep -v test\|doc` | **进程间文件冲突** |
| **SQLite 语句泄漏** | `grep -rn "prepare" \| grep -cv "finalize"` | **UAF/double finalize** |
| **LMDB 事务泄漏** | `grep -rn "txn_begin" \| grep -cv "txn_abort\|txn_commit"` | **写者阻塞/死锁** |
| **fork 后持锁** | `grep "fork()" -A5 \| grep -c "pthread"` + `grep -rn "pthread_atfork"` | **fork-safe** |
| **非线程安全函数** | `grep -rn "strtok(\|localtime(\|inet_ntoa(" \| grep -v "_r("` | **线程安全违规** |
| **信号 handler 违规** | `grep -A10 "signal_handler\|sig_handler" \| grep "malloc\|printf\|lock"` | **async-signal-safe** |
| **跨线程 free** | `grep -rn "malloc" -A5 \| grep "free" \| grep -v "same_func"` | **tcache 竞态** |
| **dlclose 竞态** | `grep -rn "dlclose" -A5 \| grep "thread\|pthread"` | **so 卸载竞态** |

#### 4d. 交叉验证

- 报告回溯中的函数调用关系是否合理？（防止栈污染假帧）
- 崩溃线程和肇事线程是否不同？（多线程场景，报告有标注）
- "疑似"结论能否通过源码分析升级为"确认"或否定？

### 第 5 步：输出分析报告

用以下格式给用户（Markdown）：

```markdown
## 崩溃分析

### 1. 概要
- **进程**: remotexdp (pid=6759)
- **架构**: arm64
- **信号**: SIGSEGV @ 0x58585858585858
- **崩溃点**: `fan_pwm_apply` @ `stomped_late.c:49`

### 2. 根因
`fan_pwm_apply` 中的 `f->set_pwm(f, duty)` 调用了一个被踩坏的函数指针。
指针值 0x58585858585858 ('XXXX' 填充) 表明是越界写入覆盖了 `fan_ctrl`
结构体尾部的回调指针。

**肇事代码**：`led_play_breath()`（stomped_late.c:33）中的
`memcpy(dst + g_curve_off, pat, sizeof(pat))` 计算目标地址时偏移错误
（`-0x20`），导致写入越过 LED 效果缓冲区的 chunk 头，恰好覆盖了
前一个 chunk（`fan_ctrl` 结构体）尾部的 `set_pwm` 回调指针。

堆取证确认：堆头完好（不是越界写穿 chunk 头），受害对象块头包含
`'fan0'`（fan_ctrl 的 name 字段），块尾被写入 `'XXXX'`（LED 模块的
填充数据）——受害者和肇事者的身份都锁定了。

### 3. 修复建议

**直接修复**（修正偏移计算）：
```c
// stomped_late.c:33
// 修改前：
memcpy(dst + g_curve_off, pat, sizeof(pat));   // g_curve_off = -0x20（错）
// 修改后：
memcpy(dst, pat, sizeof(pat));                  // 写入本 chunk 起始处（正确）
```

**防御措施**（防止类似问题）：
```c
// 在 led_play_breath 入口添加边界断言
assert(dst >= g_led->curve);
assert(dst + sizeof(pat) <= g_led->curve + sizeof(g_led->curve));
```

### 4. 置信度
| 结论 | 可信度 | 依据 |
|---|---|---|
| 崩溃原因：回调指针被踩 | 确认 | 信号 + pc 值 + 堆取证 |
| 肇事代码：led_play_breath 偏移错误 | 确认 | 指纹匹配 + 源码分析 |
| 修复方案 | 建议 | 基于根因推断 |
```

## 重要原则

1. **不要猜测**——源码不在指定树中就说"源码不可达"，不编造分析
2. **区分事实和建议**——事实用"确认"，推断用"疑似"，建议用"建议"
3. **给可执行的修复**——不是"建议检查空指针"，而是"在第 42 行添加 `if (!dev) return -ENODEV;`"
4. **多线程注意**——崩溃线程≠肇事线程，报告会标注，你要在分析中体现
5. **版本敏感**——如果符号配对报 mismatch，提醒用户符号表版本不对
6. **console 日志很重要**——glibc 的 abort 原因只打印在 stderr，core 里没有
7. **离线模式**——`--offline` 不调用 gdb，但符号配对/栈扫描/行号/堆取证全可用

## 工具参考

bmccore 工具的能力边界（你不需要重复工具做的事，专注于工具做不到的）：

| 工具做的 | 你做的（增量） |
|---|---|
| 运行分析、解析 core | 决定用什么参数、怎么解读结果 |
| 按崩溃帧贴 ±5 行源码 | 读完整函数体、理解上下文 |
| 报"疑似堆数据被踩 + 指纹" | grep 源码定位肇事代码 |
| 给出受害对象地址和大小 | 追溯数据结构定义和生命周期 |
| 报"崩溃线程 tid=X" | 分析多线程竞态场景 |
| 输出 md/json 报告 | 写给人看的分析报告（含修复建议） |

# coredump —— BMC coredump 离线分析工具

解析 ARM32 / ARM64 / RISC-V / x86_64 / i386 BMC 用户态进程的 ELF core 文件：
输入 core 包（如 `1_core-2078599821-remotexdp-6759.tar.gz`），结合编译机上
编译阶段单独产出的符号表文件（`--symbol-table`），输出带可信度标注的
Markdown/JSON 定位报告 + Web 可视化面板。

## 核心能力

| 能力 | 说明 |
|---|---|
| 输入识别 | 自动解包 tar.gz/gz/xz；解析文件名（序号/时间戳/进程名/pid）；探测 core 实际转储内容，缺堆/缺栈时对应技能明确降级 |
| 符号自动配对 | 从 core 内存映像还原每个 so 的 build-id，与符号表目录精确配对；配不上/版本不符时明确报警，绝不静默用错符号 |
| GDB 精确回溯 | 自动生成符号加载脚本（file + add-symbol-file）驱动交叉 gdb -batch 回溯 |
| CFI 离线回溯 | 无 gdb 时用 .eh_frame CFI 精确展开（纯 Python，替代启发式栈扫描） |
| 栈扫描兜底 | SP 向下扫代码区候选 + 按架构判定"前一条指令是 call"（ARM/Thumb/A64/RISC-V/x86），每帧如实标注 确认/未验证 |
| glibc 堆取证 | chunk 链走查定位损坏点；前一个 chunk 是重点嫌疑；受害对象探测（堆头完好时用崩溃寄存器定位）；内容指纹指向肇事模块 |
| 变量生命周期追踪 | 从崩溃行提取被解引用的指针，在源码中追溯其声明→赋值→释放→崩溃的完整轨迹 |
| 线程锁关联 | 扫描 pthread_mutex_t 活跃状态，构建等待图，DFS 检测死锁环 |
| 可视化面板 | Web 仪表盘：递进式崩溃故事 + 源码高亮 + 变量时间线 + 内存布局 + 交互式线程浏览器 + 堆健康报告 |
| debuginfod | 按 build-id 从远程 HTTP 服务器拉取符号（标准 debuginfod 协议） |
| Minidump | 支持 Google Breakpad Minidump 格式（线程/模块/异常/内存流） |
| 信号归因 | SIGSEGV 空指针/越界分类、SIGABRT glibc堆/assert/fortify 归因、SIGBUS mmap截断、出错地址归属 |
| 源码联动 | 回溯帧的 file:line 自动到源码树抠 ±5 行上下文贴进报告 |
| 完全离线 | `--offline` 纯 Python 模式，零外部依赖，99 格系统矩阵已验证 |
| 信号归因 | SIGSEGV 空指针/未映射/越界分类、出错地址归属（模块/堆/栈/未映射）、console 日志提取 glibc abort 原因 |
| 源码联动 | 回溯帧的 file:line 自动到源码树抠 ±5 行上下文贴进报告 |

## 快速开始（编译服务器）

```bash
cp bmccore.toml.example bmccore.toml   # 配产物目录/源码树/sysroot/工具链
python3 bmccore.py analyze 1_core-2078599821-remotexdp-6759.tar.gz
```

详见 [docs/使用说明.md](docs/使用说明.md)。

## 傻瓜式使用指南（从零开始，照抄即可）

下面按"第一次用"和"日常用"两个场景给出可直接复制的完整命令。
假设：工具仓库在 `~/bmccore`，core 包拷到了 `~/cores/` 目录。

### 场景 A：第一次用（一次性配置，约 3 分钟）

**第 1 步：确认 Python 版本**（3.8 及以上都行）

```bash
python3 --version     # 输出 3.8.x / 3.9.x / ... / 3.13.x 均可
```

**第 2 步：确认交叉 gdb（可选，但强烈建议装）**

```bash
which aarch64-linux-gnu-gdb gdb-multiarch    # 有任意一个就行
```

- 都没有？`sudo apt install gdb-multiarch`（其他发行版同理）。
- 实在没有也能跑：回溯技能会跳过，栈扫描兜底照常工作，只是报告
  少一节精确回溯。

**第 3 步：写配置文件**（放在 core 包所在的目录，或其任意上层目录）

```bash
cd ~/cores
cp ~/bmccore/bmccore.toml.example bmccore.toml
vi bmccore.toml      # 只需要改下面 3 行
```

必改的 3 行（其他行保持默认）：

```toml
# ① 符号表文件或目录的绝对路径（编译阶段单独产出的 ELF，含 build-id+symtab+DWARF）
#    单个文件: symbol_table = "/home/bmc/build/symbols/main.elf"
#    目录:     symbol_table = "/home/bmc/build/symbols/"
symbol_table = "/home/bmc/build/symbols"

# ② 源码树根：让报告贴出崩溃行前后 5 行源码（没有可不配）
source_root = "/home/bmc/src/bmc-project"

# ③ 固件根文件系统（staging 目录，so 路径兜底用；没有可不配）
sysroot = "/home/bmc/build/rootfs"
```

工具链部分**不用改**——默认会自动探测 `aarch64-linux-gnu-gdb` 等常见
前缀，找不到就用 `gdb-multiarch` 兜底。

**完成。** 配置只需这一次，之后分析任何 core 都不用再动。

### 场景 B：日常使用（每次崩溃，两条命令）

**第 1 步：先看一眼摘要**（秒出，不解符号）

```bash
cd ~/cores
python3 ~/bmccore/bmccore.py info 1_core-2078599821-remotexdp-6759.tar.gz
```

输出长这样（架构/信号/崩溃线程/已加载模块……）：

```
  架构        : arm64 (ELF64)
  崩溃信号    : 11
  出错地址    : 0x0
  线程数      : 1
  崩溃线程    : tid=6759 pc=0x7f08022e0728 sp=0x4000008006d0
```

**第 2 步：全量分析**（解符号+回溯+堆取证，一条命令出报告）

```bash
# 强烈建议带上串口日志：glibc 堆报错只打印在设备 stderr，core 里没有
python3 ~/bmccore/bmccore.py analyze 1_core-2078599821-remotexdp-6759.tar.gz \
    --console-log console.log
```

跑完会在 core 包旁边生成 `bmccore_report/` 目录，屏幕同时打印摘要：

```
  [确认] 空指针解引用：访问地址 0x0（空指针+0 偏移...）
  技能 backtrace  ok
  技能 heap       ok
  ...
  报告: ~/cores/bmccore_report/1_core-..._report.md    ← 打开这个文件
```

**第 3 步：读报告**（按顺序看三处，2 分钟定位）

1. **"定位结论"表（报告最后）**：最终答案。每条带可信度——
   `确认` = 有硬证据（信号/console/指令级验证），可直接信；
   `疑似` = 强启发式推断，会注明依据。
2. **"线程回溯"**：崩溃线程的调用栈（`#0` 是崩溃点，往上是谁调的），
   带源码文件:行号。
3. **"堆取证"（如有）**：内存被踩时看这里——损坏点位置、
   **前一个 chunk 是重点嫌疑**、内容指纹（拿字符串去源码 grep 常直接
   锁定肇事模块）。

### 常见问题速查

| 现象 | 原因 | 怎么办 |
|---|---|---|
| 回溯帧是 `??` 或没有行号 | 符号表 strip 了或没编 `-g` | 确认 `symbol_table` 指向的是**未 strip** 的编译输出；行号要 `-g` 编译 |
| 报告说某模块 `missing` | 符号表目录里没这个 so | 把对应固件版本的符号表文件补进目录，或 `--module libfoo.so=/路径` 手动指定 |
| 结论只有"崩溃信号 SIGABRT" | 没给串口日志 | 加 `--console-log`，assert/堆报错的原因都在里面 |
| 堆取证说"core 中无堆数据" | 设备端 coredump_filter 裁了匿名段 | 检查 `/proc/<pid>/coredump_filter`（默认 0x33 即可） |
| zstd 压缩包 | 标准库不支持 | 先 `zstd -d` 解开再喂给工具 |
| 版本对不上怕用错符号 | — | 不用担心：工具按 build-id 精确配对，配不上会**明说**而不是猜 |

### 命令速查

```bash
# 快速摘要（不解符号，秒出）
python3 bmccore.py info <core文件或tar.gz包>

# 全量分析（自动读同目录/上层的 bmccore.toml）
python3 bmccore.py analyze <core> [--console-log console.log]

# 手动指定符号表/源码（不想写 toml 时）
python3 bmccore.py analyze <core> --symbol-table /符号表文件或目录 --source-root /源码树

# 主程序配不上时强制指定
python3 bmccore.py analyze <core> --exe /路径/主程序

# 保留中间文件（gdb 脚本等，排障用）
python3 bmccore.py analyze <core> --keep-temp
```

支持的全部参数：`python3 bmccore.py analyze --help`

## 依赖

- **Python 3.8+**（基线 3.8，已在 3.8.18 / 3.12.3 / 3.13.5 实测（单测+CLI 全功能）；vendored pyelftools 固定 0.31.x，tests/test_py38_compat.py 静态防回退）
- 交叉 gdb / addr2line（可选；缺失时对应技能自动降级，栈扫描等纯 Python 能力不受影响）

## 完全离线使用（编译服务器无网络）

**本工具天然离线可用**：零 pip 依赖（pyelftools 已 vendored 在仓库内）、
零 apt 依赖（不需要安装 gdb/addr2line）。把整个仓库目录拷到编译服务器
即可，例如打包传输：

```bash
# 有网机器上打包（或直接 git archive / 复制目录）
tar czf bmccore-offline.tar.gz --exclude=.git -C ~ bmccore
# U盘/scp 送到编译服务器后解压，配置同"傻瓜式指南 场景A"，然后：
python3 bmccore.py analyze 1_core-...tar.gz --offline
```

`--offline` = 纯 Python 模式，**保证不调用任何外部程序**（无网/无工具链
环境的最稳形态）：

| 能力 | 离线（--offline） | 在线（默认，有交叉 gdb） |
|---|---|---|
| 符号配对（build-id）/栈扫描(call 指令级验证)/DWARF 行号/堆取证/受害对象探测/信号归因/源码联动/console 归因 | ✅ 纯 Python | ✅ |
| gdb 精确回溯 | 自动跳过（栈扫描兜底给出调用链） | ✅ |

99 格系统测试（33 维度×3 架构）已按 --offline 全量验证（见
`tests/test_system_matrix.py` 的 `test_system_matrix_offline` 抽样防回退）。
不加 `--offline` 时，若机器上恰好有 gdb 也会自动用上、没有则同样降级。

## Web 可视化面板

分析完成后加 `--viz` 启动 Web 仪表盘（自动检测可用端口，明确显示 IP:PORT）：

```bash
python3 bmccore.py analyze core.tar.gz --symbol-table /path --viz
# 输出:
#   📊 BMC Coredump 崩溃分析面板
#   ➜ 本机:  http://localhost:8080
#   ➜ 局域网: http://192.168.1.100:8080
```

面板包含 7 个数据驱动组件（有数据就显示，没有自动隐藏）：

| 面板 | 内容 |
|---|---|
| 📝 崩溃故事 | 递进式叙事：发生了什么→崩在哪里→怎么走到的→为什么崩 |
| 📄 崩溃源码 | 红色高亮崩溃行，前后 8 行上下文 |
| 🔍 变量追踪 | 指针从声明→赋值→释放→崩溃的竖线时间线 |
| 🗺️ 内存布局 | 堆叠式条形图（代码/堆/栈/只读）+ 明细列表 |
| 🧵 线程浏览器 | 点击任意线程查看其栈回溯（崩溃线程红色高亮） |
| 📦 堆健康报告 | 用人话回答"堆有没有问题、谁踩的、怎么踩的" |
| 🎯 定位结论 | 可信度标注的最终判定 |

`--viz-port 9090` 指定首选端口（被占用自动+1）；`--viz-timeout 30` 定时关闭。

## 关于符号表

**符号表是编译阶段单独产出的文件，使用时通过 `--symbol-table` 指定其绝对路径。**

符号表文件或目录中存放的是**未 strip 的编译输出**（完整 ELF，含 build-id +
symtab + DWARF），工具按以下方式使用：

1. 工具从 core 的内存映像还原每个已加载模块（主程序 + 每个 so）的
   **build-id**，与符号表目录里的文件按 build-id **自动精确配对**——
   版本不符会明确报 mismatch，绝不静默用错符号；
2. 函数名来自符号表 symtab，行号来自符号表 DWARF（`.debug_line`）；
   因此要求编译时保留符号：**不要 strip**，且行号需要 `-g`
   （仅 `-O1` 不加 `-g` 时函数名仍可用，行号缺失会如实标注）；
3. 配不上时的逃生门：`--exe /路径/主程序`、`--module libfoo.so=/路径`
   （可多次），或把对应固件版本的符号表文件补进目录。

符号表文件可以是以下任一形态（工具自动识别 ELF 格式）：
- **完整未 strip ELF**（推荐）：编译输出的原始文件，含 .text/.data/
  .debug_* 全部段——call 指令验证可直接读 .text 字节
- **objcopy --only-keep-debug 产物**：.text 等段变 NOBITS，工具自动
  回退从 core 内存读指令字节（功能不减，速度稍慢）

## 测试

```bash
python tests/run_all.py        # 合成 core 单测，任意平台可跑
```

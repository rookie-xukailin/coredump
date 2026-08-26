# tools/ —— 系统测试 core 生成与分析基础设施

本目录包含 78 维度 × 3 架构 = 234 格系统测试的完整生成、分析、判定、可视化流水线。

## 目录结构

```
tools/
├── cases/               33 个旧维度崩溃案例源码（新 40 维度由生成脚本产出）
├── corefix/             core 文件保真处理工具
│   ├── inject_siginfo.py    注入 NT_SIGINFO（qemu 不写，内核必写）
│   │                        可选第 5 参修补 pr_cursig（断点取核场景）
│   ├── fix_riscv_prstatus.py  riscv64 PRSTATUS 扩容到 376 字节（gdb 只认该尺寸）
│   └── corepatch.py          core 文件中部插字节时同步维护节头表
├── verdict/             程序化判定
│   ├── verdict_matrix.py     在线模式全量判定（234 格）
│   ├── verdict_offline.py    离线模式全量判定
│   └── offline_matrix.sh     离线批量分析
├── gen_matrix.sh        【主入口】生成 234 格 core（编译→qemu运行→gcore→保真→打包）
├── make_cases.sh        基础 12 维度案例源码（空指针/堆/栈/信号/多线程/so）
├── make_cases2.sh       高难度 9 维度（SIGILL/NUL投毒/UAF复用/深链/巨栈/dlopen/信号处理/跨线程/静默踩）
├── make_cases_conc.sh   并发 6 维度（线程间/进程间×数据库资源移动/删除/修改）
├── make_cases_db.sh     引擎 6 维度（SQLite×3/LMDB×2/dlclose×1）
├── make_case21.sh       静默踩内存（堆头完好/延迟引爆）
├── make_cases3.sh       批次1·传统 C 语言经典 21 维度（#34~#54）
├── make_cases4.sh       批次2·硬件/平台/嵌入式 10 维度（#55~#64）
├── make_cases5.sh       批次3·BMC/OpenBMC 特定 9 维度（#65~#73）
├── make_cases6.sh       批次4·消息队列 5 维度（#74~#78）
├── analyze_matrix.sh    批量分析 234 格（符号表模式）
├── build_third.sh       编译 SQLite/LMDB 三架构共享库
├── make_symtables2.sh   构建符号表目录（拷贝未strip ELF + libc/ld）
├── viz_check.py         可视化面板全量校验（逐格构建 viz 数据 + 结构断言）
├── viz_gallery.py       全量格可视化画廊（localhost:8080 浏览全部 234 格）
├── summarize_matrix.py  汇总矩阵结果
├── probe_core.sh        core 文件结构检查（readelf notes/segments）
└── recon_console.sh     重采 console 日志（无 gdb 运行）
```

## 快速开始

```bash
# 0. 前置：三架构交叉链 + qemu-user + gdb-multiarch + Python 3.8+
sudo apt install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf \
                 gcc-riscv64-linux-gnu gdb-multiarch qemu-user-static

# 1. 编译三方库（SQLite amalgamation + LMDB，见脚本内下载说明）
./tools/build_third.sh

# 2. 生成全部 78 个案例源码
bash tools/make_cases.sh && bash tools/make_cases2.sh && \
bash tools/make_cases_conc.sh && bash tools/make_cases_db.sh && \
bash tools/make_case21.sh && bash tools/make_cases3.sh && \
bash tools/make_cases6.sh && \
bash tools/make_cases4.sh && bash tools/make_cases5.sh

# 3. 生成 234 格 core（约 30 分钟，自动含保真处理）
bash tools/gen_matrix.sh

# 4. 构建符号表目录
bash tools/make_symtables2.sh

# 5. 批量分析
bash tools/analyze_matrix.sh

# 6. 程序化判定
python3 tools/verdict/verdict_matrix.py

# 7. 可视化校验 + 画廊（localhost:8080 浏览全部格）
python3 tools/viz_check.py
python3 tools/viz_gallery.py &
```

## 新增 45 维度（#34~#78）

### 批次 1：传统 C 语言经典（21 个）
realloc 悬垂/返回栈地址/非堆 free/未初始化栈指针/差一越界/
32 位乘法回绕/sprintf 溢出(fortify)/strlen 无终止/sizeof 参数退化/
union 混用/符号转换/只读段写/字节序错读/定时器 UAF/atexit UAF/
关闭顺序/fd 耗尽/malloc NULL/SIGPIPE/SIGFPE/嵌套信号

### 批次 2：硬件/平台/嵌入式特定（10 个）
缺 volatile 寄存器读/非对齐访问(双形态)/DMA 对齐/EEPROM 垃圾函数指针/
配置数组尺寸/argv 缺失/初始化顺序/看门狗卡死/线程挂死/锁死锁

### 批次 3：BMC/OpenBMC 特定（9 个）
IPMI crafted 报文/FRU 损坏/sensor 热插拔/I2C 超时旧缓存/
D-Bus 属性 UAF/电源切换上下文/SEL 写满/shm 对象移除后访问/FIFO SIGPIPE

### 批次 4：消息队列（5 个）
POSIX mq 消费者线程 UAF（qemu 未实现 mq_notify，通知语义以阻塞消费者
实现）/接收缓冲过小 EMSGSIZE 未检查（残留旧消息野偏移）/消息长度字段
未校验反序列化越界/SysV 队列被 IPC_RMID 后返回值当长度用/自研环形队列
满判断缺失越界写

## qemu-user 环境适配（生成层，不影响真机语义）

| 适配 | 原因 | 方案 |
|---|---|---|
| SIGPIPE 断点取核 | qemu gdbstub 不拦截宿主 SIGPIPE（直接杀死仿真器） | 案例以 poll 探测 EPIPE 后走 ipc_sigpipe_default；gen 在该函数断点 gcore，再注入 NT_SIGINFO(13)+修补 pr_cursig |
| shm 对象移除用 rename | unlink 后孤儿 inode 截断区的 gcore 读取会击杀仿真器 | 生成环境 rename 移除对象名（真机仍走 unlink） |
| fd 配额 4 | gdb 对宿主 fd 数敏感（>128 崩溃） | 打开配额在软件层模拟 EMFILE |
| 整数除零不陷阱 | arm64/riscv 整数除法返回 0 无异常 | 换算层检测除零后 raise(SIGFPE)（固件规约） |
| mq_notify 不可用 | qemu-user 8.2 未实现 mq_notify 翻译（ENOSYS） | 消息通知语义以阻塞消费者线程实现（mq_consumer_uaf） |

## 保真处理说明

qemu-user 生成的 core 与真实内核 core 有差异，需要以下处理：

1. **NT_SIGINFO 注入**（`corefix/inject_siginfo.py`）
   - qemu 不写 NT_SIGINFO，内核必写
   - 注入位置：最后一个完整非 GDB note 之后（GDB note 的 desc 会吞噬追加内容）
   - 信号/出错地址取自 gdb 停止事件的真实上报

2. **riscv64 PRSTATUS 扩容**（`corefix/fix_riscv_prstatus.py`）
   - gcore 对 riscv64 只写 336 字节（截断），gdb 只接受 376 字节
   - 尺寸矩阵实测：336→unavailable, 376→正常, 其他→段错误

3. **节头表维护**（`corefix/corepatch.py`）
   - gdb core 自带 section header table
   - 文件中部插字节必须同步平移 e_shoff + section offset/size
   - PT_NOTE filesz 以 .shstrtab 起点为界

4. **gcore 前置**（gen_matrix.sh）
   - gcore 排在 info registers/bt 之前执行——个别 core 状态会触发
     gdb 自身崩溃（fd 风暴类），先落盘再采集日志

## 可视化验证

```bash
# 逐格校验面板数据结构（全量格过一遍，产出 viz/<tag>.json）
python3 tools/viz_check.py

# 8080 端口画廊：索引页按批次分组，逐格查看完整分析面板
python3 tools/viz_gallery.py
```

## 深度分析（v5：gdb+Python 双引擎全量取证 → 证据包 → LLM 叙事）

引擎在传统"信号+回溯"之上新增五个深度技能，产出 `<case>_evidence.json`
证据包（gdb bt full 帧变量运行时值/寄存器全解码/崩溃现场反汇编/栈内存
逐字解码/堆对象字段级还原+持有链/锁等待图，每条标注来源与可信度）：

| 技能 | 路径 | 产出 |
|---|---|---|
| deepdive | gdb（bt full/info registers/x 反汇编+x 栈/p *ptr 表达式） | 每帧参数+局部变量运行时值、崩溃指令流、栈原始字、对象解引用 |
| framevars | gdb bt full；离线兜底=DIE 参数表(DW_OP_regN)×入口寄存器 | 崩溃链各帧变量值（标注确认/离线启发式） |
| regs | Python（区域/全局名/堆块/栈偏移/字符串语义化） | 全部 GP 寄存器"它是什么"解码，参数寄存器与 DIE 参数名配对 |
| stackdump | Python | 崩溃线程 SP 起 64 字逐字语义解码 |
| heaptyping | Python（DIE 结构体表） | 受害/嫌疑 chunk 字段级还原 + "谁持有该指针"持有链 |

triage 新增结论源：参数归因（崩溃经由参数 X 传入，值 Y）、寄存器×出错
地址交叉（精确/页级基址归因）、死锁环。vartrace 与运行时值联动（悬垂
指针判定）。面板新增 5 张卡片（帧变量/反汇编/寄存器/栈内存/锁关系）；
SKILL.md 六步法把证据包列为叙事首选输入，AI 写 narrative.json →
render_report.py 渲染 HTML 闭环。

## 编译基线

`-g -O1`（真实固件级别，不加帧指针）。案例源码经抗优化加固：
- volatile 汇（防死存储消除/常量折叠）
- noinline 定帧（防内联改变帧布局）
- 静态载荷（防栈布局重组）
- 编译屏障（防循环不变量外提）
- 返回局部地址经 memcpy 逃逸（防 GCC 静态改写为 NULL）

# tools/ —— 系统测试 core 生成与分析基础设施

本目录包含 33 维度 × 3 架构 = 99 格系统测试的完整生成、分析、判定流水线。

## 目录结构

```
tools/
├── cases/               33 个崩溃案例的 C 源码（-g -O1 抗优化加固）
├── corefix/             core 文件保真处理工具
│   ├── inject_siginfo.py    注入 NT_SIGINFO（qemu 不写，内核必写）
│   ├── fix_riscv_prstatus.py  riscv64 PRSTATUS 扩容到 376 字节（gdb 只认该尺寸）
│   └── corepatch.py          core 文件中部插字节时同步维护节头表
├── verdict/             程序化判定
│   ├── verdict_matrix.py     在线模式 99 格全量判定
│   ├── verdict_offline.py    离线模式 99 格全量判定
│   └── offline_matrix.sh     离线批量分析
├── gen_matrix.sh        【主入口】生成 99 格 core（编译→qemu运行→gcore→保真→打包）
├── make_cases.sh        基础 12 维度案例源码（空指针/堆/栈/信号/多线程/so）
├── make_cases2.sh       高难度 9 维度（SIGILL/NUL投毒/UAF复用/深链/巨栈/dlopen/信号处理/跨线程/静默踩）
├── make_cases_conc.sh   并发 6 维度（线程间/进程间×数据库资源移动/删除/修改）
├── make_cases_db.sh     引擎 6 维度（SQLite×3/LMDB×2/dlclose×1）
├── make_case21.sh       静默踩内存（堆头完好/延迟引爆）
├── analyze_matrix.sh    批量分析 99 格（符号表模式）
├── build_third.sh       编译 SQLite/LMDB 三架构共享库
├── make_symtables2.sh   构建符号表目录（拷贝未strip ELF + libc/ld）
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

# 2. 生成 33 个案例源码
bash tools/make_cases.sh && bash tools/make_cases2.sh && \
bash tools/make_cases_conc.sh && bash tools/make_cases_db.sh && \
bash tools/make_case21.sh

# 3. 生成 99 格 core（约 15 分钟，自动含保真处理）
bash tools/gen_matrix.sh

# 4. 构建符号表目录
bash tools/make_symtables2.sh

# 5. 批量分析
bash tools/analyze_matrix.sh

# 6. 程序化判定
python3 tools/verdict/verdict_matrix.py
```

## gen_matrix.sh 案例 清单

脚本顶部 `CASES` 变量定义了全部 33 个案例 × 3 架构：

| 案例 | 维度 | 信号 |
|---|---|---|
| null_write | 空指针写 struct 成员 | SEGV |
| wild_mmio | 基址表索引写坏→写未映射(Thumb) | SEGV |
| stack_overflow | 自引用环路无限递归爆栈 | SEGV |
| heap_overflow | 堆溢出写穿 chunk 头, free 暴雷 | ABRT |
| double_free | 重复释放(tcache 检出) | ABRT |
| uaf_write | 大块 free→munmap 后悬垂写 | SEGV |
| oob_read | 报文字段大越界读 | SEGV |
| bad_funcptr | 被写坏的函数指针调用→PC 跳飞 | SEGV |
| stack_smash | 缓冲溢出覆盖 LR 断链 | SEGV |
| assert_fail | 防御性 assert 失败 abort | ABRT |
| thread_crash | 4 线程 worker 空指针崩溃 | SEGV |
| shlib_crash | 链接期 so 内崩溃(跨模块配对) | SEGV |
| ill_jump | 跳入垃圾指令 SIGILL | ILL/TRAP |
| null_poison | 单字节 NUL 堆投毒 | ABRT |
| uaf_reuse | UAF+堆复用类型混淆踩回调 | SEGV |
| deep_chain | 12 层深调用链后空指针 | SEGV |
| hugespan | 单帧 12MB 巨栈一步越界 | SEGV |
| dlopen_crash | dlopen 运行时装载插件内崩溃 | SEGV |
| handler_crash | 信号处理函数内二次空指针 | SEGV |
| blame_thread | 肇事线程≠崩溃线程(堆指纹指认) | ABRT |
| stomped_late | 静默踩内存/堆头完好/延迟引爆 | SEGV |
| db_reload_race | 线程间·数据库整表替换(热更新) | SEGV |
| rec_delete_race | 线程间·删除记录+堆复用悬垂调用 | SEGV |
| shm_truncate_bus | 进程间·部署收缩库文件→SIGBUS | BUS/SEGV |
| db_index_corrupt | 进程间·无锁修改共享库索引→越界读 | SEGV |
| dblfree_concurrent | 线程间·并发双重释放 | ABRT |
| db_compact_race | 线程间·碎片整理移动记录→len 读坏 | SEGV |
| sqlite_close_race | SQLite·跨线程 close+finalize UAF | SEGV |
| sqlite_corrupt_bus | SQLite·扫描中库文件被截断→SIGBUS | BUS |
| sqlite_finalize_uaf | SQLite·双重 finalize UAF | SEGV/ABRT |
| lmdb_close_race | LMDB·env 关闭与活动读者并发 | SEGV |
| lmdb_truncate_bus | LMDB·data.mdb 被部署截断 | BUS |
| dlclose_race | 动态库·dlclose 与调用并发→代码页解映射 | SEGV |

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

## 编译基线

`-g -O1`（真实固件级别，不加帧指针）。案例源码经抗优化加固：
- volatile 汇（防死存储消除/常量折叠）
- noinline 定帧（防内联改变帧布局）
- 静态载荷（防栈布局重组）
- 编译屏障（防循环不变量外提）

# 项目工作规约（bmccore）

本文件对本仓库的所有后续修改生效（AI 助手与人均须遵守）。

## 1. 强制流程：改码 → 全量测试 → 提交

任何代码修改（含"小改动"）完成后，**必须**依次通过：

```bash
# ① 基础单测（必须全过）
python tests/run_all.py          # 18 项，无外部依赖

# ② 系统测试（有真实 core 环境时必须全过：33 维度 × 3 架构 = 99 格）
export BMCCORE_SYSTEM_WORK=<工作目录>   # 布局见 tests/test_system_matrix.py 头注
python tests/run_all.py          # 系统套件将进程内驱动完整分析流水线逐格断言
```

- 系统测试当前基线（**编译级别 -g -O1，与真实固件一致**）：**97 PASS / 0 FAIL / 2 SKIP**
  （SKIP = lmdb_truncate_bus 的 arm64/arm32，qemu SIGBUS 交付不稳，见
  `tests/system_manifest.py` 的 EXPECT_ARCH 注释）。任何新增 FAIL 都许不许提交。
- 修改只影响纯文档/注释时，① 必须跑；② 建议跑。

## 1.5 Python 版本基线

- **Python 3.8+**（真实编译服务器环境；已实测 3.8.18 / 3.12.3 / 3.13.5）：新增代码不得引入 3.9+ 语法/API
  （`tests/test_py38_compat.py` 静态门禁拦截；vendored pyelftools 固定 0.31.x，
  升级前必须在真实 3.8 解释器上重跑全量测试）。

## 2. 提交规约

- 提交到**当前分支**（`develop/rookie/coredump`），不擅自开分支。
- **按逻辑单元拆小提交**（一个 bug 修复一个提交），便于逐个回退。
- 提交信息必须**十分详细**，格式：

```
<type>(<scope>): 一句话摘要

背景:      什么场景暴露的问题（含 33 维度系统测试中的哪个维度/格）
根因:      具体技术原因
修改:      逐条列出改动点（文件:行为级）
验证:      python tests/run_all.py 18/18；系统测试 98/99 PASS（附日志要点）
```

- type: fix / feat / test / docs / refactor / chore

## 3. 系统测试资产

- `tests/system_manifest.py` —— 33 维度 × 3 架构的**单一事实源**：
  每格的维度描述、结论关键词、崩溃函数证据、降级许可、按架构覆盖与
  环境限制（SKIP）。新增场景必须先登记进 manifest 再写生成脚本。
- `tests/test_system_matrix.py` —— 进程内驱动完整流水线（intake→symbols→
  backtrace→scan→heap→console→triage→source）逐格断言。
- core 生成环境要点（WSL Ubuntu 24.04）：
  - 三架构交叉链 + qemu-user-static + gdb-multiarch；`qemu -g` + 交叉 gdb
    `gcore` 产 core（qemu 直接崩溃的 core 缺 NT_FILE，不可用）。
  - 保真处理：NT_SIGINFO 按当次 gdb 停止信号注入；riscv 的 gcore PRSTATUS
    需扩容到 376 字节（gdb 只认该尺寸）；文件中部插字节须同步平移节头表。
  - 生成/分析脚本与全部产物在仓库外部工作目录（不入库）。
- **编译基线 `-g -O1`（真实固件级别，不加帧指针）**：案例源码经抗优化处理
  （volatile 汇/noinline 定帧），杜绝 -O1 的死存储消除/常量折叠/尾调用把
  缺陷机制"合法拆弹"；早期 -O0 产物归档于工作目录 cores_O0/ 供对照。
- **离线能力是发布承诺**：`--offline` 必须保持"零外部程序调用"（99 格
  系统矩阵已按 --offline 全量验证 97/0/2）；任何改动不得让离线模式新依赖
  gdb/addr2line 等外部工具；行号解析走 `bmccore/linetab.py`（纯 Python
  读 DWARF）。抽样防回退见 `test_system_matrix_offline`。

## 4. 已知环境限制（如实记录，不许静默绕过）

| 现象 | 原因 | 处置 |
|---|---|---|
| lmdb_truncate_bus.arm64 无法 gcore | qemu-aarch64 对 mmap 越界 EOF 报 internal SIGBUS 杀死仿真器 | manifest 登记 SKIP |
| ill_jump.arm32 信号为 SIGTRAP | qemu 对 UDF 的上报与真机不同 | 按当次真实信号断言 |
| riscv 越文件 EOF 可报 BUS 或 SEGV | qemu 翻译层差异 | 结论关键词双匹配 |
| dblfree_concurrent 崩溃线程无应用帧 | glibc abort 路径 + qemu clone 线程栈伪影（活体=gcore 一致） | 依据 console glibc 报错断言 |

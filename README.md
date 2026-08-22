# coredump —— BMC coredump 离线分析工具

解析 ARM32 / ARM64 / RISC-V BMC 用户态进程的 ELF core 文件：输入 core 包
（如 `1_core-2078599821-remotexdp-6759.tar.gz`），结合编译机上未 strip 的
编译产物（符号）与交叉工具链，输出带可信度标注的 Markdown/JSON 定位报告。

## 核心能力

| 能力 | 说明 |
|---|---|
| 输入识别 | 自动解包 tar.gz/gz/xz；解析文件名（序号/时间戳/进程名/pid）；探测 core 实际转储内容，缺堆/缺栈时对应技能明确降级 |
| 符号自动配对 | 从 core 内存映像还原每个 so 的 build-id，与产物目录精确配对；配不上/版本不符时明确报警，绝不静默用错符号 |
| GDB 精确回溯 | 自动生成符号加载脚本（file + add-symbol-file）驱动交叉 gdb -batch 回溯 |
| 栈扫描兜底 | GDB 回溯出 `??`/断链时的降级手段：SP 向下扫代码区候选 + 按架构判定"前一条指令是 call"（ARM/Thumb BL/BLR、A64 BL/BLR、RISC-V JAL/JALR），每帧如实标注 确认/未验证；SP 出界/贴栈底直判栈溢出 |
| glibc 堆取证 | chunk 链走查定位损坏点；前一个 chunk 是重点嫌疑（越界写穿模式）；全内存引用搜索（谁指着受害区）；内容指纹（字符串/魔数/填充模式 → 指向肇事模块） |
| 信号归因 | SIGSEGV 空指针/未映射/越界分类、出错地址归属（模块/堆/栈/未映射）、console 日志提取 glibc abort 原因 |
| 源码联动 | 回溯帧的 file:line 自动到源码树抠 ±5 行上下文贴进报告 |

## 快速开始（编译服务器）

```bash
cp bmccore.toml.example bmccore.toml   # 配产物目录/源码树/sysroot/工具链
python3 bmccore.py analyze 1_core-2078599821-remotexdp-6759.tar.gz
```

详见 [docs/使用说明.md](docs/使用说明.md)。

## 依赖

- **Python 3.8+**（基线 3.8，已在 3.8.18/3.12 实测；vendored pyelftools 固定 0.31.x，tests/test_py38_compat.py 静态防回退）
- 交叉 gdb / addr2line（可选；缺失时对应技能自动降级，栈扫描等纯 Python 能力不受影响）

## 测试

```bash
python tests/run_all.py        # 合成 core 单测，任意平台可跑
```

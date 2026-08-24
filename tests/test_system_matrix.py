# -*- coding: utf-8 -*-
"""系统测试：33 维度 × 3 架构 = 99 格真实 core 全量回归。

用真实交叉编译 + qemu 运行产生的 ELF core（见 tests/system_manifest.py）
驱动完整分析流水线，逐格断言：
  1. symbols/triage 技能 ok
  2. 定位结论命中预期关键词（可信度体系内）
  3. 报告正文含预期崩溃函数/行号证据
  4. backtrace ok（标记 degrade 的维度允许降级为栈扫描/判定性结论）

运行条件（默认跳过，保证单测快速）：
    export BMCCORE_SYSTEM_WORK=/path/to/work      # 含 cores/ symtab/ cases/
    python tests/run_all.py                       # 或单跑 pytest tests/test_system_matrix.py

BMCCORE_SYSTEM_WORK 目录布局（与本仓库 tools/gen 脚本产物一致）：
    cores/        99 格 core（<case>_<arch>.core[.gz] 或 1_core-*_<case>_<arch>-*.tar.gz）
    symtab/       分离符号表（objcopy --only-keep-debug 产出，build-id 配对）
    cases/        案例源码（源码联动）
    logs/matrix/  <case>.<arch>.console.log（可选，abort 类归因）
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "coredump-analyze"))
sys.path.insert(0, HERE)

from system_manifest import CASES, ARCHS, EXPECT_ARCH          # noqa: E402


def _find_core(cores_dir, name, arch):
    import glob
    cands = ([os.path.join(cores_dir, "%s_%s.core" % (name, arch)),
              os.path.join(cores_dir, "%s_%s.core.gz" % (name, arch))] +
             sorted(glob.glob(os.path.join(
                 cores_dir, "1_core-*-%s_%s-*.tar.gz" % (name, arch))),
                 reverse=True))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def _iter_cells():
    for name, spec in CASES.items():
        for arch in ARCHS:
            over = EXPECT_ARCH.get((name, arch), spec)
            yield name, arch, over


def _run_matrix():
    """逐格执行；返回 (失败清单, 统计)。"""
    from bmccore.config import Config
    from bmccore.intake import intake
    from bmccore.skills import Pipeline, build_report

    work = os.environ["BMCCORE_SYSTEM_WORK"]
    cores_dir = os.path.join(work, "cores")
    logs_dir = os.path.join(work, "logs", "matrix")

    cfg = Config()
    cfg.symbol_table = os.path.join(work, "symtab")
    cfg.source_root = os.path.join(work, "cases")
    cfg.toolchain = {
        "arm64": {"prefix": "aarch64-linux-gnu-", "gdb": "/usr/bin/gdb-multiarch"},
        "arm32": {"prefix": "arm-linux-gnueabihf-", "gdb": "/usr/bin/gdb-multiarch"},
        "riscv64": {"prefix": "riscv64-linux-gnu-", "gdb": "/usr/bin/gdb-multiarch"},
    }

    fails, n_pass = [], 0
    for name, arch, spec in _iter_cells():
        tag = "%s.%s" % (name, arch)
        if spec is None:
            print("SKIP  %-24s %s（环境限制，见 manifest）" % (tag, ""))
            continue
        core = _find_core(cores_dir, name, arch)
        if not core:
            fails.append("%s: core 缺失" % tag)
            continue

        cfg.console_log = None
        clog = os.path.join(logs_dir, "%s.console.log" % tag)
        if os.path.isfile(clog):
            cfg.console_log = clog

        res = intake(core, keep_temp=True)
        try:
            pipe = Pipeline(res.core_path, cfg, log=lambda _m: None)
            results = pipe.run()
            rep = build_report(results, cfg, res.meta, res.source_name)
            text = rep.render_markdown()
        finally:
            res.cleanup()

        st = results["status"]
        problems = []
        if not st.get("symbols", "").startswith("ok"):
            problems.append("symbols=%s" % st.get("symbols"))
        if not st.get("triage", "").startswith("ok"):
            problems.append("triage=%s" % st.get("triage"))
        concl = "\n".join("|".join(l.split("|")[1:3]) for l in text.splitlines()
                          if l.startswith("| 确认 |") or l.startswith("| 疑似 |"))
        if not any(k.lower() in concl.lower() for k in spec["kw"].split("|")):
            problems.append("结论缺[%s]" % spec["kw"])
        if spec["ev"] not in text:
            problems.append("报告缺证据[%s]" % spec["ev"])
        if not st.get("backtrace", "").startswith("ok") and not spec.get("degrade"):
            problems.append("backtrace=%s" % st.get("backtrace"))

        if problems:
            fails.append("%s: %s" % (tag, "; ".join(problems)))
            print("FAIL  %-24s %s" % (tag, "; ".join(problems)))
        else:
            n_pass += 1
            print("PASS  %-24s (%s)" % (tag, spec["dim"]))
    return fails, n_pass


def test_system_matrix():
    """99 格系统回归（默认跳过；设 BMCCORE_SYSTEM_WORK=<work> 启用）。"""
    if not os.environ.get("BMCCORE_SYSTEM_WORK"):
        print("SKIP  system_matrix（设 BMCCORE_SYSTEM_WORK=<work> "
              "启用 99 格系统回归）")
        return
    fails, n_pass = _run_matrix()
    print("-" * 60)
    print("系统测试: PASS %d, FAIL %d（总格数 %d，含环境 SKIP）"
          % (n_pass, len(fails), len(list(_iter_cells()))))
    if fails:
        raise AssertionError("系统测试失败 %d 格:\n%s" % (len(fails), "\n".join(fails)))


# 离线模式抽样格：(case, arch, 结论关键词, 证据)——覆盖三架构与行号来源
_OFFLINE_CELLS = [
    ("null_write", "arm64", "空指针", "hw_fan_set_pwm"),        # 扫描函数名(symtab)
    ("stomped_late", "arm64", "0x5858585", "stomped_late.c:"),  # LR帧+DWARF行号
    ("assert_fail", "arm32", "断言", "assert_fail.c:"),          # 扫描帧行号
    ("oob_read", "riscv64", "非法内存访问", "sdr_read_at"),      # riscv扫描帧
]


def test_system_matrix_offline():
    """离线模式抽样：无 gdb/addr2line 时纯 Python 能力仍产出结论与证据。"""
    work = os.environ.get("BMCCORE_SYSTEM_WORK")
    if not work:
        print("SKIP  system_matrix_offline（设 BMCCORE_SYSTEM_WORK 启用）")
        return
    from bmccore.config import Config
    from bmccore.intake import intake
    from bmccore.skills import Pipeline, build_report

    cores_dir = os.path.join(work, "cores")
    logs_dir = os.path.join(work, "logs", "matrix")
    cfg = Config()
    cfg.offline = True                     # 不探测任何外部工具
    cfg.toolchain = {}
    cfg.symbol_table = os.path.join(work, "symtab")
    cfg.source_root = os.path.join(work, "cases")

    fails = []
    for name, arch, kw, ev in _OFFLINE_CELLS:
        tag = "%s.%s" % (name, arch)
        core = _find_core(cores_dir, name, arch)
        if not core:
            fails.append("%s: core 缺失" % tag)
            continue
        cfg.console_log = None
        clog = os.path.join(logs_dir, "%s.console.log" % tag)
        if os.path.isfile(clog):
            cfg.console_log = clog
        res = intake(core, keep_temp=True)
        try:
            pipe = Pipeline(res.core_path, cfg, log=lambda _m: None)
            results = pipe.run()
            text = build_report(results, cfg, res.meta, res.source_name).render_markdown()
        finally:
            res.cleanup()
        st = results["status"]
        if st.get("backtrace", "").startswith("ok"):
            fails.append("%s: 离线模式不应调用 gdb" % tag)
        concl = "\n".join(l for l in text.splitlines()
                          if l.startswith("| 确认 |") or l.startswith("| 疑似 |"))
        if kw.lower() not in concl.lower():
            fails.append("%s: 结论缺[%s]" % (tag, kw))
        if ev not in text:
            fails.append("%s: 报告缺证据[%s]" % (tag, ev))
        if fails and fails[-1].startswith(tag):
            continue
        print("PASS  offline %-24s (%s)" % (tag, kw))
    if fails:
        raise AssertionError("离线抽样失败:\n" + "\n".join(fails))
    print("离线抽样: PASS %d" % len(_OFFLINE_CELLS))

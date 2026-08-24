#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bmc-core —— BMC coredump 离线分析工具

用法（编译服务器上，配好 bmccore.toml 后）:
    python3 bmccore.py info  1_core-2078599821-remotexdp-6759.tar.gz
    python3 bmccore.py analyze 1_core-2078599821-remotexdp-6759.tar.gz
"""
import argparse
import os
import sys

from . import __version__
from bmccore.config import Config
from bmccore.intake import intake
from bmccore.skills import Pipeline, build_report


def _load_config(args):
    cfg = Config()
    path = getattr(args, "config", None) or cfg.find_config_file(
        os.path.dirname(os.path.abspath(args.core)) if hasattr(args, "core") else None)
    if path and os.path.isfile(path):
        cfg.update_from_toml(path)
    cfg.update_from_cli(args)
    return cfg


def _fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%d" % n


def cmd_info(args):
    res = intake(args.core, keep_temp=args.keep_temp)
    try:
        from bmccore.corefile import CoreFile
        from bmccore.modules import group_modules
        core = CoreFile(res.core_path)
        summ = core.summary()

        print("=" * 62)
        print("core 概览")
        print("=" * 62)
        print("  输入        : %s (%s)" % (res.source_name,
                                           _fmt_size(os.path.getsize(args.core))))
        if res.meta:
            print("  文件名信息  : seq=%s stamp=%s 进程=%s pid=%s" % (
                res.meta.get("seq"), res.meta.get("stamp"),
                res.meta.get("procname"), res.meta.get("pid")))
        print("  架构        : %s (ELF%d)" % (summ["arch"], summ["elfclass"]))
        print("  崩溃进程    : %s" % (summ["fname"] or summ["exe"] or "?"))
        print("  命令行      : %s" % summ["psargs"])
        print("  崩溃信号    : %s" % summ["signal"])
        print("  出错地址    : %s" % ("0x%x" % summ["fault_addr"]
                                     if summ["fault_addr"] is not None else "-"))
        print("  线程数      : %d" % summ["nthreads"])
        t = core.crash_thread
        if t:
            print("  崩溃线程    : tid=%d pc=0x%x sp=0x%x lr=0x%x" % (
                t.tid, t.pc, t.sp, t.lr))
        print("  已加载模块  : %d" % summ["nmodules"])
        mods = group_modules(core)
        for m in mods[:12]:
            print("    %-24s base=0x%-10x %s" % (
                m.name, m.base, ("build-id=" + m.build_id[:16]) if m.build_id else ""))
        if len(mods) > 12:
            print("    ... 共 %d 个" % len(mods))
        caps = summ["capability"]
        print("  内存段      : %d 段，匿名读写 %s" % (
            caps["regions"], _fmt_size(caps["anon_rw_bytes"])))
        uncovered = [tid for tid, ok in caps["stack_covered"].items() if not ok]
        if uncovered:
            print("  注意        : %d 个线程的栈未转储（coredump_filter 裁剪?）"
                  % len(uncovered))
        if core.arch is None:
            print("  !! 不支持的架构（machine=%s），当前支持 ARM32/ARM64/RISC-V"
                  % core._elf.header["e_machine"])
        return 0
    finally:
        res.cleanup()


def cmd_analyze(args):
    def log(msg):
        if args.debug or True:
            print(msg, file=sys.stderr)

    cfg = _load_config(args)
    res = intake(args.core, keep_temp=True)
    try:
        pipe = Pipeline(res.core_path, cfg, log=log)
        results = pipe.run()
        rep = build_report(results, cfg, res.meta, res.source_name)

        outdir = cfg.output or os.path.join(os.path.dirname(os.path.abspath(args.core)),
                                            "bmccore_report")
        stem = os.path.splitext(res.source_name)[0]
        if stem.endswith(".tar"):
            stem = stem[:-4]
        written = rep.write(outdir, fmt=cfg.fmt, stem=stem + "_report")

        # 摘要打到屏幕
        print("=" * 62)
        print("分析完成: %s" % res.source_name)
        print("=" * 62)
        for c in results["conclusions"]:
            print("  [%s] %s" % (c.confidence, c.text))
        print("-" * 62)
        for k in sorted(results["status"]):
            print("  技能 %-10s %s" % (k, results["status"][k]))
        print("-" * 62)
        for p in written:
            print("  报告: %s" % p)
        if cfg.keep_temp:
            print("  中间文件保留于: %s" % res.temp_dir)
        return 0
    finally:
        if not cfg.keep_temp:
            res.cleanup()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bmccore",
                                 description="BMC coredump 离线分析工具 (ARM32/ARM64/RISC-V)")
    ap.add_argument("--version", action="version", version="bmccore %s" % __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="bmccore.toml 路径（默认向上查找）")

    p_info = sub.add_parser("info", parents=[common], help="快速摘要：架构/信号/线程/模块")
    p_info.add_argument("core", help="core 文件或 tar.gz 包")
    p_info.add_argument("--keep-temp", action="store_true", help=argparse.SUPPRESS)
    p_info.set_defaults(func=cmd_info)

    p_an = sub.add_parser("analyze", parents=[common], help="全量分析并输出报告")
    p_an.add_argument("core", help="core 文件或 tar.gz 包")
    p_an.add_argument("--symbol-table", metavar="PATH",
                      help="符号表文件或目录的绝对路径（编译阶段单独产出的 ELF/"
                           "符号表文件，含 build-id+symtab+DWARF）")
    p_an.add_argument("--artifact-dir", metavar="PATH", dest="artifact_dir",
                      help="[兼容旧参数] 未strip编译产物根目录，等价 --symbol-table")
    p_an.add_argument("--source-root", help="源码树根目录")
    p_an.add_argument("--sysroot", help="固件staging根文件系统")
    p_an.add_argument("--toolchain-prefix", help="交叉工具链前缀（如 aarch64-linux-gnu-）")
    p_an.add_argument("--console-log", help="设备串口/console日志文件")
    p_an.add_argument("--exe", help="强制指定主程序产物路径")
    p_an.add_argument("--module", action="append", default=[], metavar="soname=path",
                      help="强制指定某so产物路径，可多次")
    p_an.add_argument("--glibc-version", help="覆盖自动探测的glibc版本")
    p_an.add_argument("--skills", help="逗号分隔：symbols,backtrace,scan,heap,console,triage,source")
    p_an.add_argument("--crash-thread-only", action="store_true", help="只深挖崩溃线程")
    p_an.add_argument("-o", "--output", help="报告输出目录")
    p_an.add_argument("--format", dest="fmt", choices=["md", "json", "both"], default=None)
    p_an.add_argument("--keep-temp", action="store_true", help="保留解包/gdb中间文件")
    p_an.add_argument("--offline", action="store_true",
                      help="离线模式：不探测/调用 gdb/addr2line 等外部工具"
                           "（纯Python：符号配对/栈扫描/行号(DWARF)/堆取证全可用）")
    p_an.add_argument("--debug", action="store_true")
    p_an.add_argument("--max-scan-depth", type=int, default=None,
                      help="栈扫描最大深度（字节），默认65536")
    p_an.add_argument("--viz", action="store_true",
                      help="分析完成后启动内存可视化 Web 面板")
    p_an.add_argument("--viz-port", type=int, default=8080,
                      help="可视化面板首选端口（被占用时自动+1，默认8080）")
    p_an.add_argument("--viz-timeout", type=int, default=0,
                      help="可视化面板超时秒数（0=持续运行，默认0）")
    p_an.add_argument("--debuginfod-url",
                      help="debuginfod 服务器 URL（远程符号拉取）")
    p_an.set_defaults(func=cmd_analyze)

    p_viz = sub.add_parser("viz", parents=[common],
                           help="单独启动内存可视化（需已生成报告）")
    p_viz.add_argument("core", help="core 文件")
    p_viz.add_argument("--port", type=int, default=8080, help="首选端口")
    p_viz.add_argument("--timeout", type=int, default=0, help="超时秒（0=持续）")

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

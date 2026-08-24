#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bmc-core —— BMC coredump 离线分析工具

用法（编译服务器上，配好 bmccore.toml 后；python3 版本不一时显式用 python3.8）:
    python3.8 bmccore.py info  1_core-2078599821-remotexdp-6759.tar.gz
    python3.8 bmccore.py analyze 1_core-2078599821-remotexdp-6759.tar.gz
"""
import argparse
import json
import os
import shutil
import sys
import tarfile
import tempfile

from . import __version__
from bmccore.config import Config
from bmccore.intake import intake
from bmccore.skills import Pipeline, build_report

_SYM_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.xz")


def _expand_symbol_archive(path, workdir, log):
    """--symbol-table 传 tar 包（rootfs_symbol.tgz 等）时解压并返回目录。

    解压结果按包名缓存在 workdir/symbols/<包名>/ 下（未指定 workdir 时用
    系统临时目录）；marker 文件记录源包 mtime/size，源包更新后自动重解，
    避免用错版本的符号表。目录/单文件输入原样返回。
    """
    if not path or not path.lower().endswith(_SYM_ARCHIVE_SUFFIXES):
        return path
    if not os.path.isfile(path):
        return path        # 不存在的路径交给后续符号技能如实报错

    stem = os.path.basename(path)
    for suf in _SYM_ARCHIVE_SUFFIXES:
        if stem.lower().endswith(suf):
            stem = stem[: -len(suf)]
            break
    cache_root = workdir or os.path.join(tempfile.gettempdir(), "bmccore_symbols")
    target = os.path.join(cache_root, "symbols", stem)
    stamp = {"src": os.path.abspath(path), "mtime": os.path.getmtime(path),
             "size": os.path.getsize(path)}
    marker = os.path.join(target, ".bmccore_src.json")
    if os.path.isdir(target):
        try:
            with open(marker, encoding="utf-8") as f:
                old = json.load(f)
        except Exception:
            old = None
        if old == stamp:
            log("[符号] 复用已解压符号表: %s" % target)
            return target
        shutil.rmtree(target, ignore_errors=True)   # 源包已更新，重解

    os.makedirs(target, exist_ok=True)
    log("[符号] 解压符号表包 %s -> %s" % (os.path.basename(path), target))
    with tarfile.open(path, "r:*") as tf:
        tf.extractall(target)
    with open(marker, "w", encoding="utf-8") as f:
        json.dump(stamp, f)
    return target


def _load_config(args):
    cfg = Config()
    core_hint = getattr(args, "core", None)
    path = getattr(args, "config", None) or cfg.find_config_file(
        os.path.dirname(os.path.abspath(core_hint)) if core_hint else None)
    if path and os.path.isfile(path):
        cfg.update_from_toml(path)
        cfg.config_path = path
    # 就近/显式 toml 未覆盖的键，用技能包 workspace 模板补缺（合并而非整份遮蔽）
    from bmccore.config import _PKG_WORKSPACE_TOML
    if (not cfg.config_path or
            os.path.abspath(cfg.config_path) != os.path.abspath(_PKG_WORKSPACE_TOML)) \
            and os.path.isfile(_PKG_WORKSPACE_TOML):
        cfg.update_from_toml(_PKG_WORKSPACE_TOML)
        cfg.config_extra = _PKG_WORKSPACE_TOML
    cfg.update_from_cli(args)
    return cfg


def _fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%d" % n


def cmd_info(args):
    cfg = _load_config(args)
    core_arg = args.core or cfg.core      # 注意：下方局部变量 core 会被 CoreFile 复用
    if not core_arg:
        print("错误: 未指定 core 文件（位置参数，或 bmccore.toml 的 core=）",
              file=sys.stderr)
        return 2
    workdir = getattr(args, "workdir", None) or cfg.workdir
    if workdir:
        workdir = os.path.abspath(workdir)    # 相对路径按调用时 cwd 锚定，避免后续 cwd 变化
        os.makedirs(workdir, exist_ok=True)
    res = intake(core_arg, keep_temp=args.keep_temp, workroot=workdir)
    try:
        from bmccore.corefile import CoreFile
        from bmccore.modules import group_modules
        core = CoreFile(res.core_path)
        summ = core.summary()

        print("=" * 62)
        print("core 概览")
        print("=" * 62)
        print("  输入        : %s (%s)" % (res.source_name,
                                           _fmt_size(os.path.getsize(core_arg))))
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
    core = args.core or cfg.core
    if not core:
        print("错误: 未指定 core 文件（位置参数，或 bmccore.toml 的 core=）",
              file=sys.stderr)
        return 2
    log("[配置] 加载 %s%s" % (
        cfg.config_path or "无 bmccore.toml",
        "；技能模板补缺: %s" % cfg.config_extra if cfg.config_extra else ""))
    workdir = getattr(args, "workdir", None) or cfg.workdir
    if workdir:
        workdir = os.path.abspath(workdir)    # 相对路径按调用时 cwd 锚定，避免后续 cwd 变化
        os.makedirs(workdir, exist_ok=True)
    if cfg.symbol_table:
        cfg.symbol_table = _expand_symbol_archive(cfg.symbol_table, workdir, log)
    res = intake(core, keep_temp=True, workroot=workdir)
    try:
        pipe = Pipeline(res.core_path, cfg, log=log)
        results = pipe.run()
        rep = build_report(results, cfg, res.meta, res.source_name)

        outdir = cfg.output or os.path.join(os.path.dirname(os.path.abspath(core)),
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

        # 可视化面板（--viz 或 toml 的 viz=true）：服务持续运行，Ctrl-C 结束
        if getattr(args, "viz", False) or cfg.viz:
            from bmccore.visualize import start_visualization
            port = args.viz_port if args.viz_port is not None else cfg.viz_port
            tmo = args.viz_timeout if args.viz_timeout is not None \
                else cfg.viz_timeout
            try:
                server, _url = start_visualization(
                    results["core"],
                    heap_result=results["heap_result"],
                    matches=results["matches"], traces=results["traces"],
                    conclusions=results["conclusions"],
                    cfi_frames=results["cfi_frames"],
                    scan_results=results["scan_results"],
                    source_root=cfg.source_root,
                    snippets=results["snippets"],
                    preferred_port=port, auto_open=True, timeout=tmo)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    print("\n面板已停止")
                finally:
                    server.server_close()
            except RuntimeError as e:
                print("可视化面板启动失败: %s" % e, file=sys.stderr)
        return 0
    finally:
        if not cfg.keep_temp:
            res.cleanup()


def cmd_toolchain(args):
    """工具链探测自检：逐工具说明命中/未命中原因，不分析 core。"""
    from bmccore import toolchain as tc_mod
    cfg = _load_config(args)
    arch = args.arch
    path = args.path
    if not path:
        tc_cfg = (cfg.toolchain or {}).get(arch) or {}
        path = tc_cfg.get("path") or tc_cfg.get("prefix")
        if not path:
            print("未从配置获得路径。自查信息：")
            print("  实际加载的配置文件: %s" % (cfg.config_path or "无（没找到任何 bmccore.toml）"))
            if cfg.toolchain:
                print("  配置中的 [toolchain.*] 节: %s" % sorted(cfg.toolchain.keys()))
                sec = cfg.toolchain.get(arch) or {}
                if sec:
                    print("  [toolchain.%s] 节的键: %s（缺 path/prefix 键？）"
                          % (arch, sorted(sec.keys())))
                else:
                    print("  缺 [toolchain.%s] 节——检查节名拼写（注意是点分层级）" % arch)
            else:
                print("  配置里没有任何 [toolchain.*] 节——"
                      "确认编辑的是上面这个文件，且已解注释 [toolchain.%s] 与 path 行"
                      % arch)
            print("提示：也可直接传目录自检探测逻辑：")
            print("  python3.8 bmccore.py toolchain <工具链bin目录> --arch %s" % arch)
            return 2
    print("== 工具链探测自检（arch=%s）==" % arch)
    for ln in tc_mod.probe_diagnose(path, arch):
        print(ln)

    class _ProbeCfg(object):
        offline = False
        toolchain = {arch: {"path": path}}
    tc = tc_mod.discover(arch, _ProbeCfg())
    print("探测结果: %r" % tc)
    if not any(tc.tools.values()):
        print("提示：可用 gdb/addr2line/objdump 逐项显式指定完整路径，绕过命名探测")
    return 0


def cmd_viz(args):
    """独立启动可视化：内部按 analyze 全流程跑一遍后带面板服务。"""
    args.viz = True
    args.viz_port = args.port if args.port is not None else None
    args.viz_timeout = args.timeout if args.timeout is not None else None
    if not hasattr(args, "debug"):
        args.debug = False
    return cmd_analyze(args)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bmccore",
                                 description="BMC coredump 离线分析工具 (ARM32/ARM64/RISC-V)")
    ap.add_argument("--version", action="version", version="bmccore %s" % __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="bmccore.toml 路径（默认向上查找）")
    common.add_argument("--workdir", metavar="PATH",
                        help="解包/中间文件目录（tar.gz 等压缩包解到该目录下，"
                             "不存在则创建；请用绝对路径，默认系统临时目录）")

    p_info = sub.add_parser("info", parents=[common], help="快速摘要：架构/信号/线程/模块")
    p_info.add_argument("core", nargs="?", default=None,
                        help="core 文件或 tar.gz 包（不填则用 bmccore.toml 的 core=）")
    p_info.add_argument("--keep-temp", action="store_true", help=argparse.SUPPRESS)
    p_info.set_defaults(func=cmd_info)

    p_an = sub.add_parser("analyze", parents=[common], help="全量分析并输出报告")
    p_an.add_argument("core", nargs="?", default=None,
                      help="core 文件或 tar.gz 包（不填则用 bmccore.toml 的 core=）")
    p_an.add_argument("--symbol-table", metavar="PATH",
                      help="符号表文件或目录的绝对路径（编译阶段单独产出的 ELF/"
                           "符号表文件，含 build-id+symtab+DWARF）；也支持 "
                           "rootfs_symbol.tgz 等 tar 包（.tar.gz/.tgz/.tar/.tar.xz），"
                           "自动解压到 --workdir 下缓存复用")
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
                      help="分析完成后启动内存可视化 Web 面板（自动打开浏览器；"
                           "服务持续运行 Ctrl-C 结束）")
    p_an.add_argument("--viz-port", type=int, default=None,
                      help="可视化面板首选端口（被占用时自动+1，默认 toml viz_port/8080）")
    p_an.add_argument("--viz-timeout", type=int, default=None,
                      help="可视化面板超时秒数（0=持续运行，默认 toml viz_timeout/0）")
    p_an.add_argument("--debuginfod-url",
                      help="debuginfod 服务器 URL（远程符号拉取）")
    p_an.set_defaults(func=cmd_analyze)

    p_viz = sub.add_parser("viz", parents=[common],
                           help="分析并启动可视化 Web 面板")
    p_viz.add_argument("core", nargs="?", default=None,
                       help="core 文件或 tar.gz 包（不填则用 bmccore.toml 的 core=）")
    p_viz.add_argument("--port", type=int, default=None, help="首选端口")
    p_viz.add_argument("--timeout", type=int, default=None, help="超时秒（0=持续）")
    p_viz.set_defaults(func=cmd_viz)

    p_tc = sub.add_parser("toolchain", parents=[common],
                          help="交叉工具链探测自检（不分析 core）")
    p_tc.add_argument("path", nargs="?", default=None,
                      help="工具链根目录/bin 目录/以-结尾前缀"
                           "（不填则用 toml [toolchain.<arch>] 的 path）")
    p_tc.add_argument("--arch", default="riscv64",
                      choices=("arm32", "arm64", "riscv64", "riscv32", "x86_64", "i386"),
                      help="目标架构（默认 riscv64）")
    p_tc.set_defaults(func=cmd_toolchain)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

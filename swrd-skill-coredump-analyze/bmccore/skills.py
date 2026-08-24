# -*- coding: utf-8 -*-
"""技能编排：一条命令把解析->配符号->回溯->兜底扫描->堆取证->结论 串完。

每个技能独立、可单独失败（失败记入报告的"技能状态"节，不影响其他技能）。
"""
import os
import time

from . import console as console_mod
from . import heap as heap_mod
from . import lockmon as lockmon_mod
from . import scan as scan_mod
from . import symbols as symbols_mod
from . import toolchain as toolchain_mod
from . import triage as triage_mod
from .backtrace import run_backtrace
from .corefile import CoreFile
from .modules import group_modules
from .report import Report
from .source import SourceIndex

def _throttled(log, every=2.0):
    """进度节流器：每 every 秒最多放行一条（长循环心跳用，避免刷屏）。"""
    state = {"t": 0.0}

    def beat(msg):
        now = time.time()
        if now - state["t"] >= every:
            state["t"] = now
            log(msg)
    return beat


ALL_SKILLS = ("symbols", "backtrace", "scan", "heap", "console", "triage",
              "source", "cfi", "locks", "viz")


class Pipeline(object):
    def __init__(self, core_path, config, log=None):
        self.core_path = core_path
        self.cfg = config
        self.log = log or (lambda msg: None)
        self.status = {}          # {skill: "ok"/"skipped"/"failed: 原因"}

    def _mark(self, skill, st, why=""):
        self.status[skill] = st if not why else "%s: %s" % (st, why)

    def run(self):
        core = CoreFile(self.core_path)
        cfg = self.cfg
        want = set(cfg.skills or ALL_SKILLS)

        # ---- 0. 工具链探测 ----
        arch_name = core.arch.name if core.arch else "arm64"
        tchain = toolchain_mod.discover(arch_name, cfg)
        self.log("[工具链] %s" % tchain)

        # ---- 1. 符号配对 ----
        matches = []
        artifacts = []
        exe_match = None
        if "symbols" in want:
            if cfg.symbol_table:
                self.log("[符号] 读取符号表 %s ..." % cfg.symbol_table)
                artifacts = symbols_mod.load_symbol_tables(
                    cfg.symbol_table, progress=_throttled(self.log))
                modules = group_modules(core)
                matches = symbols_mod.match_modules(modules, artifacts,
                                                    overrides=cfg.modules)
                # --exe 手动指定主程序：覆盖主程序模块的配对结果
                if cfg.exe:
                    art = symbols_mod.read_artifact_info(cfg.exe)
                    exe_mod = next((m for m in modules if m.path == core.exe_path), None)
                    if art and exe_mod:
                        for i, r in enumerate(matches):
                            if r.module is exe_mod:
                                matches[i] = symbols_mod.MatchResult(exe_mod, art, "overridden",
                                                                     "--exe 指定")
                                break
                # 找主程序配对结果
                for r in matches:
                    if r.module.path == core.exe_path or (
                            core.prpsinfo and r.module.name.startswith(core.prpsinfo.get("fname", ""))):
                        exe_match = r
                        break
                n_ok = sum(1 for r in matches if r.status in ("matched", "byname", "overridden"))
                self._mark("symbols", "ok" if matches else "failed",
                           "" if matches else "未解析到模块")
                self.log("[符号] %d/%d 模块配上符号" % (n_ok, len(matches)))
            else:
                self._mark("symbols", "skipped", "未配置 --symbol-table")
        else:
            self._mark("symbols", "skipped", "未启用")

        resolver = symbols_mod.SymbolResolver()

        # ---- 2. GDB 精确回溯 ----
        traces = []
        raw_gdb = ""
        if "backtrace" in want:
            if tchain.has("gdb") and exe_match and exe_match.artifact:
                self.log("[回溯] 运行 %s ..." % tchain.tools["gdb"])
                script = symbols_mod.gdb_symbol_script(exe_match.artifact, matches, core)
                if cfg.sysroot:
                    script.insert(2, "set sysroot %s" % cfg.sysroot)
                crash_tid = core.crash_thread.tid if core.crash_thread else None
                ok, traces, raw_gdb = run_backtrace(
                    tchain.tools["gdb"], self.core_path, script, cfg.max_frames)
                if not ok:
                    self._mark("backtrace", "failed", "gdb 回溯失败（详见 --keep-temp）")
                else:
                    self._mark("backtrace", "ok")
            else:
                self._mark("backtrace", "skipped",
                           "无 gdb 或主程序未配上符号" if not tchain.has("gdb") else "主程序未配上符号")

        # ---- 3. 栈扫描兜底 ----
        scan_results = {}      # tid -> ScanResult
        if "scan" in want:
            # 崩溃线程必须参与扫描（即使 SP 已落在任何转储段之外——
            # 那正是 scan_thread 里"栈溢出或 SP 已被破坏"判定的目标形态，
            # 不能在此被过滤掉）；其余线程按栈是否转储过滤。
            threads = [t for t in core.threads
                       if t is core.crash_thread or core.region_of(t.sp)]
            if cfg.crash_thread_only and core.crash_thread:
                threads = [core.crash_thread]
            # 始终扫描（即使 GDB 回溯完整，也作为交叉验证）
            a2l = None
            if tchain.has("addr2line"):
                def a2l(path, addrs, base):
                    return toolchain_mod.addr2line_batch(
                        path, [a - base for a in addrs], tchain.tools["addr2line"])
            else:
                # 离线（无 addr2line）：纯 Python 直读 DWARF 行号表
                from . import linetab
                _linetab_seen = set()
                _beat_line = _throttled(self.log)

                def a2l(path, addrs, base):
                    if path not in _linetab_seen:
                        _linetab_seen.add(path)
                        self.log("[行号] 首次解析 %s 行号表（大库需数秒，仅此一次）..."
                                 % os.path.basename(path))
                    table = linetab.resolve(path, [a - base for a in addrs],
                                            progress=_beat_line)
                    return {k: ("", v) for k, v in table.items()}
            self.log("[栈扫描] 共 %d 个线程待扫（含行号解析）" % len(threads))
            for t in threads:
                self.log("[栈扫描] tid=%d 开始 ..." % t.tid)
                _t0 = time.time()
                scan_results[t.tid] = scan_mod.scan_thread(
                    core, core.arch, t, matches, resolver,
                    max_depth=cfg.max_scan_depth, addr2line=a2l)
                self.log("[栈扫描] tid=%d 完成，%d 个候选帧（耗时 %.1fs）"
                         % (t.tid, len(scan_results[t.tid].frames),
                            time.time() - _t0))
            n_conf = sum(len(r.confirmed) for r in scan_results.values())
            self._mark("scan", "ok", "%d 个确认帧" % n_conf)

        # ---- 4. 堆取证 ----
        heap_result = None
        if "heap" in want:
            victim = (core.siginfo or {}).get("addr")
            # 崩溃线程寄存器值（剔除 pc/sp 等）：堆头完好时用于定位受害对象
            reg_ptrs = []
            if core.crash_thread and core.arch:
                skip = {core.arch.reg_pc, core.arch.reg_sp, "pstate", "cpsr",
                        "orig_r0", "fpcsr", "fpcr"}
                for k, v in core.crash_thread.regs.items():
                    if k in skip:
                        continue
                    reg_ptrs.append(v)
            self.log("[堆取证] 走查堆区 ...")
            _t0 = time.time()
            heap_result = heap_mod.run_heap_skill(core, core.threads, matches,
                                                  victim_addr=victim,
                                                  reg_ptrs=reg_ptrs,
                                                  progress=_throttled(self.log))
            self.log("[堆取证] 完成（耗时 %.1fs）" % (time.time() - _t0))
            self._mark("heap", "ok" if heap_result.has_heap else "skipped",
                       "" if heap_result.has_heap else "core 中无堆数据")

        # ---- 5. console 日志 ----
        console_hits, console_err = [], None
        if "console" in want:
            if cfg.console_log and os.path.isfile(cfg.console_log):
                console_hits, console_err = console_mod.extract_key_lines(cfg.console_log)
                self._mark("console", "ok" if not console_err else "failed",
                           console_err or "")
            else:
                self._mark("console", "skipped", "未提供 --console-log")

        # ---- 6. triage 结论 ----
        conclusions = []
        if "triage" in want:
            crash_scan = scan_results.get(core.crash_thread.tid) if core.crash_thread else None
            conclusions = triage_mod.triage(core, matches, console_hits or None,
                                            crash_scan, heap_result)
            self._mark("triage", "ok")

        # ---- 7. 源码联动 ----
        src_index = SourceIndex(cfg.source_root) if cfg.source_root else None
        snippets = []
        if "source" in want and src_index:
            # 收集崩溃线程回溯里的 file:line
            wanted = []
            for tr in traces:
                if core.crash_thread and tr.lwp == core.crash_thread.tid:
                    for fr in tr.frames[:8]:
                        if fr.loc and ":" in fr.loc:
                            f, _, ln = fr.loc.rpartition(":")
                            if ln.isdigit():
                                wanted.append((f, int(ln)))
            crash_scan = scan_results.get(core.crash_thread.tid) if core.crash_thread else None
            if crash_scan:
                for fr in crash_scan.frames[:12]:
                    if fr.loc and ":" in fr.loc:
                        f, _, ln = fr.loc.rpartition(":")
                        if ln.isdigit():
                            wanted.append((f, int(ln)))
            seen = set()
            for f, ln in wanted:
                key = (f, ln)
                if key in seen:
                    continue
                seen.add(key)
                snip = src_index.snippet(f, ln)
                if snip:
                    snippets.append((f, ln, snip[0], snip[1]))
                if len(snippets) >= 5:
                    break
            self._mark("source", "ok" if snippets else "skipped",
                       "" if snippets else "回溯无行号或源码树中未定位到文件")
        else:
            self._mark("source", "skipped", "未启用或未配置 --source-root")

        # ---- 8. CFI 离线回溯（精确展开，无 gdb 时的最佳兜底） ----
        cfi_frames = None
        if "cfi" in want and core.crash_thread:
            from .ehframe import cfi_unwind
            exe_artifact = exe_match.artifact if exe_match else None
            if exe_artifact:
                arch_name = core.arch.name if core.arch else "x86_64"
                self.log("[CFI] .eh_frame 展开崩溃线程 ...")
                _t0 = time.time()
                cfi_frames = cfi_unwind(core, core.crash_thread,
                                        arch_name, exe_artifact.path,
                                        cfg.max_frames)
                self.log("[CFI] 完成，%d 帧（耗时 %.1fs）"
                         % (len(cfi_frames or []), time.time() - _t0))
            if cfi_frames:
                self._mark("cfi", "ok", "%d 帧（.eh_frame 精确展开）" % len(cfi_frames))
            else:
                self._mark("cfi", "skipped", "无 .eh_frame 或展开失败")

        # ---- 9. 线程锁关联分析 ----
        lock_result = None
        if "locks" in want and len(core.threads) > 1:
            self.log("[锁分析] %d 个线程 ..." % len(core.threads))
            _t0 = time.time()
            lock_result = lockmon_mod.analyze_locks(core, core.threads,
                                                    progress=_throttled(self.log))
            self.log("[锁分析] 完成，%d 个活跃锁 / %d 条等待关系（耗时 %.1fs）"
                     % (len(lock_result.locks), len(lock_result.wait_graph),
                        time.time() - _t0))
            if lock_result.has_deadlock:
                self._mark("locks", "ok", "⚠ 检测到死锁！")
            elif lock_result.wait_graph:
                self._mark("locks", "ok", "%d 条等待关系" % len(lock_result.wait_graph))
            elif lock_result.locks:
                self._mark("locks", "ok", "%d 个活跃锁（无等待/死锁）" % len(lock_result.locks))
            else:
                self._mark("locks", "skipped", "未检测到锁活动")
        else:
            self._mark("locks", "skipped", "单线程或未启用")

        return {
            "core": core,
            "matches": matches,
            "traces": traces,
            "scan_results": scan_results,
            "heap_result": heap_result,
            "console_hits": console_hits,
            "conclusions": conclusions,
            "snippets": snippets,
            "status": dict(self.status),
            "raw_gdb": raw_gdb,
            "toolchain": tchain,
            "cfi_frames": cfi_frames,
            "lock_result": lock_result,
        }


# ---------------------------------------------------------------------------
# 报告组装
# ---------------------------------------------------------------------------

def build_report(results, cfg, intake_meta=None, source_name=None):
    core = results["core"]
    summ = core.summary()
    crash = core.crash_thread

    rep = Report("BMC Coredump 分析报告")
    rep.meta = {"source": source_name or core.path, "arch": summ["arch"]}

    # 概览
    pairs = [("core 文件", source_name or core.path),
             ("架构", "%s (ELF%d)" % (summ["arch"], summ["elfclass"])),
             ("崩溃进程", "%s (pid=%s)" % (summ["fname"] or "?",
                                          intake_meta.get("pid") if intake_meta else crash.tid)),
             ("命令行", summ["psargs"]),
             ("崩溃信号", summ["signal"]),
             ("出错地址", "0x%x" % summ["fault_addr"] if summ["fault_addr"] is not None else "-"),
             ("线程数", summ["nthreads"]),
             ("加载模块数", summ["nmodules"])]
    if intake_meta and intake_meta.get("stamp"):
        pairs.insert(1, ("dump 时间戳/计数", intake_meta["stamp"]))
    rep.add_kv_table("概览", pairs)

    # 技能状态
    rep.add_kv_table("技能状态", sorted(results["status"].items()))

    # 崩溃线程寄存器
    if crash:
        regs = ["| 寄存器 | 值 |", "|---|---|"]
        keys = [core.arch.reg_pc, core.arch.reg_sp, core.arch.reg_lr, core.arch.reg_fp]
        for k in keys:
            if k in crash.regs:
                regs.append("| %s | 0x%x |" % (k, crash.regs[k]))
        for k in ("x0", "a0", "r0"):
            if k in crash.regs:
                regs.append("| %s | 0x%x |" % (k, crash.regs[k]))
        rep.add("崩溃线程寄存器 (tid=%d)" % crash.tid, regs)

    # 模块配对
    if results["matches"]:
        lines = ["| 模块 | 设备路径 | 配对结果 | 产物 | 说明 |", "|---|---|---|---|---|"]
        for r in results["matches"]:
            lines.append("| %s | %s | %s | %s | %s |" % (
                r.module.name, r.module.path, r.status,
                r.artifact.path if r.artifact else "-", r.note or "-"))
        rep.add("符号配对 (%d 模块)" % len(results["matches"]), lines)

    # GDB 回溯
    for tr in results["traces"]:
        is_crash = crash and tr.lwp == crash.tid
        title = "线程 LWP %d 回溯%s" % (tr.lwp, "（崩溃线程）" if is_crash else "")
        lines = ["```"]
        for fr in tr.frames:
            lines.append("#%-2d 0x%-12x %s%s" % (
                fr.level, fr.addr or 0, fr.func,
                (" @ %s" % fr.loc) if fr.loc else ""))
        if not tr.frames:
            lines.append("(无帧)")
        lines.append("```")
        if tr.unknown_count:
            lines.append("> 注意：该线程 %d 帧 address 显示 ??（符号缺失或栈损坏）" % tr.unknown_count)
        rep.add(title, lines)

    # 栈扫描
    for tid, sr in results["scan_results"].items():
        is_crash = crash and tid == crash.tid
        if not sr.frames and not sr.overflow:
            continue
        title = "线程 %d 栈扫描%s" % (tid, "（崩溃线程）" if is_crash else "")
        lines = []
        if sr.overflow:
            lines.append("**%s**" % sr.overflow)
            lines.append("")
        lines += ["| 栈偏移 | 值 | 置信度 | 函数/位置 | 判定 |", "|---|---|---|---|---|"]
        for f in sr.frames:
            loc = f.loc or (f.func or "")
            off_txt = ("PC(现场)" if f.stack_off == -2 else
                       "LR/ra寄存器" if f.stack_off == -1 else
                       "SP+0x%x" % f.stack_off)
            lines.append("| %s | 0x%x | %s | %s | %s |" % (
                off_txt, f.value, f.confidence, loc, f.why))
        for note in sr.notes:
            lines.append("")
            lines.append("> %s" % note)
        lines.append("")
        lines.append("> 置信度说明：\"确认\"= 代码区间命中 + 前一条指令经判定是 call；"
                     "\"未验证\"= 仅代码区间命中（指令字节不可得），仅供参考。")
        rep.add(title, lines)

    # 堆取证
    hr = results["heap_result"]
    if hr:
        lines = []
        for note in hr.notes:
            lines.append("- %s" % note)
        for desc, chunks in hr.regions:
            inuse = sum(1 for c in chunks if c.inuse)
            lines.append("- 堆区 %s：%d 个 chunk（%d in-use）" % (desc, len(chunks), inuse))
        for c in hr.corruptions:
            lines.append("")
            lines.append("**chunk 头损坏：偏移 +0x%x（size=0x%x，%s）**" % (
                c.offset, c.size_value, c.reason))
            if c.prev:
                lines.append("- 前一 chunk：偏移 +0x%x，大小 0x%x，%s ——"
                             "重点怀疑它越界写穿下一个 chunk 头" % (
                                 c.prev.offset, c.prev.size,
                                 "in-use" if c.prev.inuse else "free"))
        if hr.references:
            lines.append("")
            lines.append("指向受害区的引用（谁拿着指向这里的指针）：")
            lines += ["- %s 0x%x -> 0x%x" % (w, a, v) for w, a, v in hr.references[:16]]
        for fp in hr.fingerprints:
            lines.append("")
            lines.append("内容指纹：%s" % fp.desc)
        rep.add("堆取证 (glibc)", lines if lines else ["core 中无堆数据"])

    # console 证据
    if results["console_hits"]:
        lines = ["```"]
        lines += [("%5d| %s" % (ln, txt)) for ln, txt in results["console_hits"][:60]]
        lines.append("```")
        rep.add("console 日志关键行", lines)

    # 源码片段
    for f, ln, real, body in results["snippets"]:
        lines = ["`%s:%d`（源码树: %s）" % (f, ln, real), "", "```c"]
        for n, txt, hit in body:
            lines.append(("%s %5d %s" % (">" if hit else " ", n, txt)))
        lines.append("```")
        rep.add("源码片段 %s:%d" % (f, ln), lines)

    # 结论
    concl = ["| 可信度 | 结论 | 依据 |", "|---|---|---|"]
    for c in results["conclusions"]:
        concl.append("| %s | %s | %s |" % (c.confidence, c.text, c.evidence))
    rep.add("定位结论", concl, level=2)

    return rep

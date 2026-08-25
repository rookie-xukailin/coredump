# -*- coding: utf-8 -*-
"""技能编排：一条命令把解析->配符号->回溯->兜底扫描->堆取证->结论 串完。

每个技能独立、可单独失败（失败记入报告的"技能状态"节，不影响其他技能）。

流程顺序（v5 深度版）：
  symbols → backtrace → deepdive(gdb bt full/反汇编/栈内存) → scan →
  heap → console → locks → dieinfo → [decoder/framevars/regs/stackdump/
  heaptyping 深度分析块] → triage(吃全部证据) → source → vartrace(吃运行时值)
  → cfi → 证据包(evidence pack)
"""
import os
import re
import time

from . import console as console_mod
from . import decode as decode_mod
from . import framevars as framevars_mod
from . import heap as heap_mod
from . import heaptyping as heaptyping_mod
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

def _md_inline(text):
    """vartrace 事件 detail 中的 <code> HTML 标签转 markdown 反引号。"""
    if not text:
        return ""
    return re.sub(r"</?code>", "`", text)


def _throttled(log, every=2.0):
    """进度节流器：每 every 秒最多放行一条（长循环心跳用，避免刷屏）。"""
    state = {"t": 0.0}

    def beat(msg):
        now = time.time()
        if now - state["t"] >= every:
            state["t"] = now
            log(msg)
    return beat


ALL_SKILLS = ("symbols", "backtrace", "deepdive", "scan", "heap", "console",
              "locks", "dieinfo", "framevars", "regs", "stackdump",
              "heaptyping", "inattr", "objrebuild", "triage", "source",
              "vartrace", "cfi", "viz")


def _serialize_locks(lock_result, addr_names):
    """lock_result → JSON 可序列化 dict（证据包用）。"""
    if lock_result is None:
        return None
    def _n(a):
        return addr_names.get(a)
    return {
        "locks": [{"addr": lk.addr, "named": _n(lk.addr),
                   "owner_tid": lk.owner_tid, "state": lk.lock_state,
                   "kind": lk.kind} for lk in lock_result.locks],
        "wait_graph": [{"waiter": e.waiter_tid, "lock": e.lock_addr,
                        "named": _n(e.lock_addr),
                        "holder": e.holder_tid}
                       for e in lock_result.wait_graph],
        "deadlocks": lock_result.deadlocks and [
            [{"waiter": e.waiter_tid, "lock": e.lock_addr,
              "named": _n(e.lock_addr), "holder": e.holder_tid}
             for e in cycle] for cycle in lock_result.deadlocks] or [],
        "futex_waits": {str(tid): bp for tid, bp in
                        getattr(lock_result, "futex_waits", {}).items()},
        "notes": lock_result.notes,
    }


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

        # ---- 2. gdb 深度取证（先跑：成功时回溯直接复用，省一个 gdb 进程）----
        traces = []
        raw_gdb = ""
        script = None
        deepdive = None
        _raw_dir = cfg.workdir or cfg.output or os.path.dirname(self.core_path)
        if ("backtrace" in want or "deepdive" in want) and \
                tchain.has("gdb") and exe_match and exe_match.artifact:
            script = symbols_mod.gdb_symbol_script(exe_match.artifact, matches, core)
            if cfg.sysroot:
                script.insert(2, "set sysroot %s" % cfg.sysroot)
        if "deepdive" in want and script:
            from .deepdive import run_deepdive
            self.log("[deepdive] gdb 深度取证（bt full/寄存器/反汇编/调用点）...")
            _t0 = time.time()
            fault = (core.siginfo or {}).get("addr")
            deepdive = run_deepdive(
                tchain.tools["gdb"], self.core_path, script,
                core.crash_thread.tid if core.crash_thread else 0,
                fault_addr=fault, max_frames=min(cfg.max_frames or 50, 15),
                log=self.log,
                timeout=getattr(cfg, "gdb_timeout", 0) or 400,
                raw_dir=_raw_dir)
            n_fv = sum(len(fr.get("locals", []))
                       for tr in deepdive.get("frames_full", [])
                       for fr in tr["frames"])
            if deepdive.get("frames_full"):
                self._mark("deepdive", "ok",
                           "bt full %d 线程/%d 个变量值 + 反汇编%d行"
                           "（全函数%d行/调用点%d行）+ 表达式%d"
                           % (len(deepdive["frames_full"]), n_fv,
                              len(deepdive.get("disasm", [])),
                              len(deepdive.get("disasm_func", [])),
                              len(deepdive.get("callsite", [])),
                              len(deepdive.get("expr_evals", []))))
            else:
                self._mark("deepdive", "failed", "gdb 深度取证未取到数据")
            self.log("[deepdive] 完成（耗时 %.1fs）" % (time.time() - _t0))
        elif "deepdive" in want:
            self._mark("deepdive", "skipped", "无 gdb 或主程序未配上符号")

        # ---- 2.5 GDB 精确回溯（deepdive 已有 bt full 时转换复用，不再起进程）----
        if "backtrace" in want:
            if tchain.has("gdb") and exe_match and exe_match.artifact:
                if deepdive and deepdive.get("frames_full"):
                    from .backtrace import Frame, ThreadTrace
                    for tr in deepdive["frames_full"]:
                        tt = ThreadTrace(0, tr["lwp"])
                        for fr in tr["frames"]:
                            tt.frames.append(Frame(
                                fr["level"], fr.get("addr"),
                                fr.get("func") or "??", fr.get("loc")))
                        traces.append(tt)
                    self._mark("backtrace", "ok",
                               "复用 deepdive bt full（省一个 gdb 进程，原始输出"
                               "见 %s）" % os.path.join(_raw_dir, "gdb_raw_deepdive1.log"))
                else:
                    self.log("[回溯] 运行 %s ..." % tchain.tools["gdb"])
                    ok, traces, raw_gdb = run_backtrace(
                        tchain.tools["gdb"], self.core_path, script, cfg.max_frames,
                        timeout=getattr(cfg, "gdb_timeout", 0) or None,
                        raw_path=os.path.join(_raw_dir, "gdb_raw_backtrace.log"))
                    if not ok:
                        self._mark("backtrace", "failed", "gdb 回溯失败（原始输出见 gdb_raw_backtrace.log）")
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

        # ---- 6. 线程锁关联分析（提前：triage/证据包都要用）----
        lock_result = None
        if "locks" in want and len(core.threads) > 1:
            self.log("[锁分析] %d 个线程 ..." % len(core.threads))
            _t0 = time.time()
            lock_result = lockmon_mod.analyze_locks(
                core, core.threads, progress=_throttled(self.log),
                full_scan=getattr(cfg, "lock_scan_full", False))
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

        # ---- 7. 语义命名（dieinfo）：锁/futex/出错地址 → DWARF 变量名 ----
        addr_names = {}
        if "dieinfo" in want:
            from . import dieinfo as dieinfo_mod
            cand = set()
            _vic = (core.siginfo or {}).get("addr")
            if _vic:
                cand.add(_vic)
            if lock_result:
                for lk in lock_result.locks:
                    cand.add(lk.addr)
                for e in lock_result.wait_graph:
                    cand.add(e.lock_addr)
                for bp in lock_result.futex_waits.values():
                    if bp.get("sys") == "futex" and bp.get("uaddr"):
                        cand.add(bp["uaddr"])
            for a in cand:
                mr = next((m for m in matches
                           if m.artifact and m.module.contains(a)), None)
                if mr is None:
                    continue
                nm = dieinfo_mod.name_address(mr.artifact.path, a)
                if nm:
                    addr_names[a] = nm
            self._mark("dieinfo", "ok" if addr_names else "skipped",
                       "%d 个地址命名" % len(addr_names) if addr_names
                       else "无产物含 DWARF 或候选地址未命中变量")
        else:
            self._mark("dieinfo", "skipped", "未启用")

        # ==============================================================
        # 深度分析块：值语义解码 / 帧变量 / 全寄存器解码 / 栈内存 / 堆对象
        # ==============================================================
        decoder = decode_mod.Decoder(core, matches,
                                     heap_result=heap_result,
                                     addr_names=addr_names)
        exe_artifact_path = (exe_match.artifact.path
                             if exe_match and exe_match.artifact else None)

        # ---- 7.5 帧变量恢复 ----
        framevars_res = None
        if "framevars" in want and core.crash_thread:
            if deepdive and deepdive.get("frames_full"):
                framevars_res = framevars_mod.from_gdb(
                    deepdive, core.crash_thread.tid, decoder)
            if framevars_res is None:
                # 离线兜底：崩溃帧函数的 DIE 参数表 + 入口寄存器
                top = None
                for tr in traces:
                    if tr.lwp == core.crash_thread.tid and tr.frames:
                        fr = tr.frames[0]
                        top = {"func": fr.func, "loc": fr.loc}
                        break
                if top is None:
                    sr = scan_results.get(core.crash_thread.tid)
                    if sr and sr.frames:
                        fr = sr.frames[0]
                        top = {"func": fr.func or "", "loc": fr.loc}
                framevars_res = framevars_mod.from_offline(
                    core, matches, exe_artifact_path, top, decoder)
            if framevars_res:
                n = sum(len(f["vars"]) for f in framevars_res["frames"])
                self._mark("framevars", "ok",
                           "%d 帧 / %d 个变量（%s）"
                           % (len(framevars_res["frames"]), n,
                              framevars_res["source"]))
            else:
                self._mark("framevars", "skipped", "无 gdb bt full 且 DIE 参数表未命中")
        else:
            self._mark("framevars", "skipped", "未启用或无崩溃线程")

        # ---- 7.6 全寄存器语义解码 ----
        regs_deep = []
        if "regs" in want and core.crash_thread:
            params = None
            if framevars_res and exe_artifact_path and framevars_res["frames"]:
                from . import dieinfo as dieinfo_mod
                fn = framevars_res["frames"][0]["func"]
                plist = dieinfo_mod.params_of(exe_artifact_path, fn)
                if core.arch:
                    params = [(nm, dieinfo_mod.dwarf_reg_name(core.arch.name, regno))
                              for nm, regno in plist if regno is not None]
            regs_deep = decode_mod.decode_regs(core, matches, decoder=decoder,
                                               heap_result=heap_result,
                                               addr_names=addr_names,
                                               params=params)
            self._mark("regs", "ok", "%d 个寄存器解码" % len(regs_deep))
        else:
            self._mark("regs", "skipped", "未启用或无崩溃线程")

        # ---- 7.7 崩溃现场栈内存解码 ----
        stackdump = []
        if "stackdump" in want and core.crash_thread:
            stackdump = decode_mod.decode_stack_words(core, decoder, words=64)
            self._mark("stackdump", "ok", "SP 起 %d 字逐字解码" % len(stackdump))
        else:
            self._mark("stackdump", "skipped", "未启用或无崩溃线程")

        # ---- 7.8 堆对象还原（字段级解码 + 持有链）----
        heap_typing = []
        holders = []
        if "heaptyping" in want and heap_result and heap_result.has_heap:
            art_paths = [m.artifact.path for m in matches if m.artifact]
            prev_set = set(id(x.prev) for x in heap_result.corruptions if x.prev)
            victim_c = getattr(heap_result, "victim_chunk", None)
            victim_r = getattr(heap_result, "victim_region", None)
            for desc, chunks in heap_result.regions:
                try:
                    start = int(desc.split("-")[0], 16)
                except Exception:
                    continue
                for c in chunks:
                    is_suspect = id(c) in prev_set          # 越界嫌疑前块
                    is_victim = victim_c is c               # 受害对象
                    if not (is_suspect or is_victim):
                        continue
                    obj = heaptyping_mod.decode_chunk(core, decoder, art_paths,
                                                      start, c)
                    if obj:
                        obj["chunk"] = "%s+0x%x" % (desc, c.offset)
                        obj["inuse"] = c.inuse
                        obj["role"] = ("受害对象" if is_victim else "越界嫌疑前块")
                        heap_typing.append(obj)
            # 持有链：指向受害区的引用
            if heap_result.corruptions:
                try:
                    start = int(heap_result.region_desc.split("-")[0], 16)
                    vstart = start + heap_result.corruptions[0].offset
                    holders = heaptyping_mod.holder_chain(
                        core, decoder, heap_result, vstart - 64,
                        vstart + 256)
                except Exception:
                    holders = []
            self._mark("heaptyping", "ok" if heap_typing else "skipped",
                       "%d 个对象还原 / %d 条持有链" % (len(heap_typing),
                                                        len(holders))
                       if heap_typing else "无尺寸匹配的结构体")
        else:
            self._mark("heaptyping", "skipped", "无堆数据或未启用")

        # ---- 7.9 崩溃指令操作数级归因（指令 → 基址寄存器 → 语义名）----
        inattr_res = None
        if deepdive and deepdive.get("disasm") and core.crash_thread and core.arch:
            from . import inattr as inattr_mod
            base_name = None
            field_name = None
            pre = inattr_mod.parse_operand(
                core.arch.name,
                inattr_mod.find_pc_line(deepdive["disasm"]) or "")
            if pre:
                _base, _disp = pre
                _bv = (core.crash_thread.regs or {}).get(_base)
                base_name = addr_names.get(_bv) if isinstance(_bv, int) else None
                if not base_name and deepdive.get("frames_full"):
                    _tr0 = next((t for t in deepdive["frames_full"]
                                 if t["lwp"] == core.crash_thread.tid), None)
                    if _tr0 and _tr0["frames"]:
                        for nm, val in _tr0["frames"][0]["args"]:
                            try:
                                if int(str(val), 0) == _bv:
                                    base_name = "参数 %s" % nm
                                    break
                            except (ValueError, TypeError):
                                pass
                # 字段名：受害对象（heaptyping）里偏移 == 指令偏移的成员
                for obj in heap_typing:
                    if obj.get("role") == "受害对象" and obj.get("type"):
                        for fd in obj.get("fields", []):
                            if fd.get("offset") == _disp:
                                field_name = "%s.%s" % (obj["type"],
                                                        fd.get("name"))
                                break
                    if field_name:
                        break
            inattr_res = inattr_mod.attribute_fault(
                core.arch.name, deepdive["disasm"],
                (core.siginfo or {}).get("addr"),
                core.crash_thread.regs or {},
                base_name=base_name, field_name=field_name)
            self._mark("inattr", "ok" if inattr_res else "skipped",
                       "指令级归因" if inattr_res else "无 PC 反汇编行")
        else:
            self._mark("inattr", "skipped", "无 gdb 反汇编")

        # ---- 7.10 gdb 类型重建（ptype / p *(struct*)addr）----
        objrebuild = None
        if deepdive and script and tchain.has("gdb"):
            cands = []
            for obj in heap_typing:
                _s = (obj.get("type") or "").replace("struct", "").strip()
                if _s and _s not in cands:
                    cands.append(_s)
            _base_reg = _base_val = None
            if inattr_res and inattr_res.get("parsed"):
                _base_reg = inattr_res.get("base_reg")
                _base_val = inattr_res.get("base_val")
            _vic_addr = None
            _vc = getattr(heap_result, "victim_chunk", None) if heap_result else None
            _vr = getattr(heap_result, "victim_region", None) if heap_result else None
            if _vc is not None and _vr is not None:
                _vic_addr = _vr.vaddr + _vc.offset
            if cands and deepdive.get("gdb_no") is not None:
                from .deepdive import run_objrebuild
                objrebuild = run_objrebuild(
                    tchain.tools["gdb"], self.core_path, script,
                    deepdive.get("gdb_no"), cands,
                    base_reg=_base_reg, base_val=_base_val,
                    victim_addr=_vic_addr, log=self.log,
                    timeout=getattr(cfg, "gdb_timeout", 0) or 300,
                    raw_dir=_raw_dir)
                self._mark("objrebuild",
                           "ok" if (objrebuild.get("ptypes")
                                    or objrebuild.get("derefs")) else "skipped",
                           "ptype %d / 解引用 %d" % (
                               len(objrebuild.get("ptypes") or []),
                               len(objrebuild.get("derefs") or [])))
            else:
                self._mark("objrebuild", "skipped",
                           "无候选结构体" if not cands else "无崩溃线程 gdb 上下文")
        else:
            self._mark("objrebuild", "skipped", "无 gdb")

        # ---- 8. triage 结论（吃全部证据）----
        conclusions = []
        if "triage" in want:
            crash_scan = scan_results.get(core.crash_thread.tid) if core.crash_thread else None
            conclusions = triage_mod.triage(core, matches, console_hits or None,
                                            crash_scan, heap_result,
                                            deepdive=deepdive,
                                            lock_result=lock_result,
                                            framevars=framevars_res,
                                            regs_deep=regs_deep,
                                            addr_names=addr_names)
            self._mark("triage", "ok")

        # ---- 9. 源码联动 ----
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

        # ---- 10. 变量生命周期（vartrace）：崩溃行指针的 声明→赋值→释放→崩溃 轨迹
        var_events = None
        var_root = None
        if "vartrace" in want and snippets and cfg.source_root:
            from . import vartrace as vartrace_mod
            f0, ln0 = snippets[0][0], snippets[0][1]
            line_txt = ""
            for _n, _txt, _hit in snippets[0][3]:
                if _hit:
                    line_txt = _txt
                    break
            if line_txt:
                # 运行时值（来自帧变量恢复）：崩溃行被解引用指针的实际取值
                rt_val = None
                if framevars_res:
                    rt_val = _crash_ptr_runtime(framevars_res, line_txt)
                var_events, var_root = vartrace_mod.trace_variable(
                    cfg.source_root, f0, ln0, line_txt,
                    fault_addr=(core.siginfo or {}).get("addr"),
                    runtime_value=rt_val,
                    runtime_sem=(decoder.decode(rt_val)
                                 if isinstance(rt_val, int) else None))
                self._mark("vartrace", "ok" if var_events else "skipped",
                           "" if var_events else (var_root or "未提取到指针变量"))
            else:
                self._mark("vartrace", "skipped", "崩溃行源码文本不可得")
        else:
            self._mark("vartrace", "skipped",
                       "无源码联动（未配 source_root 或回溯无行号）")

        # ---- 11. CFI 离线回溯（精确展开，无 gdb 时的最佳兜底）----
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

        # ---- 12. 证据包（evidence pack）：全量证据汇总，LLM/面板共用 ----
        # 读码清单：纯坐标导航（哪个文件哪一段+为什么要看）——
        # 业务理解由 LLM 通读源码完成，引擎不做任何语义分析
        reading_list = []
        _rl_seen = set()

        def _rl_add(f, ln, why, span=15):
            base = os.path.basename(f) if f else ""
            if not base:
                return
            for e in reading_list:        # 同文件 3 行内视为同一处，去重
                if e["file"] == base and abs(e["line"] - ln) <= 3:
                    return
            reading_list.append({"file": base, "line": ln,
                                 "span": [max(1, ln - span), ln + span],
                                 "why": why})

        if core.crash_thread:
            for tr in traces:
                if tr.lwp != core.crash_thread.tid:
                    continue
                for fr in tr.frames[:8]:
                    if fr.loc and ":" in fr.loc:
                        f, _, ln = fr.loc.rpartition(":")
                        if ln.isdigit():
                            _rl_add(f, int(ln), "崩溃链 #%d %s（通读整个函数）"
                                    % (fr.level, fr.func.split("(")[0]))
            sr0 = scan_results.get(core.crash_thread.tid)
            if sr0:
                for fr in sr0.frames[:8]:
                    if fr.loc and ":" in fr.loc:
                        f, _, ln = fr.loc.rpartition(":")
                        if ln.isdigit():
                            _rl_add(f, int(ln), "崩溃链（栈扫描）%s" % (
                                fr.func or ""))
            for tr in traces:              # 其他线程的业务函数（跳过 ??/libc 帧）
                if tr.lwp == core.crash_thread.tid:
                    continue
                for fr in tr.frames[:4]:
                    if fr.loc and ":" in fr.loc and "?" not in (fr.func or ""):
                        f, _, ln = fr.loc.rpartition(":")
                        if ln.isdigit():
                            _rl_add(f, int(ln), "线程 %d 的业务函数 %s"
                                    % (tr.lwp, fr.func.split("(")[0]))
                        break
        # 崩溃文件整读条目（LLM 五问的落点）
        if reading_list:
            reading_list.append({
                "file": reading_list[0]["file"], "line": 0, "span": None,
                "why": "崩溃所在文件——通读全文：函数入口/调用者/共享数据/"
                       "指针生命周期（配合 SKILL 4a-2 五问）"
                + ("；重点全局变量：%s" % "、".join(sorted(set(addr_names.values()))[:4])
                   if addr_names else "")})

        evidence = _build_evidence(core, {
            "deepdive": deepdive,
            "framevars": framevars_res,
            "regs_deep": regs_deep,
            "stackdump": stackdump,
            "heap_typing": heap_typing,
            "holders": holders,
            "locks": _serialize_locks(lock_result, addr_names),
            "addr_names": addr_names,
            "inattr": inattr_res,
            "objrebuild": objrebuild,
            "console_hits": console_hits,
            "conclusions": [{"confidence": c.confidence, "text": c.text,
                             "evidence": c.evidence}
                            for c in conclusions],
            "source_refs": [{"file": f, "line": ln, "real": real}
                            for f, ln, real, _b in snippets],
            "source_reading_list": reading_list[:12],
        })

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
            "var_events": var_events,
            "var_root_cause": var_root,
            "addr_names": addr_names,
            "inattr": inattr_res,
            "objrebuild": objrebuild,
            "exe_artifact_path": exe_artifact_path,
            "deepdive": deepdive,
            "framevars": framevars_res,
            "regs_deep": regs_deep,
            "stackdump": stackdump,
            "heap_typing": heap_typing,
            "holders": holders,
            "evidence": evidence,
        }


def _crash_ptr_runtime(framevars_res, crash_line):
    """从帧变量恢复结果里找崩溃行被解引用指针的运行时值（int）。"""
    import re as _re
    # 崩溃行里的标识符（如 ctx->seq / *slot / buf[idx]）
    ids = set(_re.findall(r"[A-Za-z_][A-Za-z0-9_]*", crash_line or ""))
    stop = {"volatile", "char", "int", "long", "void", "static", "return",
            "if", "for", "while", "struct", "const", "unsigned", "signed"}
    ids -= stop
    if not framevars_res:
        return None
    for fr in framevars_res.get("frames", [])[:1]:
        for var in fr.get("vars", []):
            if var["name"] in ids:
                try:
                    s = str(var.get("value", "")).strip()
                    s = s.split()[0]
                    return int(s, 0)
                except (ValueError, IndexError):
                    return None
    return None


def _build_evidence(core, parts):
    """证据包汇总：分区 + 来源/可信度标注，全部 JSON 可序列化。"""
    deepdive = parts.get("deepdive") or {}
    fault = (core.siginfo or {}).get("addr")
    sig = core.threads[0].cursig if core.threads else 0
    # gdb 与 NT_PRSTATUS 寄存器一致性校验（两个引擎互证）
    gdb_vs = None
    if deepdive.get("registers") and core.crash_thread:
        gregs = deepdive["registers"].get(core.crash_thread.tid) or []
        gmap = {}
        for rn, v, _raw in gregs:
            gmap[rn] = v
        same = diff = 0
        for rn, v in (core.crash_thread.regs or {}).items():
            if rn in gmap and isinstance(v, int) and isinstance(gmap[rn], int):
                if gmap[rn] == v:
                    same += 1
                else:
                    diff += 1
        if same or diff:
            gdb_vs = "一致 %d 个 / 不一致 %d 个%s" % (
                same, diff, "（以 NT_PRSTATUS 为准）" if diff else "")
    return {
        "meta": {
            "说明": "全量证据包：gdb+Python 双引擎取证，供 LLM 根因推断与面板展示",
            "可信度约定": "确认=DWARF/gdb 精确证据；启发式=Python 推断（标注于各条目）",
            "gdb寄存器交叉校验": gdb_vs,
        },
        "summary": {
            "signal": sig,
            "fault_addr": fault,
            "arch": core.arch.name if core.arch else None,
            "process": (core.prpsinfo or {}).get("fname"),
            "nthreads": len(core.threads),
            "crash_tid": core.crash_thread.tid if core.crash_thread else None,
        },
        "registers": [
            {"reg": rn, "value": v, "sem": sem,
             "source": "NT_PRSTATUS+语义解码"}
            for rn, v, sem in (parts.get("regs_deep") or [])],
        "frame_vars": parts.get("framevars"),
        "stack_dump": [
            {"sp_off": off, "addr": a, "value": v, "sem": sem,
             "source": "core 内存读取+语义解码"}
            for off, a, v, sem in (parts.get("stackdump") or [])],
        "heap_objects": parts.get("heap_typing"),
        "holders": parts.get("holders"),
        "locks": parts.get("locks"),
        "addr_names": {("0x%x" % k): v
                       for k, v in (parts.get("addr_names") or {}).items()},
        "disasm": deepdive.get("disasm"),
        "disasm_func": deepdive.get("disasm_func"),
        "callsite": deepdive.get("callsite"),
        "gdb_stack_hex": deepdive.get("stack_hex"),
        "fault_mem": deepdive.get("fault_mem"),
        "inattr": parts.get("inattr"),
        "objrebuild": ({"ptypes": p, "derefs": d}
                       if parts.get("objrebuild") else None),
        "expr_evals": [{"expr": e, "output": out}
                       for e, out in (deepdive.get("expr_evals") or [])],
        "gdb_frames_full": deepdive.get("frames_full"),
        "console": [{"line": ln, "text": txt}
                    for ln, txt in (parts.get("console_hits") or [])[:40]],
        "conclusions": parts.get("conclusions"),
        "source_refs": parts.get("source_refs"),
        "source_reading_list": parts.get("source_reading_list"),
    }


# ---------------------------------------------------------------------------
# 报告组装
# ---------------------------------------------------------------------------

def _scene_rows(core, results):
    """每线程现场行（表格与叙事共用）：tid/崩溃/顶部帧/栈转储/持锁/等锁。"""
    crash = core.crash_thread
    lock_result = results.get("lock_result")
    held_by = {}      # tid -> [lock_addr]
    wait_by = {}      # tid -> [(lock_addr, holder_tid)]
    if lock_result:
        for lk in lock_result.locks:
            held_by.setdefault(lk.owner_tid, []).append(lk.addr)
        for e in lock_result.wait_graph:
            wait_by.setdefault(e.waiter_tid, []).append((e.lock_addr, e.holder_tid))
    tops = {}         # tid -> 顶部帧描述（新→旧）
    for tr in results["traces"]:
        funcs = [fr.func for fr in tr.frames[:3] if fr and fr.func]
        if funcs:
            tops[tr.lwp] = " ← ".join(funcs)
    for tid, sr in results["scan_results"].items():
        if tid in tops:
            continue
        names = []
        for f in sr.frames[:3]:
            nm = f.func or f.loc
            if nm and nm not in names:
                names.append(nm)
        if names:
            tops[tid] = " ← ".join(names)
    rows = []
    futex_waits = {}
    if lock_result:
        futex_waits = getattr(lock_result, "futex_waits", None) or {}
    addr_names = results.get("addr_names") or {}

    def _n(a):
        return addr_names.get(a)

    for t in core.threads:
        lk_txt = []
        for a in held_by.get(t.tid, [])[:3]:
            nm = _n(a)
            lk_txt.append("持锁 0x%x%s" % (a, "(=%s)" % nm if nm else ""))
        for a, h in wait_by.get(t.tid, [])[:3]:
            nm = _n(a)
            lk_txt.append("等锁 0x%x%s(持有者T%d)" % (a, "(=%s)" % nm if nm else "", h))
        blk = ""
        bp = futex_waits.get(t.tid)
        if bp:
            if bp.get("sys") == "futex" and bp.get("uaddr"):
                nm = _n(bp["uaddr"])
                blk = "futex@0x%x%s" % (bp["uaddr"], "(=%s)" % nm if nm else "")
            else:
                blk = "syscall %s" % bp.get("sys", "?")
        rows.append({
            "tid": t.tid,
            "is_crash": bool(crash and t.tid == crash.tid),
            "top": tops.get(t.tid) or "",
            "stack_dumped": bool(core.region_of(t.sp)),
            "locks": "；".join(lk_txt),
            "block": blk,
        })
    return rows, held_by, wait_by


def build_report(results, cfg, intake_meta=None, source_name=None):
    core = results["core"]
    summ = core.summary()
    crash = core.crash_thread

    rep = Report("BMC Coredump 分析报告")
    rep.meta = {"source": source_name or core.path, "arch": summ["arch"]}

    # 概览
    fault = summ["fault_addr"]
    fault_txt = "0x%x" % fault if fault is not None else "-"
    _fa = (results.get("addr_names") or {}).get(fault)
    if _fa:
        fault_txt += " (= %s)" % _fa
    pairs = [("core 文件", source_name or core.path),
             ("架构", "%s (ELF%d)" % (summ["arch"], summ["elfclass"])),
             ("崩溃进程", "%s (pid=%s)" % (summ["fname"] or "?",
                                          intake_meta.get("pid") if intake_meta else crash.tid)),
             ("命令行", summ["psargs"]),
             ("崩溃信号", summ["signal"]),
             ("出错地址", fault_txt),
             ("线程数", summ["nthreads"]),
             ("加载模块数", summ["nmodules"])]
    if intake_meta and intake_meta.get("stamp"):
        pairs.insert(1, ("dump 时间戳/计数", intake_meta["stamp"]))
    rep.add_kv_table("概览", pairs)

    # 技能状态
    rep.add_kv_table("技能状态", sorted(results["status"].items()))

    # 崩溃现场反汇编（deepdive：PC 邻域 + 全函数 + 调用点现场）
    dd = results.get("deepdive") or {}
    if dd.get("disasm"):
        lines = ["```"]
        lines += dd["disasm"]
        lines.append("```")
        if dd.get("disasm_func"):
            lines.append("")
            lines.append("**崩溃函数完整反汇编**（看参数如何装进寄存器、"
                         "对象从哪来；全文在证据包 disasm_func）——"
                         "前 %d 行：" % min(60, len(dd["disasm_func"])))
            lines.append("```")
            lines += dd["disasm_func"][:60]
            lines.append("```")
        if dd.get("callsite"):
            lines.append("")
            lines.append("**上层调用点现场**（frame 1 的 PC 前 10 条——"
                         "看调用发生时参数装载）：")
            lines.append("```")
            lines += dd["callsite"]
            lines.append("```")
        lines.append("> 崩溃指令前后的反汇编——出错的访存指令、它的基址/偏移寄存器，"
                     "在这里一目了然。")
        rep.add("崩溃现场反汇编", lines)

    # 崩溃指令操作数级归因（指令 → 基址寄存器 → 语义名 → 字段）
    ia = results.get("inattr")
    if ia:
        from .inattr import describe as _ia_desc
        _d = _ia_desc(ia)
        if _d:
            lines = ["**%s**" % _d, ""]
            if ia.get("base_name"):
                lines.append("- 基址语义名：%s" % ia["base_name"])
            if ia.get("field_name"):
                lines.append("- 偏移对应字段：%s" % ia["field_name"])
            lines.append("- 验证：基址 %s=0x%x + 0x%x = 0x%x%s"
                         % (ia.get("base_reg"), ia.get("base_val") or 0,
                            ia.get("disp") or 0, ia.get("computed") or 0,
                            " == 出错地址 ✓" if ia.get("verified")
                            else " ≠ 出错地址（疑似）"))
            lines.append("")
            lines.append("> 来源：gdb 指令解析 + NT_PRSTATUS 寄存器交叉"
                         "（指令语法未匹配时会如实标注）。")
            rep.add("崩溃指令归因 (指令级)", lines)

    # 对象还原（gdb 类型重建：ptype / p *(struct*)addr）
    ob = results.get("objrebuild")
    if ob and (ob.get("ptypes") or ob.get("derefs")):
        lines = []
        for expr, out in ob.get("ptypes") or []:
            lines.append("**%s**" % expr)
            lines.append("```")
            lines += out
            lines.append("```")
        for expr, out in ob.get("derefs") or []:
            lines.append("**%s**（运行时值按 DWARF 类型重建）" % expr)
            lines.append("```")
            lines += out
            lines.append("```")
        lines.append("> 置信度：确认（gdb+DWARF）——比 heaptyping 的尺寸"
                     "启发式匹配强一档，可消歧同尺寸结构体。")
        rep.add("对象还原 (gdb 类型重建)", lines)

    # 出错地址附近内存（gdb 直读）
    if dd.get("fault_mem"):
        lines = ["```"]
        lines += dd["fault_mem"]
        lines.append("```")
        lines.append("> gdb 直读出错地址周边 8 个字（不可读时为 gdb 报错原文，"
                     "如实保留）。")
        rep.add("出错地址附近内存 (gdb)", lines)

    # 崩溃帧变量（gdb bt full 或 DIE 参数表）
    fv = results.get("framevars")
    if fv:
        lines = []
        if fv.get("confidence"):
            lines.append("> 来源：%s（%s）" % (fv["source"], fv["confidence"]))
        if fv.get("note"):
            lines.append("> %s" % fv["note"])
        for fr in fv.get("frames", []):
            if not fr["vars"]:
                continue
            lines.append("")
            lines.append("**#%d %s**%s" % (
                fr["level"], fr["func"],
                " @ %s" % fr["loc"] if fr.get("loc") else ""))
            lines.append("| 变量 | 类型 | 值 | 语义 |")
            lines.append("|---|---|---|---|")
            for v in fr["vars"]:
                lines.append("| %s | %s | `%s` | %s |" % (
                    v["name"], v.get("kind", ""), v.get("value", ""),
                    v.get("sem", "")))
        if any(l.startswith(("**", "|")) for l in lines):
            rep.add("崩溃帧变量 (framevars)", lines)

    # 崩溃线程寄存器（全量语义解码版）
    regs_deep = results.get("regs_deep") or []
    if regs_deep:
        lines = ["| 寄存器 | 值 | 语义 |", "|---|---|---|"]
        for rn, v, sem in regs_deep:
            lines.append("| %s | 0x%x | %s |" % (rn, v, sem))
        rep.add("崩溃线程寄存器 (tid=%s，全量解码)" % (
            crash.tid if crash else "?"), lines)

    # 崩溃现场栈内存（SP 起逐字解码）
    sd = results.get("stackdump") or []
    if sd:
        lines = ["| SP偏移 | 地址 | 值 | 语义 |", "|---|---|---|---|"]
        for off, a, v, sem in sd[:40]:
            lines.append("| +0x%03x | 0x%x | 0x%x | %s |" % (off, a, v, sem))
        if len(sd) > 40:
            lines.append("| ... | ... | ... | （共 %d 字，仅列前 40） |" % len(sd))
        lines.append("")
        lines.append("> 栈上每个字是什么：返回地址/局部变量/参数传递区/"
                     "指向全局或堆的指针，逐字标注。")
        rep.add("崩溃现场栈内存 (SP 起)", lines)

    # 线程现场还原（案发现场总览：每线程一行——在干什么/持什么/等什么/阻塞在哪）
    rows, _held_by, _wait_by = _scene_rows(core, results)
    if rows:
        lines = ["| tid | 状态 | 阻塞点(疑似) | 顶部帧（新→旧） | 锁关系 |",
                 "|---|---|---|---|---|"]
        for r in rows:
            state = "💥崩溃" if r["is_crash"] else ""
            top = r["top"] or ("（栈未转储）" if not r["stack_dumped"]
                               else "（无符号化帧）")
            lines.append("| T%d | %s | %s | %s | %s |" % (
                r["tid"], state, r["block"] or "-", top, r["locks"] or "-"))
        lines.append("")
        lines.append("> 阻塞点来自寄存器解码（dump 时刻最后一次系统调用，故标"
                     "疑似）：futex@0x… 即该线程在等此地址的锁/条件变量。"
                     "崩溃线程≠肇事线程——重点看持锁/等锁/阻塞地址的交叉与"
                     "共享数据的访问路径。")
        rep.add("线程现场还原 (%d 线程)" % len(rows), lines)

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
                _exe_p = results.get("exe_artifact_path")
                if _exe_p:
                    from . import dieinfo as dieinfo_mod
                    _st = dieinfo_mod.struct_by_size(_exe_p, c.prev.size)
                    if _st:
                        _members = ", ".join("0x%x:%s" % (o, m[0])
                                             for o, m in sorted(_st[1].items())[:6])
                        lines.append("- 前块尺寸 0x%x 与 **struct %s** 匹配"
                                     "（DIE 证据；成员偏移：%s）"
                                     % (c.prev.size, _st[0], _members or "无"))
        if hr.references:
            lines.append("")
            lines.append("指向受害区的引用（谁拿着指向这里的指针）：")
            lines += ["- %s 0x%x -> 0x%x" % (w, a, v) for w, a, v in hr.references[:16]]
        for fp in hr.fingerprints:
            lines.append("")
            lines.append("内容指纹：%s" % fp.desc)
        rep.add("堆取证 (glibc)", lines if lines else ["core 中无堆数据"])

    # 堆对象还原（字段级结构化解码 + 持有链）
    heap_typing = results.get("heap_typing") or []
    holders = results.get("holders") or []
    if heap_typing or holders:
        lines = []
        for obj in heap_typing:
            lines.append("**对象还原：%s（%s，%s）**" % (
                obj.get("type", "?"), obj.get("chunk", "?"),
                "in-use" if obj.get("inuse") else "free"))
            lines.append("| 偏移 | 成员 | 类型 | 运行时值 | 语义 |")
            lines.append("|---|---|---|---|---|")
            for f in obj.get("fields", []):
                lines.append("| +0x%x | %s | %s | `%s` | %s |" % (
                    f["offset"], f["name"], f["type"], f["value"], f["sem"]))
            lines.append("> 证据：%s" % obj.get("evidence", "DIE"))
            lines.append("")
        for h in holders:
            lines.append("- 持有链：%s" % h)
        rep.add("堆对象还原 (heaptyping)", lines)

    # gdb 表达式求值
    if dd.get("expr_evals"):
        lines = ["```"]
        for expr, out in dd["expr_evals"]:
            lines.append("(gdb) p %s" % expr)
            lines += out[:12]
            lines.append("")
        lines.append("```")
        rep.add("gdb 表达式求值", lines)

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

    # 变量生命周期（崩溃指针的静态溯源轨迹 + 运行时值）
    var_events = results.get("var_events")
    if var_events:
        lines = []
        root_cause = results.get("var_root_cause")
        if root_cause:
            lines.append("**指向根因：%s**" % _md_inline(root_cause))
            lines.append("")
        for ev in var_events:
            lines.append("- %s **%s**（%s:%s）%s" % (
                ev.get("icon", ""), ev.get("title", ""),
                ev.get("file", "?"), ev.get("line", "?"),
                _md_inline(ev.get("detail", ""))))
            code = (ev.get("code") or "").strip()
            if code:
                lines.append("")
                lines.append("  `%s`" % code)
        lines.append("")
        lines.append("> 生命周期由源码静态追溯（声明/初始化/置空/释放的所有位置），"
                     "是叙事的骨架素材——与运行时栈/堆证据交叉验证后采信。")
        rep.add("变量生命周期 (vartrace)", lines)

    # 结论（指令级归因验证通过时置顶——最硬的一条证据）
    concl = ["| 可信度 | 结论 | 依据 |", "|---|---|---|"]
    _ia = results.get("inattr")
    if _ia and _ia.get("parsed"):
        from .inattr import describe as _ia_d
        _t = _ia_d(_ia)
        if _t:
            concl.append("| %s | %s | 崩溃指令归因（gdb 指令解析+寄存器交叉） |"
                         % ("确认" if _ia.get("verified") else "疑似", _t))
    for c in results["conclusions"]:
        concl.append("| %s | %s | %s |" % (c.confidence, c.text, c.evidence))
    rep.add("定位结论", concl, level=2)

    return rep

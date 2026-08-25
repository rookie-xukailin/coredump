# -*- coding: utf-8 -*-
"""deepdive 技能：gdb 深度取证——把 core 里的值级信息一次挖全。

与 backtrace（只要函数名链）互补，本技能两遍 gdb 取证：

第一遍（与崩溃现场无关的全量信息）：
  - thread apply all info registers   每线程全寄存器（含浮点标记）
  - thread apply all bt full N        每帧的参数值+局部变量值（DWARF 精确）

第二遍（选中崩溃线程后的现场细节）：
  - x/16i $pc-8                       崩溃指令前后的反汇编（看操作数来源）
  - x/48gx $sp                        栈内存原始字
  - x/8gx <fault_addr>                出错地址周边内存（可读时）
  - p *ptr（自动表达式求值）           bt full 里崩溃帧的指针型变量解引用
                                       （拿结构体字段的运行时值）

所有解析结果结构化为 JSON 可序列化的 dict（证据包的 gdb 分区）。
"""
import os
import re

from . import toolchain as tc

_THREAD_HEAD = re.compile(r"^Thread (\d+) \(LWP (\d+)\)")
_FRAME_FULL = re.compile(r"^#(\d+)\s+(?:0x([0-9a-f]+) in )?(.+)$")
_FUNC_AT = re.compile(r"^(.*?)\s+at\s+(.+?):(\d+)$")
_VAR_LINE = re.compile(r"^(\s+)([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+|\[[^\]]*\])*)\s=\s(.*)$")
_HEXROW = re.compile(r"^0x([0-9a-f]+):\s*(.*)$")
_PTRVAL = re.compile(r"0x[0-9a-f]{5,}")


def _split_sections(out):
    """按 =====NAME===== 标记切段；返回 {name: text}。"""
    secs = {}
    parts = re.split(r"=====([A-Z0-9_]+)=====", out)
    # parts: [pre, NAME1, body1, NAME2, body2, ...]
    for i in range(1, len(parts) - 1, 2):
        secs[parts[i]] = parts[i + 1]
    return secs


def parse_regs(text):
    """`thread apply all info registers` 输出 → {lwp: [(reg, value, 原始行)]}。"""
    out = {}
    cur = None
    for line in text.splitlines():
        m = _THREAD_HEAD.match(line.strip())
        if m:
            cur = int(m.group(2))
            out[cur] = []
            continue
        if cur is None or not line.strip():
            continue
        # 形如 "x0             0x0	0" / "cpsr 0x60000000 ..."
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0][0].isalpha():
            name = parts[0]
            try:
                val = int(line.split()[1], 0)
            except Exception:
                val = None
            out[cur].append((name, val, line.rstrip()))
    return out


def parse_bt_full(text):
    """`thread apply all bt full` 输出 → [{lwp, frames:[{...}]}]。"""
    traces = []
    cur_trace = None
    cur_frame = None
    for line in text.splitlines():
        rline = line.rstrip()
        m = _THREAD_HEAD.match(rline.strip())
        if m:
            cur_trace = {"lwp": int(m.group(2)), "frames": []}
            traces.append(cur_trace)
            cur_frame = None
            continue
        m = _FRAME_FULL.match(rline)
        if m and cur_trace is not None:
            level = int(m.group(1))
            rest = m.group(3)
            func, loc = rest, None
            ma = _FUNC_AT.match(rest)
            if ma:
                loc = "%s:%s" % (ma.group(2), ma.group(3))
                func = ma.group(1)
            try:
                addr = int(m.group(2), 16) if m.group(2) else None
            except ValueError:
                addr = None
            cur_frame = {"level": level, "addr": addr, "func": func.strip(),
                         "loc": loc, "args": [], "locals": []}
            cur_trace["frames"].append(cur_frame)
            continue
        mv = _VAR_LINE.match(rline)
        if mv and cur_frame is not None:
            # 归属判定：bt full 的参数跟在帧头行内（已由帧头正则吞掉），
            # 缩进行都是局部变量；帧头括号里的参数单独解析
            cur_frame["locals"].append((mv.group(2), mv.group(3).strip()))
    # 帧头里的参数（func (a=0x1, b=0x2)）解析
    for tr in traces:
        for fr in tr["frames"]:
            fr["args"] = _parse_frame_args(fr["func"])
            fr["func"] = _strip_args(fr["func"])
    return traces


def _parse_frame_args(func_text):
    """'mq_event_process (ctx=0x0, x=2)' → [('ctx','0x0'),('x','2')]。"""
    i = func_text.find("(")
    if i < 0:
        return []
    inner = func_text[i + 1: func_text.rfind(")")] if ")" in func_text[i:] else ""
    args = []
    depth = 0
    cur = []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        args.append("".join(cur))
    out = []
    for a in args:
        if "=" not in a:
            continue
        name, _, val = a.partition("=")
        name = name.strip()
        # 去掉 "struct foo *" 之类的类型前缀，取最后一个标识符
        name = re.split(r"[ *]", name.strip())[-1] if name else ""
        if name:
            out.append((name, val.strip()))
    return out


def _strip_args(func_text):
    i = func_text.find("(")
    return func_text[:i].strip() if i >= 0 else func_text.strip()


def parse_hexdump(text):
    """`x/Ngx` 输出 → [(行地址, [word 值])]。"""
    rows = []
    for line in text.splitlines():
        m = _HEXROW.match(line.strip())
        if not m:
            continue
        addr = int(m.group(1), 16)
        vals = []
        for tok in m.group(2).split():
            try:
                vals.append(int(tok, 16))
            except ValueError:
                break
        if vals:
            rows.append((addr, vals))
    return rows


def pick_exprs(bt_full_traces, crash_lwp, max_exprs=6):
    """从崩溃帧(0/1)的参数与局部变量里挑指针型变量 → ['*ctx', '*msg']。"""
    tr = next((t for t in bt_full_traces if t["lwp"] == crash_lwp), None)
    if tr is None:
        return []
    cand = []
    for fr in tr["frames"][:2]:
        for name, val in fr["args"] + fr["locals"]:
            if _PTRVAL.search(val or ""):
                cand.append((fr["level"], name))
    out = []
    seen = set()
    for _lvl, name in cand:
        key = name.split(".")[0].split("[")[0]
        if not key or key in seen:
            continue
        seen.add(key)
        out.append("*%s" % key)
        if len(out) >= max_exprs:
            break
    return out


def run_deepdive(gdb_path, core_path, symbol_script, crash_lwp,
                 fault_addr=None, max_frames=15, log=None,
                 timeout=400, raw_dir=None):
    """两遍 gdb 深度取证；返回 dict（全部 JSON 可序列化）。

    raw_dir 给定时每个 gdb 进程的原始输出落盘 raw_dir/gdb_raw_*.log
    （审计"哪些结论来自 gdb"的第一手材料）。
    """
    result = {"source": "gdb", "registers": {}, "frames_full": [],
              "disasm": [], "disasm_func": [], "callsite": [],
              "stack_hex": [], "fault_mem": None,
              "expr_evals": [], "gdb_no": None}
    base = list(symbol_script) + ["core %s" % core_path]

    def _raw(tag):
        return (raw_dir + os.sep + "gdb_raw_%s.log" % tag) if raw_dir else None

    # ---- 第一遍：全寄存器 + bt full ----
    script1 = base + [
        "echo \\n=====REGS=====\\n",
        "thread apply all info registers",
        "echo \\n=====BTFULL=====\\n",
        "thread apply all bt full %d" % max_frames,
    ]
    ok, out = tc.gdb_batch(gdb_path, script1, timeout=timeout,
                           raw_path=_raw("deepdive1"))
    secs = _split_sections(out)
    if "REGS" in secs:
        result["registers"] = parse_regs(secs["REGS"])
    if "BTFULL" in secs:
        result["frames_full"] = parse_bt_full(secs["BTFULL"])
    if log:
        log("[deepdive] 一遍完成：寄存器 %d 线程 / bt full %d 线程"
            % (len(result["registers"]), len(result["frames_full"])))

    # ---- 找崩溃线程的 gdb 线程号 ----
    gdb_no = None
    m = re.search(r"^Thread (\d+) \(LWP %d\)" % crash_lwp, out, re.M)
    if m:
        gdb_no = int(m.group(1))
    if gdb_no is None:
        # bt full 的线程顺序与 info threads 一致，用序号兜底
        for i, tr in enumerate(result["frames_full"]):
            if tr["lwp"] == crash_lwp:
                gdb_no = i
                break
    result["gdb_no"] = gdb_no

    # ---- 第二遍：崩溃线程现场 ----
    if gdb_no is not None:
        crash_fn = _crash_func_name(result["frames_full"], crash_lwp)
        script2 = base + [
            "thread %d" % gdb_no,
            "echo \\n=====DISASM=====\\n",
            "x/16i $pc-8",
        ]
        if crash_fn:
            script2 += [
                "echo \\n=====FUNCDISASM=====\\n",
                "disassemble %s" % crash_fn,
            ]
        script2 += [
            "echo \\n=====CALLSITE=====\\n",
            "frame 1",
            "x/10i $pc-24",
            "frame 0",
            "echo \\n=====STACK=====\\n",
            "x/48gx $sp",
        ]
        if fault_addr:
            script2 += [
                "echo \\n=====FAULTMEM=====\\n",
                "x/8gx (void*)%d" % fault_addr,
            ]
        for i, e in enumerate(pick_exprs(result["frames_full"], crash_lwp)):
            script2 += [
                "echo \\n=====E%d=====\\n" % i,
                "p %s" % e,
            ]
        ok2, out2 = tc.gdb_batch(gdb_path, script2, timeout=timeout,
                                 raw_path=_raw("deepdive2"))
        secs2 = _split_sections(out2)
        if "DISASM" in secs2:
            result["disasm"] = [l.rstrip() for l in secs2["DISASM"].splitlines()
                                if l.strip()]
        if "FUNCDISASM" in secs2:
            result["disasm_func"] = [l.rstrip()
                                     for l in secs2["FUNCDISASM"].splitlines()
                                     if l.strip()][:200]     # 大函数截断
        if "CALLSITE" in secs2:
            result["callsite"] = [l.rstrip()
                                  for l in secs2["CALLSITE"].splitlines()
                                  if l.strip()]
        if "STACK" in secs2:
            result["stack_hex"] = parse_hexdump(secs2["STACK"])
        if "FAULTMEM" in secs2:
            result["fault_mem"] = [l.rstrip() for l in secs2["FAULTMEM"].splitlines()
                                   if l.strip()]
        exprs = pick_exprs(result["frames_full"], crash_lwp)
        for i, e in enumerate(exprs):
            body = secs2.get("E%d" % i)
            if body:
                result["expr_evals"].append(
                    (e, [l.rstrip() for l in body.splitlines() if l.strip()]))
        if log:
            log("[deepdive] 二遍完成：反汇编 %d 行（全函数 %d 行/调用点 %d 行）"
                "/ 栈 %d 行 / 表达式 %d 个"
                % (len(result["disasm"]), len(result["disasm_func"]),
                   len(result["callsite"]), len(result["stack_hex"]),
                   len(result["expr_evals"])))
    return result


def _crash_func_name(frames_full, crash_lwp):
    """崩溃线程帧 0 的函数名（disassemble 用；剥掉模板/参数尾巴）。"""
    tr = next((t for t in frames_full if t["lwp"] == crash_lwp), None)
    if not tr or not tr["frames"]:
        return None
    fn = (tr["frames"][0].get("func") or "").strip()
    # 帧头参数已在 parse_bt_full 剥离；再防一手括号尾巴与空格
    fn = fn.split("(")[0].strip()
    return fn or None


def run_objrebuild(gdb_path, core_path, symbol_script, gdb_no,
                   candidates, base_reg=None, base_val=None,
                   victim_addr=None, log=None, timeout=300, raw_dir=None):
    """第三遍（对象重建）：用 gdb 的 DWARF 类型系统在运行时地址上重建对象。

    candidates: 候选结构体名列表（来自 heaptyping 尺寸匹配/DIE）；
    base_reg/base_val: 崩溃指令的基址寄存器与值（inattr 归因产物）；
    victim_addr: 堆取证受害对象地址。返回 dict（JSON 可序列化）。
    """
    out = {"ptypes": [], "derefs": []}
    if gdb_no is None or not candidates:
        return out
    script = list(symbol_script) + [
        "core %s" % core_path,
        "thread %d" % gdb_no,
    ]
    tags = []
    for i, s in enumerate(candidates[:3]):
        script += ["echo \\n=====PT%d=====\\n" % i, "ptype struct %s" % s]
        tags.append(("PT%d" % i, "ptype struct %s" % s))
    derefs = []
    if victim_addr is not None:
        for s in candidates[:2]:
            e = "p *(struct %s *)%d" % (s, victim_addr)
            script.append("echo \\n=====DR%d=====\\n" % len(derefs))
            script.append(e)
            derefs.append(("DR%d" % len(derefs), e))
    elif base_reg and isinstance(base_val, int):
        for s in candidates[:2]:
            e = "p *(struct %s *)$%s" % (s, base_reg)
            script.append("echo \\n=====DR%d=====\\n" % len(derefs))
            script.append(e)
            derefs.append(("DR%d" % len(derefs), e))
    if not tags and not derefs:
        return out
    raw = (raw_dir + os.sep + "gdb_raw_objrebuild.log") if raw_dir else None
    ok, outp = tc.gdb_batch(gdb_path, script, timeout=timeout, raw_path=raw)
    secs = _split_sections(outp)
    for tag, expr in tags:
        body = secs.get(tag)
        if body:
            out["ptypes"].append(
                (expr, [l.rstrip() for l in body.splitlines() if l.strip()][:80]))
    for tag, expr in derefs:
        body = secs.get(tag)
        if body:
            out["derefs"].append(
                (expr, [l.rstrip() for l in body.splitlines() if l.strip()][:60]))
    if log:
        log("[objrebuild] gdb 类型重建：ptype %d 个 / 解引用 %d 个"
            % (len(out["ptypes"]), len(out["derefs"])))
    return out

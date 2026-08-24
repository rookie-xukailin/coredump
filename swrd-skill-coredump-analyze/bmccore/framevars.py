# -*- coding: utf-8 -*-
"""帧变量恢复：崩溃调用链每一帧的参数值/局部变量值。

两条路径：
- gdb 路径：deepdive 的 bt full 已带每帧参数与局部变量（DWARF 精确），
  本模块把崩溃线程的帧转成统一结构并给每个值做语义解码
- 离线路径（无 gdb）：dieinfo 的 DW_TAG_formal_parameter + DW_OP_regN
  把崩溃帧函数的参数与入口寄存器精确配对（仍是 DWARF 证据），
  局部变量离线不可恢复（需要 location 表达式求值器），如实标注
"""
from . import dieinfo as dieinfo_mod


def _int_of(raw):
    """gdb 值文本 → int（0x… / 十进制 / 负数）；解析不了返回 None。"""
    if raw is None:
        return None
    s = str(raw).strip()
    if s.startswith("$"):
        return None
    for cut in (" (", " <", " ["):
        i = s.find(cut)
        if i > 0:
            s = s[:i]
    s = s.split()[0] if s.split() else s
    try:
        return int(s, 0)
    except ValueError:
        pass
    try:
        return int(s)
    except ValueError:
        return None


def from_gdb(deepdive_result, crash_lwp, decoder, max_frames=8):
    """gdb 路径：deepdive frames_full → 统一帧变量结构。"""
    tr = next((t for t in deepdive_result.get("frames_full", [])
               if t["lwp"] == crash_lwp), None)
    if tr is None:
        return None
    frames = []
    for fr in tr["frames"][:max_frames]:
        if fr["func"].startswith("??"):
            continue
        vars_ = []
        for name, val in fr.get("args", []):
            v = _int_of(val)
            vars_.append({"name": name, "kind": "参数", "value": val,
                          "sem": (decoder.decode(v) if v is not None
                                  and 0 <= v < (1 << 63) else _short(val)),
                          "origin": "gdb bt full"})
        for name, val in fr.get("locals", [])[:24]:
            v = _int_of(val)
            vars_.append({"name": name, "kind": "局部", "value": val,
                          "sem": (decoder.decode(v) if v is not None
                                  and 0 <= v < (1 << 63) else _short(val)),
                          "origin": "gdb bt full"})
        frames.append({"level": fr["level"], "func": fr["func"],
                       "loc": fr.get("loc"), "vars": vars_})
    return {"source": "gdb bt full", "confidence": "确认（DWARF 精确）",
            "frames": frames}


def _short(val):
    s = str(val)
    return s if len(s) <= 60 else s[:57] + "..."


def from_offline(core, matches, exe_artifact_path, top_frame, decoder):
    """离线路径：崩溃帧参数 = dieinfo 参数表(带 DW_OP_regN) ∩ 入口寄存器。

    top_frame: {"func": 名字, "loc": "f:ln"}（来自 gdb bt 或栈扫描首帧）
    局部变量离线不可恢复，如实标注。
    """
    if not exe_artifact_path or not top_frame or not top_frame.get("func"):
        return None
    func = top_frame["func"].split("(")[0].strip()
    arch_name = core.arch.name if core.arch else ""
    params = dieinfo_mod.params_of(exe_artifact_path, func)
    if not params:
        return None
    t = core.crash_thread
    if t is None:
        return None
    vars_ = []
    for pname, regno in params:
        entry = {"name": pname, "kind": "参数"}
        if regno is not None:
            reg = dieinfo_mod.dwarf_reg_name(arch_name, regno)
            if reg and reg in t.regs:
                v = t.regs[reg]
                entry.update({"value": "0x%x" % v,
                              "sem": decoder.decode(v),
                              "origin": "DWARF DW_OP_reg%d → %s" % (regno, reg)})
                vars_.append(entry)
                continue
        entry.update({"value": "（寄存器映射不可得）", "sem": "-",
                      "origin": "DWARF 参数表"})
        vars_.append(entry)
    if not vars_:
        return None
    return {
        "source": "python（DIE 参数表 + 寄存器）",
        "confidence": "确认（参数）；局部变量需 gdb bt full",
        "frames": [{"level": 0, "func": func, "loc": top_frame.get("loc"),
                    "vars": vars_}],
        "note": "离线模式仅恢复入口参数；局部变量需要 gdb（bt full）。"
    }

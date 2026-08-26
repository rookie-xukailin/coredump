# -*- coding: utf-8 -*-
"""崩溃指令操作数级归因：回答"崩溃到底在解引用谁"。

输入是 deepdive 已取回的 x/i 反汇编文本 + NT_PRSTATUS 寄存器 + 命名上下文
（DIE 参数名 / 全局变量名 / 结构体字段名），产出指令级结论：

    崩溃指令 lw a5,0x18(a0)：解引用 <参数 dev> 的字段 +0x18
    （struct fan_ctrl.set_pwm）——基址寄存器 a0=0x7f42..，0x7f42..+0x18
    == 出错地址，寄存器交叉验证一致。

四架构 load/store 语法正则；解析失败返回 None 或 parsed=False（如实降级，
不阻塞流水线）。
"""
import re

# 各架构访存指令的操作数正则（组序见 parse_operand）
_ARCH_LOAD = {
    # riscv: lw/ld/lh/lb/lhu/lbu/... rd, imm(rs1)   （imm 可负）
    "riscv64": re.compile(
        r"\b(?:l[wdbh]u?|c\.l[wds]p?)\s+\w+,\s*(-?0x[0-9a-f]+|-?\d+)\((\w+)\)"),
    "riscv32": re.compile(
        r"\b(?:l[wdbh]u?|c\.l[wds]p?)\s+\w+,\s*(-?0x[0-9a-f]+|-?\d+)\((\w+)\)"),
    # arm64/arm32: ldr[bhdq]s? xd, [xn, #imm]   （#imm 可缺省=0）
    "arm64": re.compile(
        r"\bldr(?:bt?[bhdq]?)?\s+\w+,\s*\[(\w+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]"),
    "arm32": re.compile(
        r"\bldr(?:bt?[bhdq]?)?\s+\w+,\s*\[(\w+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]"),
    # x86 att 语法（gdb 默认）: mov 0x18(%rcx),%rax   （disp 可缺省）
    "x86_64": re.compile(
        r"\bmov[a-z]*\s+(?:(?:qword|dword|word|byte) ptr\s+)?"
        r"(-?0x[0-9a-f]+)?\((%\w+)\),"),
    "i386": re.compile(
        r"\bmov[a-z]*\s+(?:(?:qword|dword|word|byte) ptr\s+)?"
        r"(-?0x[0-9a-f]+)?\((%\w+)\),"),
}


def find_pc_line(disasm_lines):
    """x/i 输出里带 => 标记的当前 PC 行；无标记时返回 None。"""
    for ln in disasm_lines or []:
        if "=>" in ln:
            return ln
    return None


def parse_operand(arch_name, insn_text):
    """从指令文本解出 (基址寄存器, 偏移)；不匹配返回 None。

    x86 att 语法的寄存器带 % 前缀，返回时去掉以与 NT_PRSTATUS 键对齐。
    """
    pat = _ARCH_LOAD.get(arch_name)
    if not pat or not insn_text:
        return None
    m = pat.search(insn_text)
    if not m:
        return None
    groups = m.groups()
    try:
        if arch_name in ("x86_64", "i386"):
            disp_s, base = groups[0], (groups[1] or "").lstrip("%")
        elif arch_name in ("arm64", "arm32"):
            base, disp_s = groups[0], groups[1]
        else:                                   # riscv: (disp, base)
            disp_s, base = groups[0], groups[1]
    except IndexError:
        return None
    if not base:
        return None
    disp = 0
    if disp_s:
        try:
            disp = int(disp_s, 0)
        except ValueError:
            return None
    return base, disp


def attribute_fault(arch_name, disasm_lines, fault_addr, regs,
                    base_name=None, field_name=None):
    """归因主入口。

    disasm_lines: deepdive 的 x/16i 输出行；regs: 崩溃线程 {寄存器名: 值}；
    base_name: 基址寄存器的语义名（DIE 参数名/全局变量名，可空）；
    field_name: 偏移对应的字段名（struct.member，可空）。
    返回 dict（JSON 可序列化）或 None（无 PC 行）。
    """
    pc_line = find_pc_line(disasm_lines)
    if pc_line is None:
        return None
    parsed = parse_operand(arch_name, pc_line)
    if parsed is None:
        return {"parsed": False, "insn": pc_line.strip(),
                "note": "指令语法未匹配（非访存指令或语法差异）"}
    base, disp = parsed
    base_val = regs.get(base)
    computed = (base_val + disp) if isinstance(base_val, int) else None
    verified = (computed is not None and fault_addr is not None
                and computed == fault_addr)
    return {
        "parsed": True,
        "insn": pc_line.strip(),
        "base_reg": base,
        "base_val": base_val,
        "disp": disp,
        "computed": computed,
        "fault_addr": fault_addr,
        "verified": verified,
        "base_name": base_name,
        "field_name": field_name,
        "source": "gdb 指令解析+寄存器",
    }


def describe(attr):
    """归因结果 → 人读结论句（进 定位结论/证据包）；不可解析返回 None。"""
    if not attr or not attr.get("parsed"):
        return None
    who = attr.get("base_name") or ("<%s>" % attr.get("base_reg"))
    if attr.get("field_name"):
        what = "的字段 %s" % attr["field_name"]
    elif attr.get("disp"):
        what = " +0x%x" % attr["disp"]
    else:
        what = ""
    verdict = ("寄存器交叉验证一致：基址+偏移 == 出错地址"
               if attr.get("verified") else
               "计算值与出错地址不一致，标注疑似")
    return ("崩溃指令 `%s`：解引用 %s%s——基址寄存器 %s=0x%x，+0x%x，%s"
            % (attr["insn"], who, what, attr.get("base_reg"),
               attr.get("base_val") or 0, attr.get("disp") or 0, verdict))

# -*- coding: utf-8 -*-
"""CFI 离线回溯：纯 Python .eh_frame 解码 + 虚拟展开器。

替代启发式栈扫描——在无 gdb 时也能精确展开调用栈。
基于 vendored pyelftools 的 CFI 解析（elftools.dwarf.callframe），
在 core 文件的内存映像上执行虚拟 CFI 指令完成逐帧展开。

原理：
  .eh_frame 段记录了"每个 PC 处的帧布局"（CFA 计算 + 寄存器保存位置）。
  展开器从崩溃线程的初始寄存器出发，逐帧查表：
    1. 找到覆盖当前 PC 的 FDE（Frame Description Entry）
    2. 执行该 FDE 的 CFI 指令直到当前 PC
    3. 计算 CFA（Canonical Frame Address）
    4. 从 core 内存读返回地址（通常在 CFA-8）
    5. 恢复 Callee-saved 寄存器 → 进入下一帧
"""
import bisect
import struct

from elftools.elf.elffile import ELFFile

# DW_CFA 指令操作码
DW_CFA_ADVANCE_LOC = 0x40     # 高 2bit=01，低 6bit=增量
DW_CFA_OFFSET = 0x80          # 高 2bit=10，低 6bit=寄存器号
DW_CFA_RESTORE = 0xC0         # 高 2bit=11，低 6bit=寄存器号
DW_CFA_NOP = 0x00
DW_CFA_SET_LOC = 0x01
DW_CFA_ADVANCE_LOC1 = 0x02
DW_CFA_ADVANCE_LOC2 = 0x03
DW_CFA_ADVANCE_LOC4 = 0x04
DW_CFA_DEF_CFA = 0x0C
DW_CFA_DEF_CFA_REGISTER = 0x0D
DW_CFA_DEF_CFA_OFFSET = 0x0E
DW_CFA_DEF_CFA_EXPRESSION = 0x0F
DW_CFA_EXPRESSION = 0x10
DW_CFA_OFFSET_EXTENDED = 0x05
DW_CFA_RESTORE_EXTENDED = 0x06
DW_CFA_UNDEFINED = 0x07
DW_CFA_SAME_VALUE = 0x08
DW_CFA_REGISTER = 0x09
DW_CFA_REMEMBER_STATE = 0x0A
DW_CFA_RESTORE_STATE = 0x0B
DW_CFA_VAL_EXPRESSION = 0x16


class FrameRule(object):
    """一个 PC 处的帧规则快照。"""
    __slots__ = ("pc", "cfa_reg", "cfa_off", "regs", "ra_rule")

    def __init__(self, pc):
        self.pc = pc
        self.cfa_reg = None       # DW_REG 号（CFA 基于哪个寄存器）
        self.cfa_off = 0          # CFA = reg + offset
        self.regs = {}            # reg_num -> (op, operand)：恢复规则
        self.ra_rule = None       # 返回地址的恢复规则


class FDEntry(object):
    """一个 FDE 及其解码后的规则表。"""
    __slots__ = ("start", "end", "rules", "cie_reg_names")

    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.rules = []           # 排序的 FrameRule 列表
        self.cie_reg_names = {}


class EHFrameTable(object):
    """一个产物的 .eh_frame 解码结果：按 PC 查 FrameRule。"""

    def __init__(self, path):
        self.path = path
        self.fdes = []            # FDEntry 列表
        self._starts = []         # 排序的 FDE 起始地址（二分查找用）
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                if not elf.has_dwarf_info():
                    return
                dw = elf.get_dwarf_info()
                # 优先 .eh_frame，退回 .debug_frame
                try:
                    entries = list(dw.EH_CFI_entries())
                except Exception:
                    try:
                        entries = list(dw.CFI_entries())
                    except Exception:
                        return
                for entry in entries:
                    if not hasattr(entry, "header"):
                        continue
                    hdr = entry.header
                    if not hasattr(hdr, "initial_location"):
                        continue  # 跳过 CIE
                    fde = FDEntry(hdr["initial_location"],
                                  hdr["initial_location"] + hdr["address_range"])
                    self._decode_fde(entry, fde)
                    if fde.rules:
                        self.fdes.append(fde)
            self.fdes.sort(key=lambda f: f.start)
            self._starts = [f.start for f in self.fdes]
        except Exception:
            pass

    def _decode_fde(self, entry, fde):
        """将 FDE 的 CFI 指令序列解码为逐 PC 的规则表。"""
        # 初始状态来自 CIE
        cie = getattr(entry, "cie", None)
        if cie is None:
            return

        # 从 CIE 读初始状态
        cfa_reg, cfa_off = self._read_cie_initial(cie)
        if cfa_reg is None:
            return

        cur = FrameRule(fde.start)
        cur.cfa_reg = cfa_reg
        cur.cfa_off = cfa_off
        pc = fde.start
        reg_state = {}            # 当前寄存器恢复状态
        state_stack = []          # DW_CFA_REMEMBER/RESTORE_STATE 用

        def _snapshot():
            r = FrameRule(pc)
            r.cfa_reg = cur.cfa_reg
            r.cfa_off = cur.cfa_off
            r.regs = dict(reg_state)
            r.ra_rule = reg_state.get(self._ra_reg_num())
            return r

        # 处理 CIE 的初始指令
        for inst in getattr(cie, "instructions", []):
            self._exec_instruction(inst, cur, reg_state, state_stack)

        rules = [_snapshot()]

        # 处理 FDE 自身的指令
        for inst in getattr(entry, "instructions", []):
            opcode = getattr(inst, "opcode", None)
            args = getattr(inst, "args", [])
            if opcode is None:
                continue
            # DW_CFA_advance_loc*
            if 0x40 <= opcode <= 0x7F:    # advance_loc
                delta = opcode & 0x3F
                pc += delta * self._code_align
                rules.append(_snapshot())
            elif opcode == DW_CFA_ADVANCE_LOC1:
                if args:
                    pc += args[0] * self._code_align
                    rules.append(_snapshot())
            elif opcode == DW_CFA_ADVANCE_LOC2:
                if args:
                    pc += args[0] * self._code_align
                    rules.append(_snapshot())
            elif opcode == DW_CFA_ADVANCE_LOC4:
                if args:
                    pc += args[0] * self._code_align
                    rules.append(_snapshot())
            else:
                self._exec_instruction(inst, cur, reg_state, state_stack)

        fde.rules = rules

    def _read_cie_initial(self, cie):
        """从 CIE 读初始 CFA 规则。"""
        # 遍历 CIE 的指令找 DW_CFA_def_cfa
        cfa_reg = cfa_off = None
        for inst in getattr(cie, "instructions", []):
            opcode = getattr(inst, "opcode", None)
            args = getattr(inst, "args", [])
            if opcode == DW_CFA_DEF_CFA and len(args) >= 2:
                cfa_reg = args[0]
                cfa_off = args[1]
            elif opcode == DW_CFA_DEF_CFA_REGISTER and args:
                cfa_reg = args[0]
            elif opcode == DW_CFA_DEF_CFA_OFFSET and args:
                cfa_off = args[0]
        return cfa_reg, cfa_off

    def _exec_instruction(self, inst, cur, reg_state, state_stack):
        """执行一条 CFI 指令，更新当前状态。"""
        opcode = getattr(inst, "opcode", None)
        args = getattr(inst, "args", [])
        if opcode is None or not args:
            return
        if 0x80 <= opcode <= 0xFF:    # DW_CFA_offset
            reg = opcode & 0x3F
            if args:
                reg_state[reg] = ("offset", args[0])
        elif opcode == DW_CFA_OFFSET_EXTENDED and len(args) >= 2:
            reg_state[args[0]] = ("offset", args[1])
        elif opcode == DW_CFA_DEF_CFA and len(args) >= 2:
            cur.cfa_reg = args[0]
            cur.cfa_off = args[1]
        elif opcode == DW_CFA_DEF_CFA_REGISTER and args:
            cur.cfa_reg = args[0]
        elif opcode == DW_CFA_DEF_CFA_OFFSET and args:
            cur.cfa_off = args[0]
        elif opcode == DW_CFA_REMEMBER_STATE:
            state_stack.append((dict(reg_state), cur.cfa_reg, cur.cfa_off))
        elif opcode == DW_CFA_RESTORE_STATE:
            if state_stack:
                rs, cr, co = state_stack.pop()
                reg_state.clear()
                reg_state.update(rs)
                cur.cfa_reg = cr
                cur.cfa_off = co
        elif opcode == DW_CFA_RESTORE or (0xC0 <= opcode <= 0xFF):
            reg = opcode & 0x3F
            reg_state.pop(reg, None)
        elif opcode == DW_CFA_RESTORE_EXTENDED and args:
            reg_state.pop(args[0], None)

    def _ra_reg_num(self):
        """返回地址的 DWARF 寄存器号（RA column）。"""
        return 16 if self.path.endswith("64") or "x86_64" in self.path else 30

    def lookup(self, pc):
        """查找覆盖 PC 的 FrameRule；找不到返回 None。"""
        self._load()
        if not self._starts:
            return None
        i = bisect.bisect_right(self._starts, pc) - 1
        if i < 0:
            return None
        fde = self.fdes[i]
        if pc < fde.start or pc >= fde.end:
            return None
        # 在 FDE 的规则表中找到 ≤pc 的最后一条
        if not fde.rules:
            return None
        j = bisect.bisect_right([r.pc for r in fde.rules], pc) - 1
        if j < 0:
            j = 0
        return fde.rules[j]


# DWARF 寄存器号 → 各架构寄存器名的映射
_DWARF_REG_MAP = {
    "x86_64": {0: "rax", 1: "rdx", 2: "rcx", 3: "rbx", 4: "rsi", 5: "rdi",
               6: "rbp", 7: "rsp", 8: "r8", 9: "r9", 10: "r10", 11: "r11",
               12: "r12", 13: "r13", 14: "r14", 15: "r15", 16: "rip"},
    "arm64": {0: "x0", 1: "x1", 2: "x2", 3: "x3", 4: "x4", 5: "x5",
              6: "x6", 7: "x7", 8: "x8", 9: "x9", 10: "x10", 11: "x11",
              12: "x12", 13: "x13", 14: "x14", 15: "x15", 16: "x16",
              17: "x17", 18: "x18", 19: "x19", 20: "x20", 21: "x21",
              22: "x22", 23: "x23", 24: "x24", 25: "x25", 26: "x26",
              27: "x27", 28: "x28", 29: "x29", 30: "x30", 31: "sp"},
    "arm32": {0: "r0", 1: "r1", 2: "r2", 3: "r3", 4: "r4", 5: "r5",
              6: "r6", 7: "r7", 8: "r8", 9: "r9", 10: "r10", 11: "fp",
              12: "ip", 13: "sp", 14: "lr", 15: "pc"},
    "riscv64": {0: "zero", 1: "ra", 2: "sp", 3: "gp", 4: "tp",
                5: "t0", 6: "t1", 7: "t2", 8: "s0", 9: "s1",
                10: "a0", 11: "a1", 12: "a2", 13: "a3",
                14: "a4", 15: "a5", 16: "a6", 17: "a7"},
}

# 架构的 CFA 默认寄存器号
_ARCH_CFA_REG = {
    "x86_64": 7,    # rsp
    "arm64": 31,    # sp
    "arm32": 13,    # sp
    "riscv64": 2,   # sp
}


def cfi_unwind(core, thread, arch_name, symbol_table_path, max_frames=50):
    """CFI 精确展开——从崩溃线程寄存器出发逐帧恢复调用栈。

    返回 [(pc, cfa, rule)] 列表；某帧查不到 FDE 时停止。
    """
    table = EHFrameTable(symbol_table_path)
    table._load()
    if not table.fdes:
        return None    # 无 .eh_frame 信息

    reg_map = _DWARF_REG_MAP.get(arch_name, {})
    word = 8 if core.elfclass == 64 else 4

    # 初始寄存器
    pc = thread.pc
    sp = thread.sp
    regs = dict(thread.regs)

    frames = []
    for depth in range(max_frames):
        rule = table.lookup(pc)
        if rule is None:
            break

        # 计算 CFA
        cfa_reg_name = reg_map.get(rule.cfa_reg)
        if cfa_reg_name is None:
            break
        cfa_base = regs.get(cfa_reg_name, 0)
        if cfa_base == 0:
            break
        cfa = cfa_base + rule.cfa_off

        # 读返回地址（通常在 CFA - word）
        ra_addr = cfa - word
        ra_bytes = core.read_mem(ra_addr, word)
        if ra_bytes is None:
            break
        ra = struct.unpack("<Q" if word == 8 else "<I", ra_bytes)[0]
        if ra == 0:
            break

        frames.append((pc, cfa, rule))

        # 恢复 callee-saved 寄存器
        new_regs = dict(regs)
        for dw_reg, (op, operand) in rule.regs.items():
            reg_name = reg_map.get(dw_reg)
            if not reg_name:
                continue
            if op == "offset":
                addr = cfa - operand * word  # DWARF offset 以 data_align 为单位
                val_bytes = core.read_mem(addr, word)
                if val_bytes is not None:
                    new_regs[reg_name] = struct.unpack(
                        "<Q" if word == 8 else "<I", val_bytes)[0]

        # 进入下一帧
        pc = ra
        sp = cfa
        regs = new_regs
        regs["sp"] = sp
        regs[reg_map.get(_ARCH_CFA_REG.get(arch_name, 7), "rsp")] = sp

    return frames if frames else None

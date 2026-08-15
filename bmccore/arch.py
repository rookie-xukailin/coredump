# -*- coding: utf-8 -*-
"""三架构（ARM32/ARM64/RISC-V）差异知识表。

包含两类信息：
1. NT_PRSTATUS 里通用寄存器的布局（名字、数量、字长），corefile.py 用它拆寄存器；
2. call 指令的二进制编码判定，scan.py 用它验证“栈上的值是不是返回地址”。
   判定输入是候选地址前面若干字节的原始指令（小端），不依赖 objdump。
"""
import struct


class ArchInfo(object):
    """一个架构的全部差异点。"""

    def __init__(self, name, machine, elfclass, regnames,
                 reg_pc, reg_sp, reg_lr, reg_fp,
                 is_call=None, thumb_aware=False):
        self.name = name                  # 'arm32' / 'arm64' / 'riscv64' / ...
        self.machine = machine            # ELF e_machine 编号
        self.elfclass = elfclass          # 32 / 64
        self.regnames = regnames          # NT_PRSTATUS 寄存器顺序名表
        self.reg_pc = reg_pc
        self.reg_sp = reg_sp
        self.reg_lr = reg_lr
        self.reg_fp = reg_fp
        # is_call(prev8: bytes, addr: int, value: int) -> (bool, str)
        # prev8 = 候选地址前 8 字节原始指令流（小端），addr = 候选地址，
        # value = 栈上存的原值（ARM32 需要看 bit0 判 Thumb）。
        self._is_call = is_call
        self.thumb_aware = thumb_aware

    @property
    def word(self):
        return 4 if self.elfclass == 32 else 8

    def is_call_before(self, prev8, addr, value):
        """判断 addr 处的值是否紧跟在一条 call 指令之后。

        prev8: addr 前 8 字节（能取到多少算多少）；
        返回 (是/否, 说明)。
        """
        if self._is_call is None:
            return True, "架构未实现call判定,视为候选"
        try:
            return self._is_call(prev8, addr, value)
        except Exception:
            return True, "指令解码异常,视为候选"


# ---------------------------------------------------------------------------
# 各架构 call 指令判定
# prev8 布局（小端，x 代表候选地址处）:
#   [addr-8 .. addr-1]，即 prev8[4:8] 是紧贴候选地址的那条指令（若 4 字节长）。
# ---------------------------------------------------------------------------

def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def _u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def _arm32_is_call(prev8, addr, value):
    """ARM32：分 ARM/Thumb 两种指令集判 BL/BLX。

    栈上值的 bit0=1 表示调用方是 Thumb 状态（返回地址带 Thumb 标记）。
    """
    thumb = value & 1
    if thumb:
        cand = value & ~1
        # Thumb-2 32位 BL/BLX：候选-4 处半字 11110xxx，候选-2 处 11xxxxxx(BL)/111xxxx(BLX)
        if len(prev8) >= 8:
            hw1 = _u16(prev8, 4)   # cand-4
            hw2 = _u16(prev8, 6)   # cand-2
            if (hw1 & 0xF800) == 0xF000 and ((hw2 & 0xF800) == 0xE800 or (hw2 & 0xF800) == 0xF000):
                return True, "Thumb BL/BLX(32位)"
        # 16位 BLX Rm：候选-2 处 01000111 1xxx x000
        if len(prev8) >= 2:
            hw = _u16(prev8, 6)
            if (hw & 0xFF87) == 0x4780:
                return True, "Thumb BLX Rm(16位)"
        return False, "Thumb但前指令不是call"
    # ARM 模式：候选-4 处条件 BL（含无条件 BL cond=1110/1111）或 BLX imm
    if len(prev8) >= 8:
        w = _u32(prev8, 4)
        if (w & 0x0F000000) == 0x0B000000:      # cond BL
            return True, "ARM BL"
        if (w & 0xFE000000) == 0xFA000000:      # BLX imm (H 位在 bit24, 不细究)
            return True, "ARM BLX imm"
    return False, "ARM但前指令不是call"


def _a64_is_call(prev8, addr, value):
    """AArch64：候选-4 处 BL (100101 imm26) 或 BLR Xn (1101011 0011 1111 0000 00 Rn 00000)。"""
    if len(prev8) >= 8:
        w = _u32(prev8, 4)
        if (w & 0xFC000000) == 0x94000000:
            return True, "A64 BL"
        if (w & 0xFFFFFC1F) == 0xD63F0000:
            return True, "A64 BLR"
        # BLRAAZ/BLRAA（PAC 场景）
        if (w & 0xFFFFFC00) == 0xD63F0C00:
            return True, "A64 BLRAA*"
    return False, "A64但前指令不是call"


def _riscv_is_call(prev8, addr, value):
    """RISC-V：JAL rd=x1/x5；JALR rd=x1/x5 且 rs1 非 x1/x5（排除 ret）；RVC c.jal(rv32)。"""
    if len(prev8) >= 8:
        w = _u32(prev8, 4)
        rd = (w >> 7) & 0x1F
        opcode = w & 0x7F
        if opcode == 0x6F and rd in (1, 5):
            return True, "RISCV JAL"
        if opcode == 0x67 and rd in (1, 5):
            rs1 = (w >> 15) & 0x1F
            if rs1 not in (1, 5):       # rs1=x1 rd=x1 是尾调用/ret 形态,排除
                return True, "RISCV JALR"
    if len(prev8) >= 2:
        hw = _u16(prev8, 6)
        if (hw & 0xE003) == 0x2001:     # c.jal (仅 rv32 有)
            return True, "RISCV c.jal"
    return False, "RISCV但前指令不是call"


# NT_PRSTATUS 寄存器顺序（对应内核 user_pt_regs / user_regs_struct 布局）
_ARM32_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
               "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc",
               "cpsr", "orig_r0"]

_A64_REGS = (["x%d" % i for i in range(31)] + ["sp", "pc", "pstate"])

# rv: pc,ra,sp,gp,tp,t0,t1,t2,s0,s1,a0..a7,s2..s11,t3..t6
_RISCV_REGS = (["pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"]
               + ["a%d" % i for i in range(8)]
               + ["s%d" % i for i in range(2, 12)]
               + ["t%d" % i for i in range(3, 7)])

ARM32 = ArchInfo("arm32", 40, 32, _ARM32_REGS,
                 "pc", "sp", "lr", "fp",
                 is_call=_arm32_is_call, thumb_aware=True)

ARM64 = ArchInfo("arm64", 183, 64, _A64_REGS,
                 "pc", "sp", "x30", "x29",
                 is_call=_a64_is_call)

RISCV64 = ArchInfo("riscv64", 243, 64, _RISCV_REGS,
                   "pc", "sp", "ra", "s0",
                   is_call=_riscv_is_call)

RISCV32 = ArchInfo("riscv32", 243, 32, _RISCV_REGS,
                   "pc", "sp", "ra", "s0",
                   is_call=_riscv_is_call)

_BY_MACHINE_CLASS = {
    (40, 32): ARM32,
    (183, 64): ARM64,
    (243, 64): RISCV64,
    (243, 32): RISCV32,
}


def arch_for(machine, elfclass):
    key = (machine, elfclass)
    if key in _BY_MACHINE_CLASS:
        return _BY_MACHINE_CLASS[key]
    return None


def all_archs():
    return [ARM32, ARM64, RISCV64, RISCV32]

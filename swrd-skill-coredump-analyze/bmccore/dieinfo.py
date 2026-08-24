# -*- coding: utf-8 -*-
"""DWARF debug_info 语义命名：把地址/偏移翻译回变量名与结构体字段名。

pyelftools 的 DIE 树（.debug_info）里存着源码级语义（vendored 三方库的
核心价值之一），本模块一次 DIE 遍历同时提取四类表：

1. 全局/静态变量表：DW_TAG_variable + DW_AT_location(DW_OP_addr) →
   {地址: 变量名}——锁地址、futex 等待地址、出错地址由此得名
   （如 futex@0x7f42… → g_sensor_lock）
2. 结构体表：DW_TAG_structure_type（DW_AT_byte_size + 成员
   DW_AT_data_member_location + 成员类型名）→ 按尺寸反推受害对象类型、
   按偏移报字段名、按字段类型解读内容
3. 函数参数表：DW_TAG_subprogram 的 DW_TAG_formal_parameter
   （名字 + DW_AT_location 首字节 DW_OP_regN）→ 崩溃帧参数的
   寄存器级恢复（DWARF 精确映射，非启发式）
4. 全局变量区间：地址+尺寸 → 指针落进 g_buf+0x10 这类"变量内偏移"命名

按产物路径缓存：DIE 遍历只发生在首次查询该产物时（大库如 libc 数秒，
之后走缓存）；产物无 DWARF 时返回空表（如实降级，不报错）。
"""
from elftools.elf.elffile import ELFFile

DW_OP_REG0 = 0x50            # DW_OP_regN = 0x50+N（0x50~0x8f）
DW_OP_REG_MAX = 0x8f

_cache = {}      # path -> table dict（见 _load）


def _dw_op_addr_value(value, addr_size):
    """DW_AT_location 为 exprloc 且首字节 DW_OP_addr(0x03) 时取地址值。"""
    if not isinstance(value, (bytes, bytearray)) or len(value) < 1 + addr_size:
        return None
    if value[0] != 0x03:
        return None
    return int.from_bytes(bytes(value[1:1 + addr_size]), "little")


def _dec(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def _type_info(die, cu):
    """解析 DIE 的 DW_AT_type → (类型名, 字节尺寸)；解析不了返回 (None, None)。"""
    tref = die.attributes.get("DW_AT_type")
    if tref is None:
        return None, None
    try:
        tdie = die.get_DIE_from_attribute("DW_AT_type")
    except Exception:
        return None, None
    name = None
    size = None
    seen = 0
    while tdie is not None and seen < 6:      # 穿透 typedef/volatile/const
        seen += 1
        tag = tdie.tag
        if "DW_AT_name" in tdie.attributes:
            name = _dec(tdie.attributes["DW_AT_name"].value)
        if "DW_AT_byte_size" in tdie.attributes:
            try:
                size = int(tdie.attributes["DW_AT_byte_size"].value)
            except Exception:
                size = None
        if tag in ("DW_TAG_pointer_type",):
            name = (name + " *" if name else None) or "ptr"
            base = None
            try:
                bdie = tdie.get_DIE_from_attribute("DW_AT_type")
            except Exception:
                bdie = None
            if bdie is not None and "DW_AT_name" in bdie.attributes:
                base = _dec(bdie.attributes["DW_AT_name"].value)
            nm = ("%s *" % base) if base else "void *"
            return nm, size if size is not None else (8 if cu.header["address_size"] == 8 else 4)
        if tag in ("DW_TAG_array_type",):
            try:
                bdie = tdie.get_DIE_from_attribute("DW_AT_type")
                bname = _dec(bdie.attributes["DW_AT_name"].value) if (
                    bdie is not None and "DW_AT_name" in bdie.attributes) else None
            except Exception:
                bname = None
            return ("%s[]" % bname) if bname else "array", size
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type",
                   "DW_TAG_enumeration_type", "DW_TAG_base_type"):
            return name or tag.replace("DW_TAG_", "").replace("_type", ""), size
        try:
            tdie = tdie.get_DIE_from_attribute("DW_AT_type")
        except Exception:
            return name, size
    return name, size


def _load(path):
    vars_ = {}            # {addr: name}
    var_ranges = []       # [(addr, size_or_None, name)]
    structs = []          # [(name, size, {off: (member, type_name)})]
    funcs = {}            # {name: [(param_name, regno_or_None)]}
    try:
        f = open(path, "rb")
    except OSError:
        return {"vars": vars_, "var_ranges": var_ranges,
                "structs": structs, "funcs": funcs}
    with f:
        try:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return {"vars": vars_, "var_ranges": var_ranges,
                        "structs": structs, "funcs": funcs}
            dw = elf.get_dwarf_info()
            for cu in dw.iter_CUs():
                addr_size = cu.header["address_size"]
                for die in cu.iter_DIEs():
                    tag = die.tag
                    if tag == "DW_TAG_variable":
                        name_at = die.attributes.get("DW_AT_name")
                        loc = die.attributes.get("DW_AT_location")
                        if not name_at or loc is None:
                            continue
                        addr = _dw_op_addr_value(loc.value, addr_size)
                        if addr is None:
                            continue
                        nm = _dec(name_at.value)
                        # 同地址多定义（COMDAT/内联副本）保留先见
                        vars_.setdefault(addr, nm)
                        _tn, _ts = _type_info(die, cu)
                        var_ranges.append((addr, _ts, nm))
                    elif tag == "DW_TAG_structure_type":
                        name_at = die.attributes.get("DW_AT_name")
                        size_at = die.attributes.get("DW_AT_byte_size")
                        if not name_at or size_at is None:
                            continue
                        members = {}
                        try:
                            children = list(die.iter_children())
                        except Exception:
                            children = []
                        for ch in children:
                            if ch.tag != "DW_TAG_member":
                                continue
                            mname = ch.attributes.get("DW_AT_name")
                            moff = ch.attributes.get("DW_AT_data_member_location")
                            if not mname or moff is None:
                                continue
                            off = moff.value
                            if isinstance(off, (bytes, bytearray)):
                                continue        # 表达式形式偏移，跳过
                            mtn, _mts = _type_info(ch, cu)
                            members[off] = (_dec(mname.value), mtn or "?")
                        structs.append((_dec(name_at.value), size_at.value, members))
                    elif tag == "DW_TAG_subprogram":
                        name_at = die.attributes.get("DW_AT_name")
                        if not name_at:
                            continue
                        params = []
                        try:
                            children = list(die.iter_children())
                        except Exception:
                            children = []
                        for ch in children:
                            if ch.tag != "DW_TAG_formal_parameter":
                                continue
                            pname = ch.attributes.get("DW_AT_name")
                            if not pname:
                                continue
                            regno = None
                            loc = ch.attributes.get("DW_AT_location")
                            if (loc is not None
                                    and isinstance(loc.value, (bytes, bytearray))
                                    and loc.value
                                    and DW_OP_REG0 <= loc.value[0] <= DW_OP_REG_MAX):
                                regno = loc.value[0] - DW_OP_REG0
                            params.append((_dec(pname.value), regno))
                        if params:
                            fn = _dec(name_at.value)
                            funcs.setdefault(fn, params)
        except Exception:
            pass
    return {"vars": vars_, "var_ranges": var_ranges,
            "structs": structs, "funcs": funcs}


def _table(path):
    t = _cache.get(path)
    if t is None:
        t = _load(path)
        _cache[path] = t
    return t


def name_address(path, addr):
    """地址 → 全局/静态变量名（精确匹配）；无 DWARF/未命中返回 None。"""
    return _table(path)["vars"].get(addr)


def name_address_loose(path, addr):
    """地址 → '变量名' 或 '变量名+0x偏移'（地址落在变量区间内）；未命中 None。"""
    t = _table(path)
    nm = t["vars"].get(addr)
    if nm:
        return nm
    best = None
    for a, sz, n in t["var_ranges"]:
        if sz and a <= addr < a + sz:
            off = addr - a
            cand = "%s+0x%x" % (n, off) if off else n
            # 取区间最小的命中（更精确的变量）
            if best is None or sz < best[0]:
                best = (sz, cand)
    return best[1] if best else None


def struct_by_size(path, size):
    """按 DW_AT_byte_size 精确匹配结构体；返回 (name, {偏移: (成员名, 类型名)}) 或 None。"""
    for nm, sz, members in _table(path)["structs"]:
        if sz == size:
            return nm, members
    return None


def member_name(path, size, offset):
    """尺寸+偏移 → 'struct.member' 名；未命中返回 None。"""
    st = struct_by_size(path, size)
    if st and offset in st[1]:
        return "%s.%s" % (st[0], st[1][offset][0])
    return None


def params_of(path, func_name):
    """函数名 → 参数表 [(参数名, DWARF寄存器号或None)]（按声明顺序）。

    寄存器号来自 DW_AT_location 的 DW_OP_regN——函数入口处的精确
    寄存器分配（DWARF 证据，非启发式）。未命中返回空表。
    """
    params = _table(path)["funcs"].get(func_name)
    return list(params) if params else []


def dwarf_reg_name(arch_name, regno):
    """DWARF 寄存器号 → 架构寄存器名（用于与 NT_PRSTATUS 寄存器配对）。"""
    if arch_name == "arm64":
        if 0 <= regno <= 30:
            return "x%d" % regno
        if regno == 31:
            return "sp"
    elif arch_name == "arm32":
        if 0 <= regno <= 15:
            return "r%d" % regno
    elif arch_name == "riscv64":
        if 0 <= regno <= 31:
            if 10 <= regno <= 17:
                return "a%d" % (regno - 10)
            if regno == 1:
                return "ra"
            if regno == 2:
                return "sp"
            if 8 <= regno <= 9:
                return "s%d" % (regno - 8)
            if 18 <= regno <= 27:
                return "s%d" % (regno - 16)
            return "x%d" % regno
    elif arch_name in ("x86_64",):
        names = ["rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        if 0 <= regno < len(names):
            return names[regno]
    return None

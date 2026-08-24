# -*- coding: utf-8 -*-
"""DWARF debug_info 语义命名：把地址/偏移翻译回变量名与结构体字段名。

pyelftools 的 DIE 树（.debug_info）里存着源码级语义（vendored 三方库的
核心价值之一），本模块一次 DIE 遍历同时提取两类表：

1. 全局/静态变量表：DW_TAG_variable + DW_AT_location(DW_OP_addr) →
   {地址: 变量名}——锁地址、futex 等待地址、出错地址由此得名
   （如 futex@0x7f42… → g_sensor_lock）
2. 结构体表：DW_TAG_structure_type（DW_AT_byte_size + 成员
   DW_AT_data_member_location）→ 按尺寸反推受害对象类型、按偏移报字段名

按产物路径缓存：DIE 遍历只发生在首次查询该产物时（大库如 libc 数秒，
之后走缓存）；产物无 DWARF 时返回空表（如实降级，不报错）。
"""
from elftools.elf.elffile import ELFFile

_cache = {}      # path -> {"vars": {addr: name}, "structs": [(name, size, {off: member})]}


def _dw_op_addr_value(value, addr_size):
    """DW_AT_location 为 exprloc 且首字节 DW_OP_addr(0x03) 时取地址值。"""
    if not isinstance(value, (bytes, bytearray)) or len(value) < 1 + addr_size:
        return None
    if value[0] != 0x03:
        return None
    return int.from_bytes(bytes(value[1:1 + addr_size]), "little")


def _dec(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def _load(path):
    vars_ = {}
    structs = []
    try:
        f = open(path, "rb")
    except OSError:
        return {"vars": vars_, "structs": structs}
    with f:
        try:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return {"vars": vars_, "structs": structs}
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
                        # 同地址多定义（COMDAT/内联副本）保留先见
                        vars_.setdefault(addr, _dec(name_at.value))
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
                            members[off] = _dec(mname.value)
                        structs.append((_dec(name_at.value), size_at.value, members))
        except Exception:
            pass
    return {"vars": vars_, "structs": structs}


def _table(path):
    t = _cache.get(path)
    if t is None:
        t = _load(path)
        _cache[path] = t
    return t


def name_address(path, addr):
    """地址 → 全局/静态变量名（精确匹配）；无 DWARF/未命中返回 None。"""
    return _table(path)["vars"].get(addr)


def struct_by_size(path, size):
    """按 DW_AT_byte_size 精确匹配结构体；返回 (name, {偏移: 成员名}) 或 None。"""
    for nm, sz, members in _table(path)["structs"]:
        if sz == size:
            return nm, members
    return None


def member_name(path, size, offset):
    """尺寸+偏移 → 'struct.member' 名；未命中返回 None。"""
    st = struct_by_size(path, size)
    if st and offset in st[1]:
        return "%s.%s" % (st[0], st[1][offset])
    return None

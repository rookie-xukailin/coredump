# -*- coding: utf-8 -*-
"""值语义化：core 里的任意一个数字 → "它是什么"。

寄存器值、栈上的字、堆块字段值……都是 64/32 位数字。本模块把它们翻译
回人类语义：空指针偏移/代码符号/全局变量(±偏移)/线程栈位置/堆 chunk/
可读字符串/小整数。证据包、帧变量、栈内存解码、堆对象解码共用。
"""
from . import dieinfo as dieinfo_mod

_PRINTABLE = set(range(0x20, 0x7f)) | {0x09}


class Decoder(object):
    """按 core+模块+可选堆结果构建的值解码器（一次构建，多次查询）。"""

    def __init__(self, core, matches, heap_result=None, addr_names=None):
        self.core = core
        self.addr_names = addr_names or {}
        # 代码区间：[(start, end, 模块名)] —— 来自配对的模块
        self.code_ranges = []
        for m in matches:
            if m.artifact is None:
                continue
            self.code_ranges.append((m.module.base,
                                     m.module.base + m.module.size,
                                     m.module.name))
        # 堆 chunk 索引：[(区起点, {chunk偏移: (chunk, 数据)}), ...]
        self.heaps = []
        if heap_result is not None:
            for desc, chunks in heap_result.regions:
                try:
                    start = int(desc.split("-")[0], 16)
                except Exception:
                    continue
                self.heaps.append((start, desc, chunks))
        # 各产物路径（dieinfo 查询用；主程序在前，命中优先级高）
        self.artifact_paths = []
        for m in matches:
            if m.artifact is not None and m.artifact.path not in self.artifact_paths:
                self.artifact_paths.append(m.artifact.path)

    # ------------------------------------------------------------------
    def _string_at(self, addr, minlen=4, maxlen=48):
        """读 addr 处的字符串（可打印且足够长才认）。"""
        data = self.core.read_mem(addr, maxlen)
        if not data:
            return None
        n = 0
        for b in data:
            if b == 0:
                break
            if b not in _PRINTABLE:
                return None
            n += 1
        if n < minlen:
            return None
        try:
            return data[:n].decode("utf-8", "replace")
        except Exception:
            return None

    def _heap_chunk(self, addr):
        for start, desc, chunks in self.heaps:
            if not (start <= addr):
                continue
            off = addr - start
            prev = None
            for c in chunks:
                if c.offset <= off < c.offset + c.size:
                    in_off = off - c.offset
                    return "%schunk+0x%x/%s(大小0x%x%s)" % (
                        "堆区%s " % desc if desc else "", in_off,
                        "in-use" if c.inuse else "free", c.size,
                        "" if prev is None else "")
                if c.offset > off:
                    break
                prev = c
        return None

    def _stack_pos(self, addr):
        """addr 落在哪个线程栈的什么位置。"""
        for t in self.core.threads:
            r = self.core.region_of(t.sp)
            if r and r.vaddr <= addr < r.vaddr + r.memsz:
                rel = addr - t.sp
                mark = "崩溃线程" if (self.core.crash_thread and
                                      t.tid == self.core.crash_thread.tid) else "线程%d" % t.tid
                return "%s栈 SP%s0x%x" % (mark, "+" if rel >= 0 else "", rel)
        return None

    def _code_name(self, addr):
        for s, e, nm in self.code_ranges:
            if s <= addr < e:
                off = addr - s
                return "代码(%s%s)" % (nm, ("+0x%x" % off) if off else "")
        return None

    def _die_name(self, addr):
        """全局变量命名：先看流水线已命名的，再按产物 DIE 表（含区间命中）。"""
        nm = self.addr_names.get(addr)
        if nm:
            return "全局 %s" % nm
        for p in self.artifact_paths:
            nm = dieinfo_mod.name_address_loose(p, addr)
            if nm:
                return "全局 %s" % nm
        return None

    # ------------------------------------------------------------------
    def decode(self, value, depth=0):
        """值 → 语义描述字符串（短，一行内）。depth 防递归。"""
        try:
            v = value & (0xFFFFFFFFFFFFFFFF if self.core.elfclass == 64
                         else 0xFFFFFFFF)
        except Exception:
            return str(value)
        if v == 0:
            return "0（NULL）"
        if v < 0x1000:
            return "0x%x（空指针+%d 偏移 或 小整数）" % (v, v)
        # 1) 已知地址命名（锁/出错地址等已在流水线命名过）
        if v in self.addr_names:
            return "全局 %s" % self.addr_names[v]
        # 2) 代码区间
        nm = self._code_name(v)
        if nm:
            return nm
        # 3) 线程栈
        nm = self._stack_pos(v)
        if nm:
            return nm
        # 4) 堆 chunk
        nm = self._heap_chunk(v)
        if nm:
            return nm
        # 5) 全局变量（DIE）
        nm = self._die_name(v)
        if nm:
            return nm
        # 6) 只读段 → 可能是字符串常量
        r = self.core.region_of(v)
        if r is not None:
            if depth == 0 and not r.write_bit:
                s = self._string_at(v)
                if s:
                    return "字符串 \"%s\"" % s[:40]
            kind = ("匿名读写段(堆/数据)" if r.write_bit else
                    "只读段" + ("(可执行)" if r.exec_bit else ""))
            return "%s 0x%x-0x%x 内 +0x%x" % (kind, r.vaddr,
                                               r.vaddr + r.filesz, v - r.vaddr)
        # 7) 未映射 + 字符串试探（指向已解映射区但曾是字符串的场景无解）
        if depth == 0:
            s = self._string_at(v)
            if s:
                return "字符串 \"%s\"（地址未映射）" % s[:40]
        if v <= 0xFFFF:
            return "%d（小整数）" % v
        return "0x%x（未映射）" % v


def decode_regs(core, matches, decoder=None, heap_result=None, addr_names=None,
                params=None):
    """崩溃线程全寄存器解码。

    params: [(参数名, 寄存器名)]（来自 dieinfo.params_of + dwarf_reg_name）
    ——命中时给参数寄存器标注 "x0 = dev = 0x0(…)"。
    返回 [(寄存器名, 值, 语义)]，按架构寄存器顺序。
    """
    d = decoder or Decoder(core, matches, heap_result, addr_names)
    t = core.crash_thread
    if t is None or core.arch is None:
        return []
    pmap = {reg: name for name, reg in (params or [])}
    out = []
    for rn in core.arch.regnames:
        if rn not in t.regs:
            continue
        v = t.regs[rn]
        sem = d.decode(v)
        if rn in pmap:
            sem = "参数 %s = %s" % (pmap[rn], sem)
        out.append((rn, v, sem))
    return out


def decode_stack_words(core, decoder, tid=None, words=64):
    """崩溃线程（或指定线程）SP 起逐字解码。

    返回 [(SP偏移, 地址, 值, 语义)]。
    """
    t = core.crash_thread
    if tid is not None:
        t = next((x for x in core.threads if x.tid == tid), t)
    if t is None or core.arch is None:
        return []
    w = core.arch.word
    data = core.read_mem(t.sp, words * w)
    if not data:
        return []
    out = []
    fmt = "<Q" if w == 8 else "<I"
    for i in range(len(data) // w):
        v = int.from_bytes(data[i * w:(i + 1) * w], "little")
        out.append((i * w, t.sp + i * w, v, d_sem(decoder, v)))
    return out


def d_sem(decoder, v):
    try:
        return decoder.decode(v)
    except Exception:
        return "?"

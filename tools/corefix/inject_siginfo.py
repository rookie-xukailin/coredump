#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向 ELF core 的 PT_NOTE 段插入 NT_SIGINFO note（真实内核转储必含，qemu/gdb 缺）。

关键点：gdb 生成的 core 在 note 段尾部带一个超大 "GDB" note（desc 24KB+），
直接追加会被当成它的 desc 吞掉。因此插入位置选在"最后一个完整非 GDB note 之后"。

  64位 desc: si_signo(i32) si_errno(i32) si_code(i32) pad(4) si_addr(u64@16)
  32位 desc: si_signo(i32) si_errno(i32) si_code(i32) si_addr(u32@12)

用法: inject_siginfo.py <core> <signo> <code> <addr-hex>
"""
import os
import struct
import sys

NT_SIGINFO = 0x53494749
PT_NOTE = 4


def main():
    path, signo, code, addr = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), None
    addr_s = sys.argv[4]
    if addr_s != "-":
        addr = int(addr_s, 0)
    else:
        addr = 0

    with open(path, "rb") as f:
        data = f.read()

    ei_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if ei_class == 2:
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
        sz_off, off_off, sz_fmt = (32, 8, "Q")
    else:
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
        sz_off, off_off, sz_fmt = (16, 4, "I")

    note_idx = None
    max_load_end = 0
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type = struct.unpack_from(endian + "I", data, o)[0]
        p_off = struct.unpack_from(endian + sz_fmt, data, o + off_off)[0]
        p_filesz = struct.unpack_from(endian + sz_fmt, data, o + sz_off)[0]
        if p_type == PT_NOTE:
            note_idx = i
        elif p_type == 1:  # PT_LOAD
            max_load_end = max(max_load_end, p_off + p_filesz)
    if note_idx is None:
        print("no PT_NOTE found")
        return 1

    noff = phoff + note_idx * phentsize
    note_fileoff = struct.unpack_from(endian + sz_fmt, data, noff + off_off)[0]
    note_filesz = struct.unpack_from(endian + sz_fmt, data, noff + sz_off)[0]
    avail = len(data) - note_fileoff          # 文件中实际存在的字节数

    # 走查 note，找到插入点：最后一个完整非 GDB note 的结束处
    off = note_fileoff
    insert_pos = note_fileoff
    n_notes = 0
    while off + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from(endian + "III", data, off)
        name = data[off + 12: off + 12 + namesz]
        if name.startswith(b"GDB"):
            insert_pos = off                  # 插在 GDB note 之前
            break
        end = off + 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
        if end > len(data):
            insert_pos = off                  # 截断的残包之前
            break
        off = end
        insert_pos = end
        n_notes += 1

    if insert_pos <= max_load_end:
        print("WARN: insert_pos 0x%x overlaps LOAD area 0x%x" % (insert_pos, max_load_end))

    # 合成 NT_SIGINFO（owner "CORE"）
    name = b"CORE\x00"
    namesz = len(name)
    if ei_class == 2:
        desc = struct.pack(endian + "iiiiQ", signo, 0, code, 0, addr)
    else:
        desc = struct.pack(endian + "iiiI", signo, 0, code, addr & 0xFFFFFFFF)
    entry = struct.pack(endian + "III", namesz, len(desc), NT_SIGINFO)
    entry += name + b"\x00" * ((-namesz) & 3)
    entry += desc

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from corepatch import insert_bytes
    new = insert_bytes(data, insert_pos, entry, elfclass=ei_class,
                       little=(data[5] == 1))
    with open(path, "wb") as f:
        f.write(new)
    # PT_NOTE filesz 以 .shstrtab 起点为界（其后是字符串表/节头表，不属于 note 段）
    new_filesz = min(note_filesz, avail) + len(entry)
    if ei_class == 2:
        e_shoff = struct.unpack_from(endian + "Q", new, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", new, 58)
        if e_shoff and e_shstrndx < e_shnum:
            so = e_shoff + e_shstrndx * e_shentsize
            shstr_off = struct.unpack_from(endian + "Q", new, so + 0x18)[0]
            if note_fileoff < shstr_off:
                new_filesz = shstr_off - note_fileoff
    with open(path, "r+b") as f:
        f.seek(noff + sz_off)
        f.write(struct.pack(endian + sz_fmt, new_filesz))
    print("NT_SIGINFO inserted@0x%x: signo=%d code=%d addr=0x%x (%d notes before, filesz 0x%x)"
          % (insert_pos, signo, code, addr, n_notes, new_filesz))
    return 0


if __name__ == "__main__":
    sys.exit(main())

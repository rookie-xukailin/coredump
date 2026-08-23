#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 riscv64 core 中被 gcore 截断的 NT_PRSTATUS 扩容为 gdb 可读布局。

gdb gcore 对 riscv64 只写了 336 字节（112 头 + 28 个寄存器）。实测 gdb 15.1
的 riscv core 寄存器段恰好要求 376 字节（112 + 32*8 + 8 对齐填充），其他
尺寸要么寄存器 <unavailable> 要么 gdb 直接段错误。本脚本在 note 段内原地
扩容：保留头部与已写寄存器，补零尾部 + fpvalid=1。

用法: fix_riscv_prstatus.py <core>
"""
import os
import struct
import sys

PT_NOTE = 4
FULL_SIZE = 376          # 112 + 32*8 + 8（实测 gdb 15.1 riscv 可接受尺寸）


def main():
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()
    if struct.unpack_from("<H", data, 18)[0] != 243:
        print("非 riscv core，跳过")
        return 0

    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    note_phdr_off = note_fileoff = None
    max_load_end = 0
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        p_off = struct.unpack_from("<Q", data, o + 8)[0]
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        if p_type == PT_NOTE:
            note_phdr_off, note_fileoff = o, p_off
        elif p_type == 1:
            max_load_end = max(max_load_end, p_off + p_filesz)

    off = note_fileoff
    patched = 0
    insertions = []      # (pos, bytes)
    while off + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from("<III", data, off)
        name = data[off + 12: off + 12 + namesz]
        desc_off = off + 12 + ((namesz + 3) & ~3)
        end = desc_off + ((descsz + 3) & ~3)
        if ntype == 1 and name.startswith(b"CORE") and descsz < FULL_SIZE \
                and descsz >= 112 + 8 * 5:
            # 截断的 prstatus：扩到 FULL_SIZE（头 112 保留，寄存器区原位，
            # 尾部补零，fpvalid=1）
            grow = FULL_SIZE - descsz
            tail = b"\x00" * (grow - 4) + struct.pack("<I", 1)
            insertions.append((desc_off + descsz, tail))
            # 改 note 头里的 descsz（namesz@0 descsz@4 ntype@8）
            data = data[:off + 4] + struct.pack("<I", FULL_SIZE) + data[off + 8:]
            patched += 1
        off = end

    if not patched:
        print("没有需要扩容的 NT_PRSTATUS")
        return 0

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from corepatch import insert_bytes
    for pos, payload in sorted(insertions, reverse=True):
        data = insert_bytes(data, pos, payload, elfclass=2, little=True)

    # PT_NOTE filesz 以 .shstrtab 起点为界
    new_filesz = len(data) - note_fileoff
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    if e_shoff and e_shstrndx < e_shnum:
        so = e_shoff + e_shstrndx * e_shentsize
        shstr_off = struct.unpack_from("<Q", data, so + 0x18)[0]
        if note_fileoff < shstr_off:
            new_filesz = shstr_off - note_fileoff
    with open(path, "wb") as f:
        f.write(data)
    with open(path, "r+b") as f:
        f.seek(note_phdr_off + 32)
        f.write(struct.pack("<Q", new_filesz))
    print("expanded %d NT_PRSTATUS to %d bytes (file=%d, note filesz=0x%x)"
          % (patched, FULL_SIZE, len(data), new_filesz))
    return 0


if __name__ == "__main__":
    sys.exit(main())

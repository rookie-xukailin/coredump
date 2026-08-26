#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core 文件中部插入字节时同步维护 ELF 头与节头表。

gdb 生成的 core 自带 section header table（note0/load/.shstrtab 等），
在 note 段内插入数据会平移其后内容，必须同步：
  - e_shoff >= 插入点 → 平移
  - 各节 sh_offset >= 插入点 → 平移
  - 覆盖插入点的节（如 note0）→ sh_size 增大
"""
import struct


def insert_bytes(data, pos, payload, elfclass=2, little=True):
    """在 data[pos] 前插入 payload，返回修复 ELF/节头后的新 bytes。"""
    endian = "<" if little else ">"
    delta = len(payload)
    sz = "Q" if elfclass == 2 else "I"
    shoff_f = 40 if elfclass == 2 else 32
    shent_f = 58 if elfclass == 2 else 46
    shnum_f = 60 if elfclass == 2 else 48

    e_shoff = struct.unpack_from(endian + sz, data, shoff_f)[0]
    if e_shoff:
        shentsize = struct.unpack_from(endian + "H", data, shent_f)[0]
        shnum = struct.unpack_from(endian + "H", data, shnum_f)[0]
        for i in range(shnum):
            so = e_shoff + i * shentsize
            if so + 64 > len(data):
                break
            sh_offset = struct.unpack_from(endian + sz, data, so + 0x18)[0]
            sh_size = struct.unpack_from(endian + sz, data, so + 0x20)[0]
            new_off, new_size = sh_offset, sh_size
            if sh_offset >= pos:
                new_off = sh_offset + delta
            if sh_offset < pos <= sh_offset + sh_size:
                new_size = sh_size + delta
            if new_off != sh_offset:
                data = data[:so + 0x18] + struct.pack(endian + sz, new_off) + data[so + 0x18 + (8 if elfclass == 2 else 4):]
            if new_size != sh_size:
                data = data[:so + 0x20] + struct.pack(endian + sz, new_size) + data[so + 0x20 + (8 if elfclass == 2 else 4):]
        if e_shoff >= pos:
            data = data[:shoff_f] + struct.pack(endian + sz, e_shoff + delta) + data[shoff_f + (8 if elfclass == 2 else 4):]
    return data[:pos] + payload + data[pos:]

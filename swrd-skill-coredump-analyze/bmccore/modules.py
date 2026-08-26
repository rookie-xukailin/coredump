# -*- coding: utf-8 -*-
"""模块表构建与 build-id 还原。

原理：内核默认 coredump_filter(0x33) 会转储每个文件映射的 ELF 头页，
因此能从 core 内存里直接读出每个 so 加载基址处的 ELF 头 -> 程序头 ->
PT_NOTE -> NT_GNU_BUILD_ID，拿它与编译机上产物的 build-id 精确配对。
"""
import struct

NT_GNU_BUILD_ID = 3
PT_NOTE = 4
PT_LOAD = 1


class Module(object):
    """core 中的一个已加载模块（可执行文件或 so）。"""

    def __init__(self, path, mappings, page_size):
        self.path = path
        self.mappings = mappings          # 该文件的 FileMapping 列表（可能多段）
        self.page_size = page_size
        # 加载基址 = 起始映射 - 文件偏移（NT_FILE 的 fofs 单位已换算为字节）
        first = min(mappings, key=lambda m: m.start)
        self.base = first.start - (first.fofs // page_size) * page_size
        self.build_id = None              # 从内存映像还原，十六进制串
        self.build_id_source = None       # 'core-image' / 说明

    @property
    def name(self):
        return self.path.rsplit("/", 1)[-1] if self.path else ""

    @property
    def size(self):
        return max(m.end for m in self.mappings) - min(m.start for m in self.mappings)

    def contains(self, addr):
        return any(m.contains(addr) for m in self.mappings)

    def __repr__(self):
        return "<Module %s base=0x%x bid=%s>" % (self.path, self.base, self.build_id)


def group_modules(core):
    """把 NT_FILE 的映射按文件路径合并成 Module 列表。"""
    page = 4096
    for m in core.file_mappings:
        # page size 可从 NT_FILE 头拿，但 corefile 已换算成字节，这里假定 4K
        break
    grouped = {}
    order = []
    for m in core.file_mappings:
        if m.path not in grouped:
            grouped[m.path] = []
            order.append(m.path)
        grouped[m.path].append(m)
    mods = [Module(p, grouped[p], page) for p in order]
    for mod in mods:
        mod.build_id = extract_build_id(core, mod)
    return mods


def _elf_class_endian(header):
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    ei_class = header[4]          # 1=32,2=64
    ei_data = header[5]           # 1=LE,2=BE
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    return ei_class, ei_data


def extract_build_id(core, module):
    """从 core 内存映像还原模块 build-id，失败返回 None。

    依赖该模块 ELF 头页被转储进 core（默认 coredump_filter 满足）。
    """
    hdr = core.read_mem(module.base, 64)
    ce = _elf_class_endian(hdr or b"")
    if not ce:
        return None
    ei_class, ei_data = ce
    endian = "<" if ei_data == 1 else ">"
    fmt_e = endian + ("HHI" if ei_class == 1 else "HHIQ")
    if len(hdr) < 20:
        return None
    e_phoff = struct.unpack_from(endian + ("I" if ei_class == 1 else "Q"), hdr, 28 if ei_class == 1 else 32)[0]
    e_phentsize, e_phnum = struct.unpack_from(endian + "HH", hdr, 42 if ei_class == 1 else 54)
    if e_phnum > 64 or e_phentsize == 0:
        return None
    ph = core.read_mem(module.base + e_phoff, e_phentsize * e_phnum)
    if ph is None:
        return None
    for i in range(e_phnum):
        off = i * e_phentsize
        p_type = struct.unpack_from(endian + "I", ph, off)[0]
        if p_type != PT_NOTE:
            continue
        if ei_class == 1:
            # ELF32: p_type(+0) p_offset(+4) p_vaddr(+8) p_paddr(+12) p_filesz(+16)
            p_offset = struct.unpack_from(endian + "I", ph, off + 4)[0]
            p_filesz = struct.unpack_from(endian + "I", ph, off + 16)[0]
        else:
            # ELF64: p_type(+0) p_flags(+4) p_offset(+8) p_vaddr(+16) p_paddr(+24)
            #        p_filesz(+32) p_memsz(+40) p_align(+48)
            p_offset = struct.unpack_from(endian + "Q", ph, off + 8)[0]
            p_filesz = struct.unpack_from(endian + "Q", ph, off + 32)[0]
        note_area = core.read_mem(module.base + p_offset, p_filesz)
        if note_area is None:
            continue
        bid = _find_build_id_note(note_area)
        if bid:
            return bid
    return None


def _find_build_id_note(buf):
    """在一段 PT_NOTE 字节里找 NT_GNU_BUILD_ID。"""
    off = 0
    while off + 12 <= len(buf):
        namesz, descsz, ntype = struct.unpack_from("<III", buf, off)
        off += 12
        name = buf[off:off + namesz]
        off += (namesz + 3) & ~3
        if ntype == NT_GNU_BUILD_ID and name.startswith(b"GNU"):
            return buf[off:off + descsz].hex()
        off += (descsz + 3) & ~3
    return None

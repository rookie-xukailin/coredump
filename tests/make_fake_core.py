# -*- coding: utf-8 -*-
"""合成 ELF core 与合成产物（带符号表的 so/可执行文件）生成器。

用途：在任意开发机（含 Windows）上单测 bmccore 的解析/扫描/堆走查逻辑，
不依赖 Linux、不依赖交叉工具链。

生成的 core 严格按内核 fs/binfmt_elf.c 的 note 布局手工构造，
布局依据与 bmccore/corefile.py 的解析端互为镜像。
"""
import struct

PT_LOAD = 1
PT_NOTE = 4

NT_PRSTATUS = 1
NT_PRPSINFO = 3
NT_AUXV = 6
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494c45
NT_GNU_BUILD_ID = 3

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOTE = 7

STT_FUNC = 2
STB_GLOBAL = 1


# ---------------------------------------------------------------------------
# 基础小工具
# ---------------------------------------------------------------------------

def _pad4(n):
    return (4 - n % 4) % 4


def make_note(ntype, name, desc):
    """构造一条 note：namesz/descsz/type + name(4对齐) + desc(4对齐)。"""
    nb = name.encode() + b"\x00"
    out = struct.pack("<III", len(nb), len(desc), ntype)
    out += nb + b"\x00" * _pad4(len(nb))
    out += desc + b"\x00" * _pad4(len(desc))
    return out


def _prstatus(arch, signo, cursig, tid, regs_by_name):
    """按内核布局拼 NT_PRSTATUS desc。"""
    vals = [regs_by_name.get(n, 0) for n in arch.regnames]
    if arch.elfclass == 64:
        b = struct.pack("<III", signo, 0, 0)
        b += struct.pack("<h", cursig) + b"\x00\x00"
        b += struct.pack("<QQ", 0, 0)                       # sigpend / sighold
        b += struct.pack("<iiii", tid, tid + 1, tid, tid)   # pid ppid pgrp sid
        b += struct.pack("<8q", *([0] * 8))                  # 4 组 timeval(64位)
        b += struct.pack("<" + "Q" * len(vals), *vals)
        b += struct.pack("<i", 1)                           # fpvalid
    else:
        b = struct.pack("<III", signo, 0, 0)
        b += struct.pack("<h", cursig) + b"\x00\x00"
        b += struct.pack("<II", 0, 0)
        b += struct.pack("<iiii", tid, tid + 1, tid, tid)
        b += struct.pack("<8i", *([0] * 8))                  # 4 组 timeval(32位)
        b += struct.pack("<" + "I" * len(vals), *vals)
        b += struct.pack("<i", 1)
    return b


def _prpsinfo(elfclass, fname, psargs):
    """64位布局: chars4+pad4+flag8+uid..sid(6*4)+fname16+psargs80 = 136。"""
    fname_b = fname.encode()[:15] + b"\x00"
    fname_b += b"\x00" * (16 - len(fname_b))
    psargs_b = psargs.encode()[:79] + b"\x00"
    psargs_b += b"\x00" * (80 - len(psargs_b))
    if elfclass == 64:
        return (struct.pack("<BBBB", 82, 82, 0, 0) + b"\x00" * 4
                + struct.pack("<Q", 0)
                + struct.pack("<IIIIII", 1000, 1000, 1, 1, 1, 1)
                + fname_b + psargs_b)
    return (struct.pack("<BBBB", 82, 82, 0, 0)
            + struct.pack("<I", 0)
            + struct.pack("<IIIIII", 1000, 1000, 1, 1, 1, 1)
            + fname_b + psargs_b)


def tid_pad(n):
    return n


def _nt_file(elfclass, entries):
    """entries: list[(start, end, fofs_pages, path)]"""
    fmt_long = "I" if elfclass == 32 else "Q"
    b = struct.pack("<" + fmt_long * 2, len(entries), 4096)
    for start, end, fofs, _p in entries:
        b += struct.pack("<" + fmt_long * 3, start, end, fofs)
    for _s, _e, _f, p in entries:
        b += p.encode() + b"\x00"
    return b


def _auxv(elfclass, pairs):
    fmt = "I" if elfclass == 32 else "Q"
    b = b""
    for k, v in pairs:
        b += struct.pack("<" + fmt * 2, k, v)
    b += struct.pack("<" + fmt * 2, 0, 0)
    return b


def _siginfo(elfclass, signo, code, addr):
    b = struct.pack("<iii", signo, 0, code)
    if elfclass == 64:
        b += b"\x00" * 4 + struct.pack("<Q", addr)
    else:
        b += struct.pack("<I", addr)
    return b


# ---------------------------------------------------------------------------
# core 生成
# ---------------------------------------------------------------------------

def build_core(path, arch, threads, regions, file_maps=None,
               auxv_pairs=None, siginfo=None, fname="remotexdp", psargs=None):
    """生成合成 core。

    参数:
      arch: bmccore.arch.ArchInfo
      threads: list[dict(tid=, cursig=, regs={regname: value, ...})]  第0个是崩溃线程
      regions: list[(vaddr, rwx_flags, bytes)]        -> PT_LOAD
      file_maps: list[(start, end, fofs_pages, path)] -> NT_FILE
      auxv_pairs: list[(key, value)]
      siginfo: dict(signo=, code=, addr=)
    """
    elfclass = arch.elfclass
    e_phnum = 1 + len(regions)                     # 1 个 PT_NOTE + N 个 PT_LOAD
    ehsize = 64 if elfclass == 64 else 52
    phentsize = 56 if elfclass == 64 else 32

    notes = b""
    for i, t in enumerate(threads):
        notes += make_note(NT_PRSTATUS, "CORE",
                           _prstatus(arch, t.get("sig", 11), t.get("cursig", 11),
                                     t["tid"], t["regs"]))
    notes += make_note(NT_PRPSINFO, "CORE", _prpsinfo(elfclass, fname,
                                                      psargs or ("/usr/bin/%s --run" % fname)))
    if auxv_pairs:
        notes += make_note(NT_AUXV, "CORE", _auxv(elfclass, auxv_pairs))
    if siginfo:
        notes += make_note(NT_SIGINFO, "CORE",
                           _siginfo(elfclass, siginfo["signo"], siginfo.get("code", 1),
                                    siginfo.get("addr", 0)))
    if file_maps:
        notes += make_note(NT_FILE, "CORE", _nt_file(elfclass, file_maps))

    # 布局: ehdr + phdrs + notes + loads
    phoff = ehsize
    note_off = phoff + e_phnum * phentsize
    loads_off = note_off + len(notes)

    e_ident = b"\x7fELF" + bytes([1 if elfclass == 32 else 2, 1, 1, 0]) + b"\x00" * 8
    if elfclass == 64:
        ehdr = e_ident + struct.pack(
            "<HHIQQQIHHHHHH",
            4,                    # e_type = ET_CORE
            arch.machine,
            1,                    # e_version
            0,                    # e_entry
            phoff, 0,             # e_phoff, e_shoff
            0x05000000 if arch.machine == 40 else 0,   # e_flags
            ehsize, phentsize, e_phnum, 0, 0, 0)
        phdr_note = struct.pack("<IIQQQQQQ", PT_NOTE, 0, note_off, 0, 0,
                                len(notes), len(notes), 0)
        load_phdrs = [struct.pack("<IIQQQQQQ", PT_LOAD, fl, off, va, va,
                                  len(data), len(data), 0x1000)
                      for (va, fl, data), off in _load_offsets(regions, loads_off)]
    else:
        ehdr = e_ident + struct.pack(
            "<HHIIIIIHHHHHH",
            4, arch.machine, 1, 0, phoff, 0,
            0x05000000 if arch.machine == 40 else 0,
            ehsize, phentsize, e_phnum, 0, 0, 0)
        phdr_note = struct.pack("<IIIIIIII", PT_NOTE, note_off, 0, 0,
                                len(notes), len(notes), 0, 4)
        load_phdrs = [struct.pack("<IIIIIIII", PT_LOAD, off, va, va,
                                  len(data), len(data), fl, 0x1000)
                      for (va, fl, data), off in _load_offsets(regions, loads_off)]

    blob = ehdr + phdr_note + b"".join(load_phdrs) + notes
    for (va, fl, data), off in _load_offsets(regions, loads_off):
        pad = off - len(blob)
        assert pad >= 0, "内部布局错误"
        blob += b"\x00" * pad + data

    with open(path, "wb") as f:
        f.write(blob)
    return path


def _load_offsets(regions, base):
    """给每个 region 分配文件内偏移（自然对齐到8）。"""
    out = []
    cur = base
    for va, fl, data in regions:
        cur = (cur + 7) & ~7
        out.append(((va, fl, data), cur))
        cur += len(data)
    return out


# ---------------------------------------------------------------------------
# 合成产物（带符号表的 so）生成
# ---------------------------------------------------------------------------
# 产物布局: ehdr + phdr(PT_LOAD覆盖全文件, PT_NOTE=build-id) + .text + note + symtab/strtab/shstrtab + shdrs

def build_artifact(path, elfclass, machine, text_bytes, funcs,
                   build_id=b"\x11\x22\x33\x44\x55\x66\x77\x88", soname=None):
    """生成带 .symtab 与 build-id 的 ET_DYN ELF。

    funcs: list[(name, vaddr, size)]，vaddr 相对基址（st_value）。
    text_bytes: .text 段内容（合成指令，供栈扫描验证用）。
    """
    ehsize = 64 if elfclass == 64 else 52
    phentsize = 56 if elfclass == 64 else 32
    nphdr = 3  # PT_LOAD + PT_NOTE + (PT_DYNAMIC 可省，用占位 NULL) -> 用 2 个真实 + 1 NULL
    phoff = ehsize
    text_off = phoff + nphdr * phentsize
    text_size = len(text_bytes)
    note_off = text_off + text_size
    note = make_note(NT_GNU_BUILD_ID, "GNU", build_id)
    note_align_off = (note_off + 7) & ~7
    note_off = note_align_off
    note_blob = b"\x00" * (note_off - (text_off + text_size)) + note

    # 符号表
    strtab = b"\x00"
    syms = []
    if elfclass == 64:
        syms.append(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
    else:
        syms.append(struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0))
    for name, vaddr, size in funcs:
        st_name = len(strtab)
        strtab += name.encode() + b"\x00"
        if elfclass == 64:
            syms.append(struct.pack("<IBBHQQ", st_name, (STB_GLOBAL << 4) | STT_FUNC, 0, 1, vaddr, size))
        else:
            syms.append(struct.pack("<IIIBBH", st_name, vaddr, size, (STB_GLOBAL << 4) | STT_FUNC, 0, 1))
    symtab = b"".join(syms)
    if soname:
        strtab += soname.encode() + b"\x00"

    symtab_off = note_off + len(note)
    symtab_off = (symtab_off + 7) & ~7
    sym_pad = b"\x00" * (symtab_off - note_off - len(note))
    strtab_off = symtab_off + len(symtab)
    shstrtab = b"\x00" + b".text\x00" + b".symtab\x00" + b".strtab\x00" + b".shstrtab\x00" + b".note.gnu.build-id\x00"
    shstrtab_off = strtab_off + len(strtab)
    shoff = shstrtab_off + len(shstrtab)
    shoff = (shoff + 7) & ~7
    sh_pad = b"\x00" * (shoff - shstrtab_off - len(shstrtab))
    sym_entsize = 24 if elfclass == 64 else 16
    sh_entsize = 64 if elfclass == 64 else 40
    n_sh = 5   # NULL, .text, .symtab, .strtab, .shstrtab (+note 并入 text 前省略)

    def sh_name_of(s):
        return {".text": 1, ".symtab": 7, ".strtab": 15, ".shstrtab": 23}[s]

    if elfclass == 64:
        shdrs = [struct.pack("<IIQQQQIIQQ", 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
                 struct.pack("<IIQQQQIIQQ", sh_name_of(".text"), SHT_PROGBITS, 0x6,
                             0, text_off, text_size, 0, 0, 16, 0),
                 struct.pack("<IIQQQQIIQQ", sh_name_of(".symtab"), SHT_SYMTAB, 0,
                             0, symtab_off, len(symtab), 3, 1 + len(funcs), 8, sym_entsize),
                 struct.pack("<IIQQQQIIQQ", sh_name_of(".strtab"), SHT_STRTAB, 0,
                             0, strtab_off, len(strtab), 0, 0, 1, 0),
                 struct.pack("<IIQQQQIIQQ", sh_name_of(".shstrtab"), SHT_STRTAB, 0,
                             0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)]
        phdrs = [struct.pack("<IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, shoff, shoff, 0x1000),
                 struct.pack("<IIQQQQQQ", PT_NOTE, 4, note_off, note_off, note_off,
                             len(note), len(note), 4),
                 struct.pack("<IIQQQQQQ", 0, 0, 0, 0, 0, 0, 0, 0)]
        ehdr = (b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
                + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, phoff, shoff,
                              0, ehsize, phentsize, nphdr, sh_entsize, n_sh, 4))
    else:
        shdrs = [struct.pack("<IIIIIIIIII", 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
                 struct.pack("<IIIIIIIIII", sh_name_of(".text"), SHT_PROGBITS, 0x6,
                             0, text_off, text_size, 0, 0, 16, 0),
                 struct.pack("<IIIIIIIIII", sh_name_of(".symtab"), SHT_SYMTAB, 0,
                             0, symtab_off, len(symtab), 3, 1 + len(funcs), 4, sym_entsize),
                 struct.pack("<IIIIIIIIII", sh_name_of(".strtab"), SHT_STRTAB, 0,
                             0, strtab_off, len(strtab), 0, 0, 1, 0),
                 struct.pack("<IIIIIIIIII", sh_name_of(".shstrtab"), SHT_STRTAB, 0,
                             0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)]
        phdrs = [struct.pack("<IIIIIIII", PT_LOAD, 0, 0, 0, shoff, shoff, 5, 0x1000),
                 struct.pack("<IIIIIIII", PT_NOTE, note_off, note_off, note_off, len(note), len(note), 4, 4),
                 struct.pack("<IIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0)]
        ehdr = (b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
                + struct.pack("<HHIIIIIHHHHHH", 3, machine, 1, 0, phoff, shoff,
                              0, ehsize, phentsize, nphdr, sh_entsize, n_sh, 4))

    parts = [ehdr, b"".join(phdrs), text_bytes, note_blob, sym_pad, symtab, strtab, shstrtab, sh_pad, b"".join(shdrs)]
    with open(path, "wb") as f:
        f.write(b"".join(parts))
    return path

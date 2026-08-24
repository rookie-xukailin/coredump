# -*- coding: utf-8 -*-
"""corefile.py / modules.py 解析层单测：三架构合成 core 全字段校验。"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "swrd-skill-coredump-analyze"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_fake_core as mfc
from bmccore.arch import ARM32, ARM64, RISCV64
from bmccore.corefile import CoreFile
from bmccore.modules import group_modules

EXE_BASE = 0x10000
LIB_BASE = 0x800000
STACK_TOP = 0x7fff0000


def _make_core(tmp, arch, extra_regions=None):
    stack = [(t["regs"].get("sp", STACK_TOP - 0x100) - 0x200, STACK_TOP, b"\xAA" * 0x1000)
             for t in []]  # 占位不用
    regions = [
        (EXE_BASE, 5, b"\x7fELF" + b"\x11" * 0x1000),          # r-x 主程序页
        (LIB_BASE, 6, b"\x00" * 0x800),                        # rw-
        (STACK_TOP - 0x2000, 6, b"\xBB" * 0x2000),             # 栈
    ]
    if extra_regions:
        regions.extend(extra_regions)

    if arch is ARM32:
        t0 = dict(tid=6759, cursig=11, regs={"pc": 0x10084, "sp": STACK_TOP - 0x800,
                                             "lr": 0x10040, "r0": 0x1})
        t1 = dict(tid=6760, cursig=0, regs={"pc": 0x10088, "sp": STACK_TOP + 0x100})
    elif arch is ARM64:
        t0 = dict(tid=6759, cursig=11, regs={"pc": 0x10084, "sp": STACK_TOP - 0x800,
                                             "x30": 0x10040, "x0": 0x1})
        t1 = dict(tid=6760, cursig=0, regs={"pc": 0x10088, "sp": STACK_TOP + 0x100})
    else:
        t0 = dict(tid=6759, cursig=11, regs={"pc": 0x10084, "sp": STACK_TOP - 0x800,
                                             "ra": 0x10040, "a0": 0x1})
        t1 = dict(tid=6760, cursig=0, regs={"pc": 0x10088, "sp": STACK_TOP + 0x100})

    file_maps = [
        (EXE_BASE, EXE_BASE + 0x1000, 0, "/usr/bin/remotexdp"),
        (LIB_BASE, LIB_BASE + 0x800, 0, "/usr/lib/libfoo.so"),
    ]
    path = os.path.join(tmp, "core_test_%s" % arch.name)
    mfc.build_core(path, arch, [t0, t1], regions,
                   file_maps=file_maps,
                   auxv_pairs=[(3, EXE_BASE + 0x40)],          # AT_PHDR
                   siginfo={"signo": 11, "code": 2, "addr": 0x0badc0de},
                   fname="remotexdp", psargs="/usr/bin/remotexdp --daemon")
    return path


def test_parse_all_archs():
    for arch in (ARM32, ARM64, RISCV64):
        tmp = tempfile.mkdtemp()
        try:
            core = CoreFile(_make_core(tmp, arch))
            assert core.arch.name == arch.name, core.arch.name
            assert core.elfclass == arch.elfclass
            assert len(core.threads) == 2
            t0 = core.crash_thread
            assert t0.is_crash and t0.tid == 6759
            assert t0.pc == 0x10084
            assert t0.sp == STACK_TOP - 0x800
            assert t0.lr == 0x10040
            assert core.threads[1].tid == 6760
            # NT_FILE
            assert len(core.file_mappings) == 2
            assert core.file_mappings[0].path == "/usr/bin/remotexdp"
            # auxv -> exe 判定
            assert core.exe_path == "/usr/bin/remotexdp"
            # siginfo
            assert core.siginfo["addr"] == 0x0badc0de
            assert core.siginfo["signo"] == 11
            # prpsinfo
            assert core.prpsinfo["fname"] == "remotexdp"
            # 内存读取
            assert core.read_mem(STACK_TOP - 0x2000, 4) == b"\xBB" * 4
            assert core.read_mem(EXE_BASE, 4) == b"\x7fELF"
            assert core.read_mem(STACK_TOP, 4) is None      # 栈区外
            # 代码地址判定
            assert core.is_code_addr(EXE_BASE + 0x10)
            assert not core.is_code_addr(STACK_TOP - 0x100)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def test_arm32_thumb_regs():
    """ARM32 全 18 个寄存器名都能取到。"""
    tmp = tempfile.mkdtemp()
    try:
        core = CoreFile(_make_core(tmp, ARM32))
        t0 = core.crash_thread
        for name in ("r0", "r10", "fp", "ip", "cpsr", "orig_r0"):
            assert name in t0.regs, name
        assert t0.regs["r0"] == 1
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_build_id_extraction():
    """从 core 内存映像还原模块 build-id。"""
    tmp = tempfile.mkdtemp()
    try:
        # 生成带 build-id 的合成 so，取其前 4KB 放进 core 的映射处
        art = os.path.join(tmp, "libfoo.so")
        mfc.build_artifact(art, 64, 183, b"\x90" * 0x400,
                           [("foo_init", 0x1000, 0x100)],
                           build_id=b"\xde\xad\xbe\xef\x01\x02\x03\x04",
                           soname="libfoo.so")
        with open(art, "rb") as f:
            art_bytes = f.read(4096)

        lib_base2 = 0x900000
        regions = [(lib_base2, 6, art_bytes)]
        arch = ARM64
        t0 = dict(tid=1, cursig=11, regs={"pc": 0x1000, "sp": 0x7fff0000 - 0x100})
        path = os.path.join(tmp, "core_bid")
        mfc.build_core(path, arch, [t0], regions,
                       file_maps=[(lib_base2, lib_base2 + len(art_bytes), 0,
                                   "/usr/lib/libfoo.so")])
        core = CoreFile(path)
        mods = group_modules(core)
        assert len(mods) == 1
        assert mods[0].base == lib_base2
        assert mods[0].build_id == b"\xde\xad\xbe\xef\x01\x02\x03\x04".hex(), mods[0].build_id
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_capability():
    tmp = tempfile.mkdtemp()
    try:
        core = CoreFile(_make_core(tmp, ARM64))
        caps = core.capability()
        assert caps["threads"] == 2
        assert caps["has_file_mappings"]
        assert caps["has_auxv"]
        assert caps["anon_rw_bytes"] > 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
        print("PASS %s" % fn.__name__)

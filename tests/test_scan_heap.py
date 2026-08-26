# -*- coding: utf-8 -*-
"""栈扫描 + 堆取证 + 符号配对 单测。

场景构造：合成 ARM64 core，栈上埋 3 个"返回地址"（真实指向合成 so 的 .text
里 BL 指令之后），外加 2 个干扰值（代码区随机值、非代码区值），
验证扫描器只认 call 后的地址并给出正确置信度。
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "swrd-skill-coredump-analyze"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_fake_core as mfc
from bmccore.arch import ARM64, ARM32
from bmccore.corefile import CoreFile
from bmccore.modules import group_modules
from bmccore import scan as scan_mod
from bmccore import symbols as symbols_mod
from bmccore import heap as heap_mod

LIB_BASE = 0x100000
STACK_BASE = 0x7ffe0000
STACK_SIZE = 0x2000
HEAP_BASE = 0x400000


def _bl_at(offset):
    """AArch64 BL 指令（imm26=0）：0x94000000。"""
    return struct.pack("<I", 0x94000000)


def _build_arm64_env(tmp, corrupt_heap=False, stack_values=None):
    """搭一个带 so 产物 + 栈 + 可选损坏堆 的 ARM64 core 测试环境。"""
    # 合成 so：.text 里放若干 BL/非BL 指令
    text = b""
    text += b"\x1f\x20\x03\xd5"          # nop        (+0x000)
    text += _bl_at(0)                     # BL         (+0x004) -> ret addr +0x008
    text += _bl_at(0)                     # BL         (+0x008) -> ret addr +0x00c
    text += b"\x1f\x20\x03\xd5"          # nop        (+0x00c)
    text += _bl_at(0)                     # BL         (+0x010) -> ret addr +0x014
    text += b"\x1f\x20\x03\xd5" * 3       # nop        (+0x014..)
    text += struct.pack("<I", 0xD63F0360)  # BLR x27    (+0x020) -> ret addr +0x024
    text += b"\x1f\x20\x03\xd5" * 4
    text_vaddr = 0x1000                   # .text 在 so 内的偏移
    funcs = [("crash_now", text_vaddr + 0x4, 0x8),
             ("helper_a", text_vaddr + 0x10, 0x10),
             ("helper_b", text_vaddr + 0x20, 0x8),
             ("innocent", text_vaddr + 0x30, 0x10)]
    art = os.path.join(tmp, "libfoo.so")
    mfc.build_artifact(art, 64, 183, text, funcs,
                       build_id=b"\xaa" * 8, soname="libfoo.so")
    with open(art, "rb") as f:
        art_page = f.read(4096)

    # 栈内容：SP 在 STACK_BASE+0x100 处
    sp = STACK_BASE + 0x100
    ret1 = LIB_BASE + text_vaddr + 0x008   # BL 后
    ret2 = LIB_BASE + text_vaddr + 0x00c   # BL 后
    ret3 = LIB_BASE + text_vaddr + 0x014   # BL 后
    ret4 = LIB_BASE + text_vaddr + 0x024   # BLR 后
    noise_in_text = LIB_BASE + text_vaddr + 0x030   # nop 后（应被拒绝）
    noise_not_code = 0x12345678
    values = stack_values if stack_values is not None else [
        0xdeadbeef, ret1, noise_not_code, noise_in_text, ret2, 0, ret3, 0, ret4]
    stack_bytes = b""
    stack_bytes += b"\xcc" * 0x100                 # SP 以下（不扫）
    for v in values:
        stack_bytes += struct.pack("<Q", v)
    stack_bytes += b"\xcc" * (STACK_SIZE - len(stack_bytes))
    assert len(stack_bytes) <= STACK_SIZE

    # 堆：glibc 64位 chunk 链（word=8）
    def chunk(size, inuse_next_prev=1, payload=b""):
        return struct.pack("<QQ", 0, size | inuse_next_prev) + payload.ljust(size - 16, b"\x00")

    heap = chunk(0x110, 1, b"HEAPDATA-A" * 8)      # chunk1: in-use
    heap += chunk(0x90, 1, b"ptrs..")              # chunk2: in-use
    if corrupt_heap:
        heap += struct.pack("<QQ", 0, 0x7b)        # 坏 size（0x78<0x20? 0x7b 剥位=0x78 未按16对齐）
        heap += b"\x00" * 0x40
    else:
        heap += chunk(0x80, 1)
    heap_bytes = heap + b"\x00" * (0x1000 - len(heap))

    regions = [
        (LIB_BASE, 5, art_page),                    # so ELF 头页(r-x)
        (LIB_BASE + text_vaddr, 5, text),           # so .text(r-x)
        (HEAP_BASE, 6, heap_bytes),                 # 堆(rw-)
        (STACK_BASE, 6, stack_bytes),               # 栈(rw-)
    ]
    t0 = dict(tid=6759, cursig=11,
              regs={"pc": LIB_BASE + text_vaddr + 0x4, "sp": sp,
                    "x30": LIB_BASE + text_vaddr + 0x008, "x0": 0x2})
    t1 = dict(tid=6761, cursig=0,
              regs={"pc": LIB_BASE + text_vaddr + 0x30, "sp": sp + 0x800})
    core_path = os.path.join(tmp, "core_scan")
    mfc.build_core(core_path, ARM64, [t0, t1], regions,
                   file_maps=[(LIB_BASE, LIB_BASE + 0x2000, 0, "/usr/lib/libfoo.so")],
                   auxv_pairs=[(3, LIB_BASE + 0x40)],
                   siginfo={"signo": 11, "code": 1, "addr": 0x3000},
                   fname="remotexdp")
    return core_path, art


def _match_env(tmp, core_path, art):
    core = CoreFile(core_path)
    mods = group_modules(core)
    arts = symbols_mod.scan_artifacts(tmp)
    matches = symbols_mod.match_modules(mods, arts)
    return core, matches


def test_stack_scan_validates_calls():
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        core, matches = _match_env(tmp, core_path, art)
        assert len(matches) == 1 and matches[0].status == "matched", \
            (matches[0].status, matches[0].note)

        resolver = symbols_mod.SymbolResolver()
        t0 = core.crash_thread
        sr = scan_mod.scan_thread(core, ARM64, t0, matches, resolver)

        vals = [f.value for f in sr.frames]
        # 4 个 call 后地址全部命中
        for want in (LIB_BASE + 0x1008, LIB_BASE + 0x100c,
                     LIB_BASE + 0x1014, LIB_BASE + 0x1024):
            assert want in vals, (hex(want), [hex(v) for v in vals])
        # nop 后的代码地址被 call 验证拒绝
        assert LIB_BASE + 0x1030 not in vals
        # 非代码区值不出现
        assert 0x12345678 not in vals
        # 全部为"确认"（.text 从产物可读）
        assert all(f.confidence == "确认" for f in sr.frames)
        # 符号定位
        funcs = {f.value: f.func for f in sr.frames}
        assert funcs[LIB_BASE + 0x1008] == "crash_now"     # +0x008 落 crash_now(0x1004+8)
        assert funcs[LIB_BASE + 0x1014] == "helper_a"
        assert funcs[LIB_BASE + 0x1024] == "helper_b"
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_stack_overflow_detection():
    """SP 落在栈区底边界附近 -> 溢出判定。"""
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(
            tmp, stack_values=[LIB_BASE + 0x1008])
        core, matches = _match_env(tmp, core_path, art)
        t = core.crash_thread
        t.regs["sp"] = STACK_BASE + 0x80          # 距底边界 128 字节
        sr = scan_mod.scan_thread(core, ARM64, t, matches)
        assert sr.overflow and "栈溢出" in sr.overflow
        # SP 完全不在任何段
        t.regs["sp"] = 0x100
        sr2 = scan_mod.scan_thread(core, ARM64, t, matches)
        assert sr2.overflow and "任何已转储" in sr2.overflow
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_arm32_thumb_bit():
    """ARM32 Thumb 返回地址 bit0=1 也能定位。"""
    tmp = tempfile.mkdtemp()
    try:
        # 布局: +0 Thumb nop×2, +4 Thumb-2 BL(hw1=0xF000,hw2=0xE800) ret=+8,
        #       +8 ARM BL ret=+12
        text = struct.pack("<HH", 0xBF00, 0xBF00)
        text += struct.pack("<HH", 0xF000, 0xE800)
        text += struct.pack("<I", 0xEB000000)
        text += struct.pack("<I", 0xE1A00000)
        text_vaddr = 0x1000
        art = os.path.join(tmp, "libt.so")
        mfc.build_artifact(art, 32, 40, text, [("thumb_fn", text_vaddr, 0x8)],
                           build_id=b"\xbb" * 8)
        art_page = open(art, "rb").read(4096)

        sp = 0x7ffe0100
        thumb_ret = LIB_BASE + text_vaddr + 8 + 1     # bit0=1
        arm_ret = LIB_BASE + text_vaddr + 12
        stack = b"\xcc" * 0x100
        for v in (thumb_ret, arm_ret, 0x9999):
            stack += struct.pack("<I", v)
        stack += b"\xcc" * (0x1000 - len(stack))
        t0 = dict(tid=1, cursig=11,
                  regs={"pc": LIB_BASE + text_vaddr + 4, "sp": sp, "lr": arm_ret})
        core_path = os.path.join(tmp, "core_t")
        mfc.build_core(core_path, ARM32, [t0],
                       [(LIB_BASE, 5, art_page),
                        (LIB_BASE + text_vaddr, 5, text),
                        (0x7ffe0000, 6, stack)],
                       file_maps=[(LIB_BASE, LIB_BASE + 0x2000, 0, "/usr/lib/libt.so")])
        core = CoreFile(core_path)
        mods = group_modules(core)
        matches = symbols_mod.match_modules(mods, symbols_mod.scan_artifacts(tmp))
        resolver = symbols_mod.SymbolResolver()
        sr = scan_mod.scan_thread(core, ARM32, core.crash_thread, matches, resolver)
        vals = [f.value for f in sr.frames]
        assert thumb_ret in vals, [hex(v) for v in vals]
        assert arm_ret in vals
        assert all(f.confidence == "确认" for f in sr.frames)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_heap_walk_and_corruption():
    tmp = tempfile.mkdtemp()
    try:
        # 正常堆
        core_path, art = _build_arm64_env(tmp, corrupt_heap=False)
        core, matches = _match_env(tmp, core_path, art)
        heaps = heap_mod.find_heap_regions(core, core.threads)
        # 匿名rw且非栈：堆 + (栈区 t1 半段? t1 sp 在栈区内, 整个栈区被剔除)
        assert heaps, "应当找到堆区"
        target = [h for h in heaps if h.vaddr == HEAP_BASE][0]
        chunks, corrs, _notes = heap_mod.walk_region(target, 64)
        assert not corrs, corrs
        assert len(chunks) == 3
        assert chunks[0].size == 0x110 and chunks[0].inuse is True
        assert chunks[1].size == 0x90

        # probe
        c, off = heap_mod.probe(chunks, HEAP_BASE + 0x10, HEAP_BASE)
        assert c is chunks[0] and off == 0x10

        # 损坏堆
        core_path2, _ = _build_arm64_env(tmp, corrupt_heap=True)
        core2 = CoreFile(core_path2)
        heaps2 = [h for h in heap_mod.find_heap_regions(core2, core2.threads)
                  if h.vaddr == HEAP_BASE]
        chunks2, corrs2, _ = heap_mod.walk_region(heaps2[0], 64)
        assert len(corrs2) == 1
        assert corrs2[0].prev is chunks2[-1]
        assert corrs2[0].prev.size == 0x90
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_heap_fingerprint_and_searchref():
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp, corrupt_heap=False)
        core, matches = _match_env(tmp, core_path, art)
        # ascii 指纹
        fp = heap_mod.fingerprint(b"SENSOR-12\0\0\0\0\0\0\0\0")
        assert fp and fp.kind == "ascii" and "SENSOR-12" in fp.desc
        # 全零
        fp0 = heap_mod.fingerprint(b"\x00" * 32)
        assert fp0.kind == "zeros"
        # searchref：栈上第4个qword(0xdeadbeef)不是指针；构造指向堆的指针
        sp = core.crash_thread.sp
        region = core.region_of(sp)
        data = bytearray(region.data)
        # 栈 SP+0x88 位置写一个指向 HEAP_BASE+0x20 的指针
        target_ptr = struct.pack("<Q", HEAP_BASE + 0x20)
        off = (sp + 0x88 - region.vaddr)
        data[off:off + 8] = target_ptr
        region.data = bytes(data)
        hits = heap_mod.searchref(core, HEAP_BASE + 0x10, HEAP_BASE + 0x60)
        assert any(v == HEAP_BASE + 0x20 for _w, v in hits), hits
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_symbols_match_byname_fallback():
    """core 中模块无 build-id 时按文件名配对（降置信）。"""
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        core = CoreFile(core_path)
        mods = group_modules(core)
        # 人为抹掉 build-id 模拟无法还原
        mods[0].build_id = None
        matches = symbols_mod.match_modules(mods, symbols_mod.scan_artifacts(tmp))
        assert matches[0].status == "byname"
        assert "build-id" in matches[0].note or "文件名" in matches[0].note
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
        print("PASS %s" % fn.__name__)

# -*- coding: utf-8 -*-
"""技能3：glibc 堆取证（治"内存被踩，找凶手"）。

纯 chunk 头走查（prev_size/size 链），不依赖 main_arena 符号：
  从堆区起点逐 chunk 前进，size 字段异常处即损坏点；
  被踩坏的往往不是肇事块——重点怀疑其前一个 chunk（越界写穿模式）。
searchref: 全进程内存搜"谁拿着指向受害区的指针"。
内容指纹: 被踩区域的字节特征（字符串/魔数/重复模式）直接指向肇事模块。
"""
import re
import struct

_MIN_SIZE = {32: 0x10, 64: 0x20}
_ALIGN = {32: 8, 64: 16}
FLAG_BITS = 7                     # PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA


class Chunk(object):
    def __init__(self, offset, size, flags):
        self.offset = offset      # 相对堆区起点
        self.size = size          # 剥离标志位后的 size
        self.flags = flags
        self.inuse = None         # 由下一块 PREV_INUSE 推出

    def __repr__(self):
        return "chunk@+0x%x size=0x%x flags=%d%s" % (
            self.offset, self.size, self.flags,
            "" if self.inuse is None else (" inuse" if self.inuse else " free"))


class Corruption(object):
    def __init__(self, offset, size_value, reason, prev=None):
        self.offset = offset
        self.size_value = size_value
        self.reason = reason
        self.prev = prev          # 前一个 chunk（越界嫌疑块）

    def __repr__(self):
        return "corruption@+0x%x size=0x%x %s" % (self.offset, self.size_value, self.reason)


class Fingerprint(object):
    def __init__(self, desc, kind):
        self.desc = desc
        self.kind = kind          # ascii / pattern / zeros / magic / unknown


class HeapResult(object):
    def __init__(self):
        self.regions = []             # [(desc, chunks)]
        self.corruptions = []
        self.region_desc = ""
        self.references = []          # searchref 结果 [(where, value)]
        self.fingerprints = []
        self.notes = []

    @property
    def has_heap(self):
        return bool(self.regions)


# ---------------------------------------------------------------------------
# 堆区发现
# ---------------------------------------------------------------------------

def find_heap_regions(core, threads):
    """匿名可读写且被转储的段，剔除各线程栈。"""
    stack_regions = set()
    for t in threads:
        r = core.region_of(t.sp)
        if r:
            stack_regions.add(id(r))
    heaps = []
    for r in core.regions:
        if not r.readable or not r.write_bit:
            continue
        if id(r) in stack_regions:
            continue
        if any(m.start <= r.vaddr < m.end for m in core.file_mappings):
            continue              # 文件映射（如 so 的数据段）不算堆
        heaps.append(r)
    return heaps


# ---------------------------------------------------------------------------
# chunk 链走查
# ---------------------------------------------------------------------------

def walk_region(region, elfclass):
    """走查一个堆区。返回 (chunks, corruptions, notes)。"""
    word = 4 if elfclass == 32 else 8
    minsz = _MIN_SIZE[elfclass]
    align = _ALIGN[elfclass]
    fmt = "<I" if word == 4 else "<Q"
    data = region.data
    end = len(data)
    cur = 0
    chunks = []
    corruptions = []
    notes = []
    guard = 0
    while cur + 2 * word <= end:
        guard += 1
        if guard > 200000:
            notes.append("chunk 数量超限，提前终止（可能是误入非堆数据）")
            break
        size_raw = struct.unpack_from(fmt, data, cur + word)[0]
        flags = size_raw & FLAG_BITS
        size = size_raw & ~FLAG_BITS
        if size == 0:
            # top chunk 的边界或未使用尾部
            break
        if size < minsz or size % align != 0:
            corruptions.append(Corruption(
                cur, size_raw,
                "size=0x%x 非法(过小或未按%d对齐)" % (size_raw, align),
                prev=chunks[-1] if chunks else None))
            break
        if cur + size > region.memsz:
            corruptions.append(Corruption(
                cur, size_raw, "size=0x%x 越过区域末尾" % size_raw,
                prev=chunks[-1] if chunks else None))
            break
        chunks.append(Chunk(cur, size, flags))
        # 当前块的 inuse 由下一块 prev_inuse 决定（提前看一眼）
        if cur + size + 2 * word <= end:
            next_flags = struct.unpack_from(fmt, data, cur + size + word)[0] & FLAG_BITS
            chunks[-1].inuse = bool(next_flags & 1)
        cur += size
    return chunks, corruptions, notes


def probe(chunks, addr, region_vaddr):
    """地址属于哪个 chunk。"""
    off = addr - region_vaddr
    for c in chunks:
        if c.offset <= off < c.offset + c.size:
            return c, off - c.offset
    return None, None


# ---------------------------------------------------------------------------
# 引用搜索
# ---------------------------------------------------------------------------

def searchref(core, target_start, target_end, limit=32):
    """全内存搜指向 [target_start,target_end) 的指针。"""
    hits = []
    for r in core.regions:
        if not r.readable:
            continue
        word = 4 if core.elfclass == 32 else 8
        fmt = "<%d%s" % (len(r.data) // word, "I" if word == 4 else "Q")
        vals = struct.unpack(fmt, r.data[: len(r.data) // word * word])
        for i, v in enumerate(vals):
            if target_start <= v < target_end:
                where = r.vaddr + i * word
                hits.append((where, v))
                if len(hits) >= limit:
                    return hits
    return hits


def describe_addr(core, addr, threads):
    """给地址一个人类可读的归属（用于引用来源标注）。"""
    r = core.region_of(addr)
    if r is None:
        return "未转储区"
    fm = core.file_mapping_of(addr)
    if fm:
        return "模块 %s" % fm.name
    for t in threads:
        tr = core.region_of(t.sp)
        if tr and r is tr:
            return "线程%d栈" % t.tid
    if r.write_bit:
        return "匿名读写段(堆)"
    return "只读段"


# ---------------------------------------------------------------------------
# 内容指纹
# ---------------------------------------------------------------------------

_MAGICS = [
    (b"\xde\xad\xbe\xef", "0xDEADBEEF"), (b"\xca\xfe\xba\xbe", "0xCAFEBABE"),
    (b"\xef\xbe\xad\xde", "0xDEADBEEF(小端)"), (b"\xfd\xfd\xfd\xfd", "0xFDFDFDFD"),
    (b"\xab\xab\xab\xab", "0xABABABAB"), (b"\xcd\xcd\xcd\xcd", "0xCDCDCDCD"),
]


def fingerprint(data, max_len=96):
    """给受害区域做内容指纹。"""
    if not data:
        return None
    view = data[:max_len]
    if all(b == 0 for b in view):
        return Fingerprint("全零（清零式踩写或未初始化）", "zeros")
    for magic, name in _MAGICS:
        if magic in view:
            return Fingerprint("含调试魔数 %s" % name, "magic")
    strings = re.findall(rb"[\x20-\x7e]{4,}", view)
    if strings:
        return Fingerprint("含可读字符串: %r（拿去源码 grep，常直接锁定肇事模块）"
                           % (b" | ".join(strings[:3]).decode("ascii")), "ascii")
    # 重复模式：1/2/4/8 字节循环
    for n in (1, 2, 4, 8):
        if len(view) >= n * 4 and view[:n] * (len(view) // n) == view[: len(view) // n * n]:
            return Fingerprint("单值重复填充 %s（memset/越界写特征）" % view[:n].hex(), "pattern")
    return Fingerprint("无显著特征：%s..." % view[:16].hex(), "unknown")


# ---------------------------------------------------------------------------
# glibc 版本识别
# ---------------------------------------------------------------------------

def detect_glibc_version(libc_artifact_path):
    """从 libc 产物的版本字符串提取 glibc 版本（堆结构随版本有差异）。"""
    try:
        with open(libc_artifact_path, "rb") as f:
            blob = f.read()
        m = re.search(rb"GNU C Library[^\x00]{0,200}?release version (\d+\.\d+)", blob)
        if m:
            return m.group(1).decode()
        m = re.search(rb"GLIBC_2\.(\d+)", blob)
        if m:
            return "2.%s" % m.group(1).decode()
    except OSError:
        pass
    return None


def find_libc(matches):
    for m in matches:
        if m.artifact and "libc.so" in m.module.name:
            return m.artifact.path
    return None


# ---------------------------------------------------------------------------
# 技能入口
# ---------------------------------------------------------------------------

def run_heap_skill(core, threads, matches, victim_addr=None, ref_radius=64):
    """堆取证主流程。victim_addr 可选（由 triage 或调用方指定受害地址）。"""
    res = HeapResult()
    heaps = find_heap_regions(core, threads)
    if not heaps:
        res.notes.append("core 中没有匿名读写段（堆未被转储或进程无堆），堆取证不可用")
        return res

    glibc_ver = None
    libc_path = find_libc(matches)
    if libc_path:
        glibc_ver = detect_glibc_version(libc_path)
        if glibc_ver:
            res.notes.append("glibc 版本 %s（来自 %s）" % (glibc_ver, libc_path))

    first_corrupt_region = None
    for r in heaps:
        desc = "0x%x-0x%x" % (r.vaddr, r.vaddr + r.filesz)
        chunks, corrs, notes = walk_region(r, core.elfclass)
        res.regions.append((desc, chunks))
        res.notes.extend(notes)
        if corrs and res.corruptions == []:
            first_corrupt_region = (r, chunks, corrs, desc)

    if first_corrupt_region:
        r, chunks, corrs, desc = first_corrupt_region
        res.region_desc = desc
        for c in corrs:
            res.corruptions.append(c)
        # 受害块指纹 + 前块尾部内容（越界载荷常留在前块数据末尾）
        c = corrs[0]
        victim_data = r.data[c.offset: c.offset + 96]
        fp = fingerprint(victim_data)
        if fp:
            res.fingerprints.append(fp)
        if c.prev:
            tail = r.data[c.prev.offset + c.prev.size - 32: c.prev.offset + c.prev.size]
            fp2 = fingerprint(tail)
            if fp2 and fp2.kind not in ("zeros", "unknown"):
                res.fingerprints.append(Fingerprint("前块尾部32字节: %s" % fp2.desc, fp2.kind))

    # searchref：优先围绕首个损坏点，其次显式 victim_addr
    target = None
    if victim_addr is not None:
        target = (victim_addr, victim_addr + ref_radius)
    elif res.corruptions:
        r_desc, _, _, _ = first_corrupt_region
        target = (r.vaddr + res.corruptions[0].offset,
                  r.vaddr + res.corruptions[0].offset + ref_radius)
    if target:
        refs = searchref(core, target[0], target[1])
        for where, v in refs:
            res.references.append((describe_addr(core, where, threads), where, v))
    return res

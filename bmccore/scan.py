# -*- coding: utf-8 -*-
"""技能2：栈扫描兜底回溯（治"栈被踩坏、bt 全是 ??"）。

思路（学 Breakpad 分级降级的第三级，本地化实现）：
  SP 向栈底逐字扫，值落入某模块可执行区间 => 疑似返回地址；
  再读候选地址前的指令字节，按架构判定"是否紧跟 call 指令"（BL/BLR/JAL/JALR），
  是 => 高置信"确认帧"；指令取不到 => 保留为"未验证帧"；判定不是 call => 丢弃。
ARM32 特殊处理 Thumb bit0。
所有结果如实标注置信度，绝不把猜测包装成结论。
"""
import struct

from elftools.elf.elffile import ELFFile


class ScanFrame(object):
    def __init__(self, stack_off, value, confidence, why, func=None, loc=None, module=None):
        self.stack_off = stack_off    # 相对 SP 的字节偏移
        self.value = value            # 栈上原始值
        self.confidence = confidence  # '确认' / '未验证'
        self.why = why                # 判定说明（如 "A64 BL"）
        self.func = func
        self.loc = loc
        self.module = module

    @property
    def display(self):
        if self.func:
            return self.func
        return "0x%x" % self.value

    def __repr__(self):
        return "[SP+0x%03x] 0x%x %s %s (%s)" % (self.stack_off, self.value,
                                                self.confidence, self.display, self.why)


class ScanResult(object):
    def __init__(self):
        self.frames = []
        self.notes = []
        self.overflow = None          # None 或溢出判定的文字说明

    @property
    def confirmed(self):
        return [f for f in self.frames if f.confidence == "确认"]


# ---------------------------------------------------------------------------
# 产物 .text 读取（供 call 指令验证；core 里代码页通常没被转储）
# ---------------------------------------------------------------------------

_text_cache = {}


def read_artifact_text(path, vaddr_off, size):
    """从产物文件 .text 读字节；vaddr_off 相对产物基址（st_value 语义）。"""
    key = path
    if key not in _text_cache:
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                sec = elf.get_section_by_name(".text")
                _text_cache[key] = (sec.header.sh_addr, sec.data()) if sec else (None, None)
        except Exception:
            _text_cache[key] = (None, None)
    base, data = _text_cache[key]
    if data is None:
        return None
    off = vaddr_off - base
    if off < 0 or off >= len(data):
        return None
    return data[off:off + size]


# ---------------------------------------------------------------------------
# 主扫描
# ---------------------------------------------------------------------------

def _find_module(matches, addr):
    for m in matches:
        if m.module.contains(addr):
            return m
    return None


def _code_addr_exec(core, addr):
    """该地址所在 core 内存段是否可执行（判断是不是代码地址）。"""
    r = core.region_of(addr)
    return bool(r and r.exec_bit)


def scan_thread(core, arch, thread, matches, resolver=None, max_depth=65536,
                addr2line=None):
    """扫描一个线程的栈。返回 ScanResult。

    matches: symbols.MatchResult 列表
    resolver: symbols.SymbolResolver
    addr2line: 可调用 (artifact_path, [addr...], base) -> {addr: (func, loc)}（可选）
    """
    res = ScanResult()
    sp = thread.sp
    word = arch.word

    region = core.region_of(sp)
    if region is None:
        res.overflow = ("栈溢出或 SP 已被破坏：SP=0x%x 不落在任何已转储的内存段内"
                        % sp)
        return res
    if sp - region.vaddr < 512:
        res.overflow = ("疑似栈溢出：SP=0x%x 距栈区底边界(0x%x)仅 %d 字节"
                        % (sp, region.vaddr, sp - region.vaddr))

    end = min(region.vaddr + region.filesz, sp + max_depth)
    start_off = sp - region.vaddr
    data = region.data[start_off:start_off + (end - sp)]

    # 预取各模块代码区间（含产物可用性）
    exec_mods = [m for m in matches if m.artifact or True]  # 全部模块都参与区间判断

    pending_a2l = []   # (artifact_path, module_base, addr)
    n_words = len(data) // word
    fmt = "<%d%s" % (n_words, "I" if word == 4 else "Q")
    values = struct.unpack(fmt, data[: n_words * word])

    for i, v in enumerate(values):
        if v == 0:
            continue
        if not _code_addr_exec(core, v) and not (arch.thumb_aware and (v & 1)):
            continue
        cand = v & ~1 if (arch.thumb_aware and (v & 1)) else v
        m = _find_module(exec_mods, cand)
        if m is None:
            continue
        if not _code_addr_exec(core, cand) and m.artifact is None:
            # 无产物也无 core 代码段佐证，纯数值碰撞，丢弃
            continue

        # call 指令验证：优先产物 .text，退回 core 内存
        prev8 = None
        if m.artifact:
            prev8 = read_artifact_text(m.artifact.path, cand - m.module.base - 8, 8)
        if prev8 is None:
            prev8 = core.read_mem(cand - 8, 8)
        if prev8 is None:
            ok, why = True, "指令字节不可得,仅按代码区间命中"
            conf = "未验证"
        else:
            ok, why = arch.is_call_before(prev8, cand, v)
            conf = "确认"
        if not ok:
            continue

        frame = ScanFrame(i * word, v, conf, why, module=m.module.name)
        if resolver and m.artifact:
            func = resolver.lookup(m.artifact.path, cand, m.module.base)
            if func:
                frame.func = func
        if m.artifact:
            pending_a2l.append((m.artifact.path, m.module.base, cand))
        res.frames.append(frame)

    # 可选行号叠加（批量 addr2line）
    if addr2line:
        by_file = {}
        for path, base, cand in pending_a2l:
            by_file.setdefault((path, base), []).append(cand)
        for (path, base), addrs in by_file.items():
            table = addr2line(path, addrs, base)
            if not table:
                continue
            for fr in res.frames:
                hit = table.get(fr.value & ~1)
                if hit:
                    fr.loc = hit[1]
                    if hit[0] and hit[0] != "??":
                        fr.func = fr.func or hit[0]

    # 递归检测
    if resolver:
        from collections import Counter
        names = [f.func for f in res.frames if f.func]
        for name, cnt in Counter(names).items():
            if cnt >= 15:
                res.notes.append("栈上发现 %d 帧同名函数 %s，疑似失控递归" % (cnt, name))
    return res


def scan_needed(trace):
    """判断 GDB 回溯结果是否需要触发栈扫描。"""
    if not trace:
        return True
    return trace.suspicious

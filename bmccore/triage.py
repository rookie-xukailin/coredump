# -*- coding: utf-8 -*-
"""技能4：信号分类 + 崩溃地址归属 + 结论汇总。

产出"定位结论"：每条结论带可信度（确认/疑似），绝不混淆。
"""
import bisect

SIG_NAMES = {2: "SIGINT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS",
             8: "SIGFPE", 11: "SIGSEGV", 13: "SIGPIPE", 24: "SIGXCPU", 25: "SIGXFSZ"}

SEGV_CODES = {1: "SEGV_MAPERR(地址未映射)", 2: "SEGV_ACCERR(权限错误)",
              3: "SEGV_BNDERR", 4: "SEGV_PKUERR"}
BUS_CODES = {1: "BUS_ADRALN(对齐错误)", 2: "BUS_ADRERR(物理地址不存在)",
             3: "BUS_OBJERR"}


class Conclusion(object):
    def __init__(self, text, confidence="疑似", evidence=""):
        self.text = text
        self.confidence = confidence     # 确认 / 疑似
        self.evidence = evidence

    def __repr__(self):
        return "[%s] %s" % (self.confidence, self.text)


def addr_region_name(core, matches, addr):
    """崩溃地址归属于哪个区域/模块：返回描述字符串。"""
    if addr is None:
        return "未知"
    if addr < 0x1000:
        return "空指针附近(低地址)"
    for m in matches:
        if m.module.contains(addr):
            return "模块 %s" % m.module.name
    r = core.region_of(addr)
    if r:
        kind = "匿名读写段(堆/栈候选)" if r.write_bit else "只读段"
        if r.exec_bit:
            kind += "(可执行)"
        return "%s 0x%x-0x%x" % (kind, r.vaddr, r.vaddr + r.filesz)
    # 各区域之间/之外
    starts = sorted(rr.vaddr for rr in core.regions)
    i = bisect.bisect_right(starts, addr)
    if i > 0:
        prev = None
        for rr in core.regions:
            if rr.vaddr == starts[i - 1]:
                prev = rr
                break
        if prev:
            gap = addr - (prev.vaddr + prev.memsz)
            if 0 < gap < 0x100000:
                return "落在已映射段 %s 尾部之后 %d 字节处(疑似越界越过段边界)" % (
                    "0x%x" % prev.vaddr, gap)
    return "完全未映射地址"


def triage(core, matches, console_hits=None, scan_result=None, heap_result=None):
    """汇总所有证据，产出结论列表。"""
    out = []
    t = core.crash_thread
    if t is None:
        out.append(Conclusion("core 中没有线程信息，无法定位", "确认"))
        return out

    sig = t.cursig
    sig_name = SIG_NAMES.get(sig, "SIG%d" % sig)
    fault = (core.siginfo or {}).get("addr")
    code = (core.siginfo or {}).get("code")

    # --- 信号定性 ---
    if sig == 11 and fault is not None:
        if fault < 0x1000:
            txt = "空指针解引用：访问地址 0x%x（空指针+%d 偏移，通常为 struct 成员访问）" % (
                fault, fault)
            out.append(Conclusion(txt, "确认", "NT_SIGINFO addr"))
        else:
            where = addr_region_name(core, matches, fault)
            txt = "非法内存访问：地址 0x%x，归属：%s" % (fault, where)
            if code in SEGV_CODES:
                txt += "，%s" % SEGV_CODES[code]
            out.append(Conclusion(txt, "确认", "NT_SIGINFO"))
    elif sig == 7 and fault is not None:
        txt = "总线错误：地址 0x%x" % fault
        if code in BUS_CODES:
            txt += "，%s" % BUS_CODES[code]
        txt += "（对齐错误居多）"
        out.append(Conclusion(txt, "确认", "NT_SIGINFO"))
    elif sig == 6:
        if console_hits:
            matched = None
            for _ln, line in console_hits[:5]:
                low = line.lower()
                if any(k in low for k in ("malloc", "free", "corrupt", "invalid",
                                          "smashing", "unaligned", "munmap")):
                    matched = Conclusion("glibc 堆检查触发 abort：%s" % line.strip(),
                                         "确认", "console日志")
                    break
                if "assert" in low:
                    matched = Conclusion("断言失败触发 abort：%s" % line.strip(),
                                         "确认", "console日志")
                    break
            if matched is None:
                matched = Conclusion("进程主动 abort（console 日志未见 glibc 堆/assert 特征）",
                                     "确认", "信号")
            out.append(matched)
        else:
            out.append(Conclusion("SIGABRT：多为 glibc 堆检查/assert 触发（建议提供 console 日志）",
                                  "确认", "信号"))
    else:
        out.append(Conclusion("崩溃信号 %s" % sig_name, "确认", "NT_PRSTATUS"))

    # --- 栈溢出特判 ---
    if scan_result is not None and scan_result.overflow:
        out.append(Conclusion(scan_result.overflow, "疑似", "栈扫描"))

    # --- 堆取证结论 ---
    if heap_result is not None and getattr(heap_result, "victim_probe", None):
        out.append(Conclusion(heap_result.victim_probe, "疑似",
                              "堆走查+崩溃寄存器定位"))
    if heap_result is not None and heap_result.corruptions:
        c = heap_result.corruptions[0]
        txt = ("glibc 堆损坏：区域 %s 偏移 0x%x 处 chunk 头异常(%s)，"
               "重点怀疑其前一个 chunk(偏移 0x%x, %s)数据越界写穿" % (
                   heap_result.region_desc, c.offset, c.reason,
                   c.prev.offset if c.prev else 0,
                   "%d字节" % c.prev.size if c.prev else "未知"))
        out.append(Conclusion(txt, "疑似", "堆走查"))
        for f in heap_result.fingerprints[:2]:
            out.append(Conclusion("损坏区内容指纹：%s" % f.desc, "疑似", "内容指纹"))

    # --- console 证据 ---
    if console_hits:
        for _ln, line in console_hits[:3]:
            if "smashing" in line.lower():
                out.append(Conclusion("栈保护金丝雀被破坏（局部缓冲区溢出）：崩溃帧所在函数"
                                      "有栈上数组越界写", "确认", "console日志"))
                break

    return out

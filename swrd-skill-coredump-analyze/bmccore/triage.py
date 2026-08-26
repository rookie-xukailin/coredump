# -*- coding: utf-8 -*-
"""技能4：信号分类 + 崩溃地址归属 + 证据加权根因推断。

产出两层结论：
1. 事实条目（fact）：信号定性/console 证据等"发生了什么"，不参与排序；
2. 根因候选（candidate）：多假设、按证据硬度加权打分排序——每条带
   refs（证据链：寄存器/堆布局/指令/帧变量逐条人话引用）与 hypothesis
   （建议的验证动作，供 LLM 在 narrative.hypotheses 逐一回应）。

证据权重表（同主线证据累加，封顶 100；≥75 确认、≥45 疑似）：
  指令归因(verified)60 / 寄存器精确匹配55 / gdb帧变量确认50 /
  gdb对象重建50 / 死锁环60 / 堆 victim_probe45 / 堆损坏40 /
  字段级受害对象40 / 栈溢出40 / 金丝雀55 / 内容指纹25 /
  栈上指针引用20 / gdb表达式20。
"""
import bisect

from .inattr import describe as _inattr_describe

SIG_NAMES = {2: "SIGINT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS",
             8: "SIGFPE", 11: "SIGSEGV", 13: "SIGPIPE", 24: "SIGXCPU", 25: "SIGXFSZ"}

SEGV_CODES = {1: "SEGV_MAPERR(地址未映射)", 2: "SEGV_ACCERR(权限错误)",
              3: "SEGV_BNDERR", 4: "SEGV_PKUERR"}
BUS_CODES = {1: "BUS_ADRALN(对齐错误)", 2: "BUS_ADRERR(物理地址不存在)",
             3: "BUS_OBJERR"}

# 证据权重表（同主线证据累加，封顶 100）
_SCORE = {
    "inattr_verified": 60, "inattr_unverified": 30,
    "regs_exact": 55, "framevars_gdb": 50, "objrebuild_deref": 50,
    "deadlock_ring": 60, "victim_probe": 45, "heap_corrupt": 40,
    "heaptyping_victim": 40, "heaptyping_suspect": 30,
    "stack_overflow": 40, "fingerprint": 25, "stack_ptr_ref": 20,
    "expr_eval": 20, "console_smashing": 55,
}


def _conf(score):
    return "确认" if score >= 75 else "疑似"


class Conclusion(object):
    """结论条目：事实（score=0）或根因候选（score>0，按分值排序）。"""

    def __init__(self, text, confidence="疑似", evidence="", score=0,
                 refs=None, hypothesis=None):
        self.text = text
        self.confidence = confidence     # 确认 / 疑似
        self.evidence = evidence
        self.score = score               # 0=事实条目；>0=根因候选（参与排序）
        self.refs = refs or []           # [{"type","detail","source"}] 证据链
        self.hypothesis = hypothesis     # 建议的验证动作（LLM 回应用）

    def __repr__(self):
        return "[%s|%d] %s" % (self.confidence, self.score, self.text)


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


def _facts(core, matches, console_hits, sig, sig_name, fault, code):
    """信号定性/console 证据等事实条目（不参与根因排序）。"""
    facts = []
    if sig == 11 and fault is not None:
        if fault < 0x1000:
            txt = "空指针解引用：访问地址 0x%x（空指针+%d 偏移，通常为 struct 成员访问）" % (
                fault, fault)
            facts.append(Conclusion(txt, "确认", "NT_SIGINFO addr"))
        else:
            where = addr_region_name(core, matches, fault)
            txt = "非法内存访问：地址 0x%x，归属：%s" % (fault, where)
            if code in SEGV_CODES:
                txt += "，%s" % SEGV_CODES[code]
            facts.append(Conclusion(txt, "确认", "NT_SIGINFO"))
    elif sig == 7 and fault is not None:
        txt = "总线错误：地址 0x%x" % fault
        if code in BUS_CODES:
            txt += "，%s" % BUS_CODES[code]
        txt += "（对齐错误居多）"
        facts.append(Conclusion(txt, "确认", "NT_SIGINFO"))
    elif sig == 6:
        if console_hits:
            matched = None
            for _ln, line in console_hits[:5]:
                low = line.lower()
                if "buffer overflow detected" in low or "overflow detected" in low:
                    matched = Conclusion(
                        "glibc 加固检查(_FORTIFY_SOURCE)触发 abort：%s —— 拷贝长度"
                        "越过目标缓冲，检查崩溃帧的 *_chk 调用点" % line.strip(),
                        "确认", "console日志")
                    break
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
            facts.append(matched)
        else:
            facts.append(Conclusion("SIGABRT：多为 glibc 堆检查/assert 触发（建议提供 console 日志）",
                                    "确认", "信号"))
    else:
        facts.append(Conclusion("崩溃信号 %s" % sig_name, "确认", "NT_PRSTATUS"))
    return facts


def _mem_access_candidate(fault, inattr_res, regs_deep, framevars,
                          objrebuild, heap_typing, stackdump):
    """访存型根因候选：指令归因+寄存器基址+帧变量+对象重建+堆布局 合并。"""
    if fault is None or fault < 0x1000:
        return None
    score = 0
    refs = []
    # 1) 指令归因（最硬）
    if inattr_res and inattr_res.get("parsed"):
        d = _inattr_describe(inattr_res)
        if d:
            refs.append({"type": "指令归因", "detail": d,
                         "source": inattr_res.get("source", "gdb指令解析")})
            score += _SCORE["inattr_verified"] if inattr_res.get("verified") \
                else _SCORE["inattr_unverified"]
    # 2) 寄存器基址/精确匹配
    if regs_deep:
        for rn, v, sem in regs_deep:
            if v == fault:
                refs.append({"type": "寄存器", "detail":
                             "%s=0x%x 恰为出错地址（%s）" % (rn, v, sem or "—"),
                             "source": "NT_PRSTATUS+语义解码"})
                score += _SCORE["regs_exact"]
                break
            if 0x1000 <= v <= fault < v + 0x1000:
                refs.append({"type": "寄存器", "detail":
                             "%s=0x%x 为对象基址，+0x%x 达出错地址（%s）"
                             % (rn, v, fault - v, sem or "—"),
                             "source": "NT_PRSTATUS+语义解码"})
                score += _SCORE["regs_exact"]
                break
    # 3) 帧变量精确命中
    if framevars and framevars.get("frames"):
        fr0 = framevars["frames"][0]
        pick = None
        for v in fr0.get("vars", []):
            try:
                iv = int(str(v.get("value", "")).split()[0], 0)
            except (ValueError, IndexError):
                continue
            if iv == fault:
                pick = v
                break
        if pick is not None:
            refs.append({"type": "帧变量", "detail":
                         "崩溃帧 %s 的 %s=%s（%s）" % (fr0.get("func", "?"),
                                                       pick["name"],
                                                       pick.get("value"),
                                                       pick.get("sem", "")),
                         "source": "framevars(%s)" % framevars.get("source", "?")})
            score += _SCORE["framevars_gdb"] if "gdb" in \
                (framevars.get("source") or "").lower() else 35
    # 4) gdb 类型重建
    if objrebuild and objrebuild.get("derefs"):
        e, _out = objrebuild["derefs"][0]
        refs.append({"type": "对象重建", "detail":
                     "gdb 按 DWARF 类型在运行时地址重建：%s" % e,
                     "source": "gdb+DWARF"})
        score += _SCORE["objrebuild_deref"]
    # 5) 堆布局：字段级受害对象
    victim = next((o for o in (heap_typing or [])
                   if o.get("role") == "受害对象"), None)
    if victim:
        fdesc = "、".join("%s=%s" % (f["name"], f["value"])
                          for f in victim.get("fields", [])[:3])
        refs.append({"type": "堆布局", "detail":
                     "受害对象 chunk：类型 %s（DIE 尺寸匹配），字段 %s"
                     % (victim.get("type", "?"), fdesc or "—"),
                     "source": "DIE+core内存"})
        score += _SCORE["heaptyping_victim"]
    # 6) 栈上指向出错地址的指针
    if stackdump:
        for off, a, v, sem in stackdump:
            if v == fault:
                refs.append({"type": "栈指针", "detail":
                             "SP+0x%x 处的值 0x%x 即出错地址（%s）"
                             % (off, a, sem or "—"),
                             "source": "core内存读取+语义解码"})
                score += _SCORE["stack_ptr_ref"]
                break
    if not refs:
        return None
    score = min(score, 100)
    lead = refs[0]["detail"]
    who = "该对象" if len(refs) > 1 else "它"
    return Conclusion(
        "崩溃为对%s的解引用：%s" % (who, lead),
        _conf(score), "证据加权(%d分)" % score, score=score, refs=refs,
        hypothesis="读崩溃函数源码追基址的赋值/初始化/释放路径；"
                   "用对象重建的字段与 DIE 偏移核对 +0x 处成员")


def _null_param_candidate(fault, framevars):
    """空指针 + 参数恰为 NULL：谁把参数传成了空。"""
    if fault is None or fault >= 0x1000 or not framevars or \
            not framevars.get("frames"):
        return None
    fr0 = framevars["frames"][0]
    for v in fr0.get("vars", []):
        if v.get("kind") != "参数":
            continue
        try:
            iv = int(str(v.get("value", "")).split()[0], 0)
        except (ValueError, IndexError):
            continue
        if iv == 0:
            refs = [{"type": "帧变量", "detail":
                     "崩溃帧 %s 的参数 %s=NULL（空指针+0x%x 成员访问形态）"
                     % (fr0.get("func", "?"), v.get("name"), fault),
                     "source": "framevars(%s)" % framevars.get("source", "?")}]
            return Conclusion(
                "空指针解引用：参数 %s 为 NULL——追谁把它传成空" % v["name"],
                _conf(55), "证据加权(55分)", score=55, refs=refs,
                hypothesis="向上追 %s 的赋值路径：初始化遗漏/失败分支/"
                           "释放后未置空（用 4c 反向数据流）" % v["name"])
    return None


def _deadlock_candidate(lock_result, addr_names):
    if lock_result is None or not getattr(lock_result, "deadlocks", None):
        return None
    score = _SCORE["deadlock_ring"]
    refs = []
    for cycle in lock_result.deadlocks[:1]:
        chain = " → ".join("T%d等0x%x(T%d持有)" % (
            e.waiter_tid, e.lock_addr, e.holder_tid) for e in cycle)
        named = (addr_names or {}).get(cycle[0].lock_addr)
        refs.append({"type": "死锁环", "detail":
                     "%s%s" % (chain, "（锁=%s）" % named if named else ""),
                     "source": "锁分析(futex+TID扫描)"})
    if len(lock_result.deadlocks) > 1:
        refs.append({"type": "死锁环", "detail":
                     "另有 %d 个死锁环" % (len(lock_result.deadlocks) - 1),
                     "source": "锁分析"})
        score = min(score + 10, 100)
    return Conclusion(
        "死锁：%s" % refs[0]["detail"], _conf(score),
        "证据加权(%d分)" % score, score=score, refs=refs,
        hypothesis="读涉事线程的业务动作与锁获取顺序，确认互等构成环"
                   "（锁分析节）")


def _stack_overflow_candidate(scan_result):
    if scan_result is None or not scan_result.overflow:
        return None
    refs = [{"type": "栈扫描", "detail": scan_result.overflow,
             "source": "栈扫描"}]
    return Conclusion(scan_result.overflow, _conf(_SCORE["stack_overflow"]),
                      "证据加权(40分)", score=_SCORE["stack_overflow"],
                      refs=refs,
                      hypothesis="读崩溃函数局部变量大小与递归终止条件；"
                                 "SP 距栈底边界核实溢出方向")


def _heap_corrupt_candidate(heap_result, heap_typing):
    if heap_result is None or not heap_result.corruptions:
        return None
    score = _SCORE["heap_corrupt"]
    refs = []
    c = heap_result.corruptions[0]
    refs.append({"type": "堆走查", "detail":
                 "区域 %s 偏移 0x%x 处 chunk 头异常(%s)，前一个 chunk"
                 "(偏移 0x%x, %s)为最大嫌疑" % (
                     heap_result.region_desc, c.offset, c.reason,
                     c.prev.offset if c.prev else 0,
                     "%d字节" % c.prev.size if c.prev else "未知"),
                 "source": "堆走查"})
    suspect = next((o for o in (heap_typing or [])
                    if o.get("role") == "越界嫌疑前块"), None)
    if suspect:
        refs.append({"type": "堆布局", "detail":
                     "嫌疑前块类型 %s（DIE 尺寸匹配）——其写入者即肇事"
                     % suspect.get("type", "?"),
                     "source": "DIE+core内存"})
        score += _SCORE["heaptyping_suspect"]
    for f in heap_result.fingerprints[:2]:
        refs.append({"type": "内容指纹", "detail": f.desc,
                     "source": "内容指纹"})
        score += _SCORE["fingerprint"]
    score = min(score, 100)
    return Conclusion(
        "堆块被越界写穿：%s" % refs[0]["detail"], _conf(score),
        "证据加权(%d分)" % score, score=score, refs=refs,
        hypothesis="grep 嫌疑前块类型的所有写入点（4c 写入者搜索），"
                   "比对写入长度与块尺寸")


def _smashing_candidate(console_hits):
    if not console_hits:
        return None
    for _ln, line in console_hits[:3]:
        if "smashing" in line.lower():
            refs = [{"type": "console", "detail":
                     "栈保护金丝雀被破坏：%s" % line.strip(),
                     "source": "console日志"}]
            return Conclusion(
                "栈缓冲区溢出（金丝雀破坏）：崩溃帧所在函数有栈上数组越界写",
                _conf(_SCORE["console_smashing"]), "证据加权(55分)",
                score=_SCORE["console_smashing"], refs=refs,
                hypothesis="读崩溃函数内栈上数组的拷贝/循环写，比对边界")
    return None


def triage(core, matches, console_hits=None, scan_result=None, heap_result=None,
           deepdive=None, lock_result=None, framevars=None, regs_deep=None,
           addr_names=None, inattr_res=None, objrebuild=None,
           heap_typing=None, stackdump=None):
    """汇总所有证据：事实条目 + 证据加权排序的根因候选。"""
    t = core.crash_thread
    if t is None:
        return [Conclusion("core 中没有线程信息，无法定位", "确认")]

    sig = t.cursig
    sig_name = SIG_NAMES.get(sig, "SIG%d" % sig)
    fault = (core.siginfo or {}).get("addr")
    code = (core.siginfo or {}).get("code")

    facts = _facts(core, matches, console_hits, sig, sig_name, fault, code)

    cands = []
    c = _mem_access_candidate(fault, inattr_res, regs_deep, framevars,
                              objrebuild, heap_typing, stackdump)
    if c:
        cands.append(c)
    c = _null_param_candidate(fault, framevars)
    if c:
        cands.append(c)
    c = _deadlock_candidate(lock_result, addr_names)
    if c:
        cands.append(c)
    c = _stack_overflow_candidate(scan_result)
    if c:
        cands.append(c)
    c = _heap_corrupt_candidate(heap_result, heap_typing)
    if c:
        cands.append(c)
    c = _smashing_candidate(console_hits)
    if c:
        cands.append(c)

    return facts + sorted(cands, key=lambda x: -x.score)

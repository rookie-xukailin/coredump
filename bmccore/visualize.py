# -*- coding: utf-8 -*-
"""内存可视化 Web 面板 v3：递进式崩溃分析 + 交互式线程 + 可视化内存布局。

设计目标：工程师打开页面 30 秒内看懂"崩在哪、为什么崩、怎么修"。
"""
import io
import json
import os
import socket
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


def _find_free_port(preferred=8080, max_tries=100):
    for port in range(preferred, preferred + max_tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return port
        except OSError:
            continue
    return None


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


_SIG_NAMES = {2: "SIGINT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT",
              7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV"}
_SIG_HINTS = {
    "SIGSEGV": "访问了不该访问的内存地址",
    "SIGABRT": "进程主动 abort（glibc 堆检查发现内存损坏，或 assert 失败）",
    "SIGBUS": "mmap 映射的文件被外部截断/替换后继续访问",
    "SIGILL": "CPU 执行了非法指令（函数指针大概率被踩坏）",
}


def _read_source_snippet(source_root, file_path, line, context=8):
    """读源码片段，返回 [(行号, 内容, 是否崩溃行)]。"""
    if not source_root or not file_path:
        return None
    # 按文件名在源码树中定位
    base = os.path.basename(file_path)
    for dirpath, _dirs, files in os.walk(source_root):
        if base in files:
            real = os.path.join(dirpath, base)
            try:
                with io.open(real, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                lo = max(1, line - context)
                hi = min(len(lines), line + context)
                return [(n, lines[n - 1].rstrip("\n"), n == line)
                        for n in range(lo, hi + 1)]
            except OSError:
                return None
    return None


def _build_thread_stacks(core, traces, scan_results, resolver_matches=None):
    """为每个线程构建栈帧列表（优先 gdb 回溯，退回栈扫描）。"""
    thread_stacks = {}

    # gdb 回溯
    if traces:
        for tr in traces:
            frames = []
            for fr in tr.frames[:15]:
                frames.append({
                    "level": fr.level,
                    "func": fr.func or "??",
                    "loc": fr.loc or "",
                    "addr": "0x%x" % (fr.addr or 0),
                    "source": "gdb",
                })
            thread_stacks[tr.lwp] = frames

    # 栈扫描兜底（gdb 不可用或断链时）
    if scan_results:
        for tid, sr in scan_results.items():
            if tid in thread_stacks and thread_stacks[tid]:
                continue    # gdb 已有结果
            frames = []
            for fr in sr.frames[:15]:
                frames.append({
                    "level": len(frames),
                    "func": fr.func or fr.loc or "0x%x" % fr.value,
                    "loc": fr.loc or "",
                    "addr": "0x%x" % fr.value,
                    "source": "scan",
                    "confidence": fr.confidence,
                    "why": fr.why,
                })
            if frames:
                thread_stacks[tid] = frames

    return thread_stacks


def build_viz_data(core, heap_result=None, matches=None, traces=None,
                   conclusions=None, cfi_frames=None, scan_results=None,
                   source_root=None, snippets=None):
    signal = core.threads[0].cursig if core.threads else 0
    sig_name = _SIG_NAMES.get(signal, "SIG%d" % signal)
    fault_addr = (core.siginfo or {}).get("addr")
    crash_thread = core.crash_thread

    # ── 崩溃故事（递进式） ──
    story_steps = []

    # 步骤 1: 发生了什么
    step1 = {
        "title": "发生了什么",
        "icon": "💥",
        "detail": "%s 进程收到 %s 信号" % (
            (core.prpsinfo or {}).get("fname", "未知"), sig_name),
        "hint": _SIG_HINTS.get(sig_name, ""),
    }
    if fault_addr is not None:
        if fault_addr < 0x1000:
            step1["detail"] += "，出错地址 0x%x——这是一个很小的地址，" \
                "几乎可以确定是空指针加偏移量（访问 NULL 指针的某个成员变量）" % fault_addr
        else:
            step1["detail"] += "，出错地址 0x%x——这个地址不属于任何已映射的内存区域" % fault_addr
    story_steps.append(step1)

    # 步骤 2: 崩在哪
    thread_stacks = _build_thread_stacks(core, traces, scan_results)
    crash_stack = thread_stacks.get(crash_thread.tid, []) if crash_thread else []
    if crash_stack:
        top_frame = crash_stack[0]
        step2 = {
            "title": "崩在哪里",
            "icon": "🎯",
            "detail": "崩溃点在 <code>%s</code>" % (top_frame["func"] or "未知函数"),
            "hint": "",
        }
        if top_frame.get("loc"):
            step2["detail"] += "，位于 <code>%s</code>" % top_frame["loc"]
            step2["hint"] = "这是调用栈最内层（#0）的函数，即崩溃瞬间正在执行的代码"
        story_steps.append(step2)

    # 步骤 3: 调用链（怎么走到这里的）
    if len(crash_stack) > 1:
        chain = " → ".join(f["func"].split("(")[0] for f in crash_stack[:5])
        story_steps.append({
            "title": "怎么走到这里的",
            "icon": "🔗",
            "detail": "调用路径：<code>%s</code>" % chain,
            "hint": "从右到左是最外层到最内层——程序从 main 一路调下来，最终崩在 %s 里"
                % crash_stack[0]["func"].split("(")[0],
        })

    # 步骤 4: 根因分析
    if conclusions:
        for c in conclusions[:2]:
            story_steps.append({
                "title": "为什么崩" if c.confidence == "确认" else "可能的根因",
                "icon": "🔍" if c.confidence == "确认" else "❓",
                "detail": c.text,
                "hint": "依据：%s | 可信度：%s" % (c.evidence, c.confidence),
            })

    # 步骤 5: 堆取证（如有）
    if heap_result:
        if heap_result.corruptions:
            c = heap_result.corruptions[0]
            story_steps.append({
                "title": "堆损坏详情",
                "icon": "📦",
                "detail": "堆块在偏移 +0x%x 处损坏（%s）。前一个堆块是重点嫌疑——" \
                    "很可能是它的数据越界写穿了下一个块的头信息" % (c.offset, c.reason),
                "hint": "越界写穿是嵌入式最常见的堆损坏模式：A 块的写入超过了自己的边界，" \
                    "踩坏了紧跟其后的 B 块的元数据（大小/标志位）",
            })
        if heap_result.fingerprints:
            for fp in heap_result.fingerprints[:1]:
                story_steps.append({
                    "title": "肇事线索",
                    "icon": "🧬",
                    "detail": "被踩区域的内容特征：%s" % fp.desc,
                    "hint": "把这段内容拿去源码里搜索（grep），通常能直接找到是哪个模块写入的",
                })

    # ── 变量生命周期追踪 ──
    var_trace = None
    var_root_cause = None
    if crash_stack and crash_stack[0].get("loc") and source_root:
        loc = crash_stack[0]["loc"]
        if ":" in loc:
            file_path, _, line_str = loc.rpartition(":")
            if line_str.isdigit():
                # 读崩溃行源码
                snippet = _read_source_snippet(source_root, file_path,
                                               int(line_str), context=0)
                if snippet:
                    crash_line_text = snippet[0][1] if snippet else ""
                    from .vartrace import trace_variable
                    var_trace, var_root_cause = trace_variable(
                        source_root, file_path, int(line_str),
                        crash_line_text, fault_addr)
                    if var_trace:
                        for ev in var_trace:
                            if ev.get("is_root_cause"):
                                story_steps.append({
                                    "title": "🔍 根因定位",
                                    "icon": "🎯",
                                    "detail": ev["detail"],
                                    "hint": "这是通过追踪变量 '%s' 的完整生命周期找到的" %
                                        ev.get("var", ""),
                                })

    # ── 崩溃源码 ──
    crash_source = None
    if crash_stack and crash_stack[0].get("loc"):
        loc = crash_stack[0]["loc"]
        if ":" in loc:
            file_path, _, line_str = loc.rpartition(":")
            if line_str.isdigit():
                crash_source = _read_source_snippet(
                    source_root, file_path, int(line_str))
                if crash_source:
                    crash_source = {
                        "file": os.path.basename(file_path),
                        "line": int(line_str),
                        "code": crash_source,
                    }

    # 退回 source snippets（Pipeline 的 source skill 已提取的）
    if crash_source is None and snippets:
        for f, ln, real_path, body in snippets[:1]:
            crash_source = {
                "file": os.path.basename(f),
                "line": ln,
                "code": [(n, txt, hit) for n, txt, hit in body],
            }
            break

    # ── 内存布局（简化+标注） ──
    mem_regions = []
    for r in core.regions:
        size_kb = r.filesz / 1024.0
        # 分类
        if r.exec_bit and not r.write_bit:
            kind = "code"
            label = "代码"
        elif r.write_bit and not r.exec_bit:
            # 判断是不是栈
            is_stack = False
            for t in core.threads:
                if r.vaddr <= t.sp < r.vaddr + r.memsz:
                    is_stack = True
                    label = "线程%d栈" % t.tid
                    break
            if not is_stack:
                kind = "heap"
                label = "堆/数据"
        elif r.readable and not r.write_bit:
            kind = "ro"
            label = "常量"
        else:
            kind = "other"
            label = "其他"
        # 找模块名
        module = ""
        for m in (core.file_mappings or []):
            if m.start <= r.vaddr < m.end:
                module = m.name
                break
        mem_regions.append({
            "start": r.vaddr,
            "size_kb": size_kb,
            "kind": kind,
            "label": label,
            "module": module,
            "r": bool(r.flags & 4), "w": bool(r.flags & 2), "x": bool(r.flags & 1),
        })

    # ── 线程详情 ──
    threads = []
    for t in core.threads:
        tinfo = {
            "tid": t.tid,
            "pc": "0x%x" % t.pc,
            "sp": "0x%x" % t.sp,
            "is_crash": t.is_crash,
            "signal": t.cursig,
            "stack": thread_stacks.get(t.tid, []),
        }
        threads.append(tinfo)

    return {
        "summary": {
            "signal": sig_name,
            "signal_hint": _SIG_HINTS.get(sig_name, ""),
            "fault_addr": "0x%x" % fault_addr if fault_addr else "-",
            "arch": core.arch.name if core.arch else "unknown",
            "process": (core.prpsinfo or {}).get("fname", "unknown"),
            "pid": crash_thread.tid if crash_thread else "-",
            "nthreads": len(core.threads),
        },
        "story": story_steps,
        "crash_source": crash_source,
        "mem_regions": mem_regions,
        "fault_addr_num": fault_addr,
        "mem_min": min(r.vaddr for r in core.regions) if core.regions else 0,
        "mem_max": max(r.vaddr + r.filesz for r in core.regions) if core.regions else 1,
        "threads": threads,
        "heap_report": _build_heap_report(heap_result),
        "var_trace": var_trace,
        "var_root_cause": var_root_cause,
        "conclusions": [{"confidence": c.confidence, "text": c.text,
                         "evidence": c.evidence} for c in (conclusions or [])],
    }


def _build_heap_chunks(heap_result):
    if not heap_result:
        return None
    for desc, chunks in heap_result.regions:
        return [{"offset": c.offset, "size": c.size, "inuse": c.inuse}
                for c in chunks[:100]]
    return None


def _build_heap_report(heap_result):
    """生成堆健康报告——用人话回答"堆有没有问题、谁踩的、怎么踩的"。

    返回 dict:
      verdict: "healthy" | "corrupted" | "stomped" | "no_heap" | "unknown"
      headline: 一句话结论
      detail: 详细解释（大白话）
      evidence: 证据列表
      suspect: 肇事嫌疑（如有）
      victim: 受害对象（如有）
      stats: 基本统计
    """
    if not heap_result:
        return {"verdict": "no_heap", "headline": "core 中没有堆数据",
                "detail": "进程可能没有堆分配，或设备端 coredump_filter 裁掉了堆内存。"}

    report = {"verdict": "unknown", "headline": "", "detail": "",
              "evidence": [], "suspect": None, "victim": None, "stats": {}}

    # 统计
    total_chunks = 0
    inuse_chunks = 0
    total_bytes = 0
    for desc, chunks in heap_result.regions:
        total_chunks += len(chunks)
        inuse_chunks += sum(1 for c in chunks if c.inuse)
        total_bytes += sum(c.size for c in chunks)
    report["stats"] = {
        "total_chunks": total_chunks,
        "inuse_chunks": inuse_chunks,
        "total_kb": round(total_bytes / 1024.0, 1),
        "inuse_pct": round(inuse_chunks * 100.0 / max(total_chunks, 1), 1),
    }

    # ── 情况 1：堆结构损坏（chunk 头被踩） ──
    if heap_result.corruptions:
        c = heap_result.corruptions[0]
        report["verdict"] = "corrupted"
        report["headline"] = "❌ 堆内存结构已损坏"
        report["detail"] = (
            "堆中的内存块是通过\"链表\"串起来的——每个块的开头记录了自己的大小和状态。"
            "现在偏移 +0x%x 处的块头信息被写坏了（%s），导致 glibc 无法继续管理后续内存块。"
        ) % (c.offset, c.reason)

        if c.prev:
            report["suspect"] = {
                "offset": c.prev.offset,
                "size": c.prev.size,
                "state": "使用中" if c.prev.inuse else "已释放",
                "why": "紧邻受损块的前一个内存块——越界写最常见的原因就是前一个块的数据"
                       "写超出了自己的边界，踩坏了下一个块的头信息",
            }
            report["detail"] += (
                "\n\n重点嫌疑是偏移 +0x%x 的那个块（%d 字节，%s）——"
                "它紧挨着被踩的位置，很可能就是它的数据越界了。"
            ) % (c.prev.offset, c.prev.size,
                 "正在使用" if c.prev.inuse else "已释放")

        # 指纹
        for fp in heap_result.fingerprints[:2]:
            report["evidence"].append(fp.desc)
            if fp.kind == "ascii":
                report["detail"] += (
                    "\n\n被踩区域发现了可读文字「%s」——"
                    "把这段文字拿到源码里搜索（grep），通常能直接找到是哪个模块写入的。"
                ) % fp.desc.split("'")[1][:30] if "'" in fp.desc else ""
            elif fp.kind == "pattern":
                report["detail"] += (
                    "\n\n被踩区域是重复的字节模式——这是 memset/数组越界写的典型特征。"
                )

    # ── 情况 2：堆头完好但数据被踩（延迟引爆） ──
    elif hasattr(heap_result, "victim_probe") and heap_result.victim_probe:
        report["verdict"] = "stomped"
        report["headline"] = "⚠ 堆数据被踩（结构完好但内容被改）"
        report["detail"] = (
            "堆的管理结构（块头链表）是完好的，但某个数据对象的内容被改写了。"
            "这种情况通常不是越界写穿 chunk 头，而是悬垂指针（Use-After-Free）"
            "或者相邻块的越界写恰好只踩到了数据区。"
        )
        if heap_result.fingerprints:
            for fp in heap_result.fingerprints[:1]:
                report["evidence"].append(fp.desc)

    # ── 情况 3：堆正常 ──
    else:
        report["verdict"] = "healthy"
        report["headline"] = "✅ 堆结构正常"
        report["detail"] = (
            "堆的块链表走查完毕，没有发现结构损坏。"
            "共 %d 个内存块，其中 %d 个正在使用（%.0f%%），总计 %.1f KB。"
        ) % (total_chunks, inuse_chunks,
             report["stats"]["inuse_pct"], report["stats"]["total_kb"])

    return report


_PAGE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>BMC Coredump 崩溃分析</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:18px;color:#58a6ff;margin-bottom:4px}
.sub{font-size:13px;color:#8b949e;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:14px}
.card h2{font-size:14px;color:#58a6ff;margin-bottom:12px}

/* 崩溃故事 */
.story-step{display:flex;gap:14px;padding:14px 0;border-bottom:1px solid #21262d}
.story-step:last-child{border-bottom:none}
.story-icon{font-size:24px;min-width:36px;text-align:center}
.story-body{flex:1}
.story-title{font-size:14px;font-weight:600;color:#e6edf3;margin-bottom:4px}
.story-detail{font-size:13px;color:#c9d1d9}
.story-detail code{background:#21262d;padding:2px 6px;border-radius:3px;font-size:12px;color:#79c0ff}
.story-hint{font-size:12px;color:#8b949e;margin-top:4px;padding:6px 10px;background:rgba(88,166,255,.06);border-radius:4px;border-left:2px solid #58a6ff}

/* 源码 */
.src-file{font-size:12px;color:#8b949e;margin-bottom:8px;font-family:monospace}
.src-line{display:flex;font-family:'Cascadia Code',Consolas,monospace;font-size:13px;padding:2px 8px;border-radius:2px}
.src-line .ln{color:#484f58;min-width:40px;text-align:right;margin-right:16px;user-select:none}
.src-line.crash{background:rgba(248,81,73,.15);border-left:3px solid #f85149}
.src-line.crash .ln{color:#f85149;font-weight:700}

/* 内存布局 */
.mem-bar{position:relative;height:60px;background:#161b22;border:1px solid #30363d;border-radius:6px;margin:12px 0;overflow:hidden}
.mem-block{position:absolute;top:0;bottom:0;border-right:1px solid #0d1117}
.mem-block.code{background:rgba(63,185,80,.35)}
.mem-block.heap{background:rgba(248,81,73,.35)}
.mem-block.stack{background:rgba(210,153,34,.35)}
.mem-block.ro{background:rgba(139,148,158,.2)}
.mem-block .mem-label{position:absolute;bottom:4px;left:6px;font-size:10px;color:#c9d1d9;text-shadow:0 1px 2px #000}
.mem-fault{position:absolute;top:-6px;bottom:-6px;width:3px;background:#f85149;border-radius:2px;z-index:5}
.mem-fault::after{content:'▼';position:absolute;top:-16px;left:-6px;color:#f85149;font-size:12px}
.mem-scale{display:flex;justify-content:space-between;font-size:10px;color:#8b949e;font-family:monospace;margin-top:4px}
.mem-legend{display:flex;gap:16px;font-size:11px;color:#8b949e;margin-top:8px}
.mem-legend span{display:flex;align-items:center;gap:4px}
.mem-legend .sw{width:12px;height:12px;border-radius:2px}

/* 线程 */
.thread-tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.thread-tab{padding:6px 14px;border-radius:6px;background:#21262d;border:1px solid #30363d;cursor:pointer;font-size:13px;transition:all .15s}
.thread-tab:hover{border-color:#58a6ff}
.thread-tab.active{background:#58a6ff;color:#0d1117;border-color:#58a6ff;font-weight:600}
.thread-tab.crash{border-color:#f85149}
.thread-tab.crash.active{background:#f85149;color:#fff}
.thread-tab .tid{font-weight:600}
.stack-frame{display:flex;gap:10px;padding:6px 10px;margin:2px 0;border-radius:4px;background:rgba(255,255,255,.03);font-size:13px;align-items:baseline}
.stack-frame:hover{background:rgba(88,166,255,.08)}
.stack-frame .lvl{color:#8b949e;min-width:28px}
.stack-frame .fn{color:#79c0ff;font-family:monospace;min-width:180px}
.stack-frame .src{color:#8b949e;font-size:12px}
.stack-frame.crash{border-left:3px solid #f85149}
.stack-frame .badge{font-size:10px;padding:1px 6px;border-radius:3px;margin-left:4px}
.stack-frame .badge.scan{background:rgba(210,153,34,.2);color:#d29922}
.stack-frame .badge.gdb{background:rgba(63,185,80,.2);color:#3fb950}

/* 堆 */
.heap-viz{display:flex;flex-wrap:wrap;gap:2px;padding:10px;background:rgba(0,0,0,.2);border-radius:4px}
.chunk{height:18px;border-radius:2px;transition:transform .1s}
.chunk:hover{transform:scaleY(1.3)}
.chunk.used{background:rgba(248,81,73,.6)}
.chunk.free{background:rgba(63,185,80,.4)}

/* 结论 */
.concl{padding:10px 14px;margin:4px 0;border-radius:6px;background:rgba(255,255,255,.03)}
.concl .conf{font-weight:700;margin-right:8px}
.concl .conf.ok{color:#3fb950}
.concl .conf.maybe{color:#d29922}
.concl .evd{font-size:12px;color:#8b949e;margin-top:2px}
</style>
</head>
<body>
<div class="wrap">
<h1>⚙ BMC Coredump 崩溃分析</h1>
<p class="sub" id="subtitle"></p>

<!-- ═══ 崩溃故事（递进式） ═══ -->
<div class="card">
<h2>📝 崩溃分析</h2>
<div id="story"></div>
</div>

<!-- ═══ 崩溃源码 ═══ -->
<div class="card" id="srcCard" style="display:none">
<h2>📄 崩溃代码</h2>
<div class="src-file" id="srcFile"></div>
<div id="source" style="background:#0d1117;border-radius:6px;padding:8px;overflow-x:auto"></div>
</div>

<!-- ═══ 变量生命周期追踪 ═══ -->
<div class="card" id="varTraceCard" style="display:none">
<h2>🔍 变量生命周期追踪 <span style="font-size:11px;color:#8b949e;font-weight:400">（这个指针从声明到崩溃经历了什么）</span></h2>
<div id="varTrace"></div>
</div>

<!-- ═══ 内存布局 ═══ -->
<div class="card">
<h2>🗺️ 进程内存布局 <span style="font-size:11px;color:#8b949e;font-weight:400">（地址从低到高，宽度≈大小）</span></h2>
<div class="mem-bar" id="memBar"></div>
<div class="mem-scale" id="memScale"></div>
<div class="mem-legend">
<span><span class="sw" style="background:rgba(63,185,80,.5)"></span>代码（CPU执行的指令）</span>
<span><span class="sw" style="background:rgba(248,81,73,.5)"></span>堆/数据（malloc/全局变量）</span>
<span><span class="sw" style="background:rgba(210,153,34,.5)"></span>线程栈（局部变量）</span>
<span><span class="sw" style="background:rgba(139,148,158,.3)"></span>只读（常量）</span>
</div>
<div id="memList" style="margin-top:10px;max-height:200px;overflow-y:auto"></div>
</div>

<!-- ═══ 线程 & 栈回溯 ═══ -->
<div class="card">
<h2>🧵 线程 & 栈回溯 <span style="font-size:11px;color:#8b949e;font-weight:400">（点击线程名切换）</span></h2>
<div class="thread-tabs" id="threadTabs"></div>
<div id="stackArea"></div>
</div>

<!-- ═══ 堆健康报告 ═══ -->
<div class="card" id="heapCard">
<h2>📦 堆健康报告</h2>
<div id="heapReport"></div>
</div>

<!-- ═══ 定位结论 ═══ -->
<div class="card">
<h2>🎯 定位结论</h2>
<div id="conclusions"></div>
</div>
</div>

<script>
const D = __DATA__;

// ── 副标题 ──
document.getElementById('subtitle').textContent =
    D.summary.process + ' · ' + D.summary.arch + ' · ' +
    D.summary.signal + ' @ ' + D.summary.fault_addr + ' · ' +
    D.summary.nthreads + ' 个线程';

// ── 崩溃故事 ──
const storyEl = document.getElementById('story');
D.story.forEach(step => {
    const div = document.createElement('div');
    div.className = 'story-step';
    div.innerHTML =
        '<div class="story-icon">' + step.icon + '</div>' +
        '<div class="story-body">' +
        '<div class="story-title">' + step.title + '</div>' +
        '<div class="story-detail">' + step.detail + '</div>' +
        (step.hint ? '<div class="story-hint">' + step.hint + '</div>' : '') +
        '</div>';
    storyEl.appendChild(div);
});

// ── 崩溃源码 ──
if (D.crash_source) {
    document.getElementById('srcCard').style.display = '';
    document.getElementById('srcFile').textContent =
        D.crash_source.file + ' : ' + D.crash_source.line + ' 行（红色高亮 = 崩溃行）';
    const srcEl = document.getElementById('source');
    D.crash_source.code.forEach(([ln, text, isCrash]) => {
        const line = document.createElement('div');
        line.className = 'src-line' + (isCrash ? ' crash' : '');
        line.innerHTML = '<span class="ln">' + ln + '</span><span>' +
            text.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</span>';
        srcEl.appendChild(line);
    });
}

// ── 变量生命周期追踪 ──
if (D.var_trace && D.var_trace.length > 0) {
    document.getElementById('varTraceCard').style.display = '';
    const vtEl = document.getElementById('varTrace');
    let html = '';

    if (D.var_root_cause) {
        html += '<div style="padding:10px 14px;margin-bottom:14px;border-radius:6px;' +
            'background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3)">' +
            '<div style="font-size:14px;font-weight:700;color:#f85149">🎯 根因</div>' +
            '<div style="font-size:13px;margin-top:4px">' + D.var_root_cause + '</div></div>';
    }

    html += '<div style="position:relative;padding-left:24px">';
    // 竖线
    html += '<div style="position:absolute;left:10px;top:8px;bottom:8px;width:2px;' +
        'background:#30363d"></div>';

    D.var_trace.forEach(ev => {
        const isCrash = ev.step === 'crash';
        const isRoot = ev.is_root_cause;
        const dotColor = isCrash ? '#f85149' : isRoot ? '#d29922'
            : ev.step === 'declaration' ? '#58a6ff'
            : ev.step.includes('missing') ? '#f85149'
            : ev.step === 'set_null' || ev.step === 'free' ? '#d29922'
            : '#3fb950';
        html += '<div style="position:relative;margin-bottom:16px">';
        // 节点圆点
        html += '<div style="position:absolute;left:-20px;top:6px;width:12px;height:12px;' +
            'border-radius:50%;background:' + dotColor + ';border:2px solid #0d1117"></div>';
        // 内容
        html += '<div style="' + (isCrash ? 'background:rgba(248,81,73,.08);padding:8px 12px;border-radius:6px;border-left:3px solid #f85149' :
                  isRoot ? 'background:rgba(210,153,34,.08);padding:8px 12px;border-radius:6px;border-left:3px solid #d29922' : '') + '">';
        html += '<div style="font-size:12px;color:#8b949e">' + ev.icon + ' ' + ev.title + '</div>';
        html += '<div style="font-size:13px;margin-top:2px">' + ev.detail + '</div>';
        if (ev.code) {
            html += '<div style="font-family:monospace;font-size:12px;color:#79c0ff;' +
                'background:#0d1117;padding:4px 8px;border-radius:4px;margin-top:4px">' +
                ev.code.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
        }
        if (ev.file && ev.line) {
            html += '<div style="font-size:11px;color:#8b949e;margin-top:2px">→ ' +
                ev.file + ':' + ev.line + '</div>';
        }
        html += '</div></div>';
    });

    html += '</div>';
    vtEl.innerHTML = html;
}
const memBar = document.getElementById('memBar');
const colors = {code:'rgba(63,185,80,.5)', heap:'rgba(248,81,73,.5)',
                stack:'rgba(210,153,34,.5)', ro:'rgba(139,148,158,.3)'};
const totalKb = D.mem_regions.reduce((s,r) => s + r.size_kb, 0);
let offset = 0;
D.mem_regions.forEach(r => {
    const pct = (r.size_kb / totalKb) * 100;
    const div = document.createElement('div');
    div.className = 'mem-block ' + r.kind;
    div.style.left = offset + '%';
    div.style.width = Math.max(pct, 0.5) + '%';
    div.style.background = colors[r.kind] || 'rgba(139,148,158,.2)';
    const label = r.module ? r.module.split('/').pop().substring(0,14) : r.label;
    if (pct > 3) {
        div.innerHTML = '<span class="mem-label">' + label + '</span>';
    }
    const sizeStr = r.size_kb > 1024 ? (r.size_kb/1024).toFixed(1)+'MB' : r.size_kb.toFixed(0)+'KB';
    div.title = r.label + (r.module ? '\n模块: ' + r.module : '') +
        '\n地址: 0x' + r.start.toString(16) +
        '\n大小: ' + sizeStr +
        '\n权限: ' + (r.r?'R':'-') + (r.w?'W':'-') + (r.x?'X':'-') +
        '\n占已映射内存: ' + pct.toFixed(1) + '%';
    memBar.appendChild(div);
    offset += pct;
});
document.getElementById('memScale').innerHTML =
    '<span>共 ' + D.mem_regions.length + ' 个区域，' +
    (totalKb > 1024 ? (totalKb/1024).toFixed(1) + ' MB' : totalKb.toFixed(0) + ' KB') +
    ' 已映射内存</span>';

// 内存明细列表
const memListEl = document.getElementById('memList');
D.mem_regions.forEach(r => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;padding:3px 6px;font-size:12px;' +
        'border-radius:3px;cursor:default';
    row.onmouseenter = () => row.style.background = 'rgba(255,255,255,.05)';
    row.onmouseleave = () => row.style.background = '';
    const c = colors[r.kind] || 'rgba(139,148,158,.3)';
    const sizeStr = r.size_kb > 1024 ? (r.size_kb/1024).toFixed(1)+'MB' : r.size_kb.toFixed(0)+'KB';
    row.innerHTML =
        '<span style="width:14px;height:14px;border-radius:2px;background:' + c + ';flex-shrink:0;margin-top:3px"></span>' +
        '<span style="font-family:monospace;color:#8b949e;min-width:140px">0x' + r.start.toString(16) + '</span>' +
        '<span style="min-width:60px;text-align:right;color:#c9d1d9">' + sizeStr + '</span>' +
        '<span style="min-width:40px;color:#8b949e">' + (r.r?'R':'-')+(r.w?'W':'-')+(r.x?'X':'-') + '</span>' +
        '<span style="color:#79c0ff">' + (r.module ? r.module.split('/').pop() : r.label) + '</span>';
    memListEl.appendChild(row);
});

// ── 线程 & 栈 ──
const tabsEl = document.getElementById('threadTabs');
const stackEl = document.getElementById('stackArea');
let activeTid = null;

function showThread(tid) {
    activeTid = tid;
    // 更新 tab 样式
    tabsEl.querySelectorAll('.thread-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tid == tid);
    });
    // 渲染栈
    stackEl.innerHTML = '';
    const thread = D.threads.find(t => t.tid == tid);
    if (!thread) return;
    if (thread.stack && thread.stack.length > 0) {
        thread.stack.forEach(f => {
            const div = document.createElement('div');
            div.className = 'stack-frame' + (f.level === 0 ? ' crash' : '');
            const srcBadge = f.source === 'scan'
                ? '<span class="badge scan">栈扫描</span>' : '';
            div.innerHTML =
                '<span class="lvl">#' + f.level + '</span>' +
                '<span class="fn">' + (f.func || '??').split('(')[0] + '</span>' +
                (f.loc ? '<span class="src">@ ' + f.loc.split('/').pop() + '</span>' : '') +
                srcBadge;
            div.title = '地址: ' + f.addr + (f.why ? '\n判定: ' + f.why : '');
            stackEl.appendChild(div);
        });
    } else {
        stackEl.innerHTML = '<div style="color:#8b949e;font-size:13px;padding:8px">' +
            (thread.is_crash ? '此线程的栈未被转储或已被破坏' : '无栈回溯数据') + '</div>';
    }
}

D.threads.forEach(t => {
    const tab = document.createElement('div');
    tab.className = 'thread-tab' + (t.is_crash ? ' crash' : '');
    tab.dataset.tid = t.tid;
    tab.innerHTML = (t.is_crash ? '🔴 ' : '') + '<span class="tid">TID ' + t.tid + '</span>';
    tab.onclick = () => showThread(t.tid);
    tabsEl.appendChild(tab);
});
// 默认选中崩溃线程
const crashTid = D.threads.find(t => t.is_crash);
showThread(crashTid ? crashTid.tid : (D.threads[0] ? D.threads[0].tid : 0));

// ── 堆健康报告 ──
const heapEl = document.getElementById('heapReport');
if (D.heap_report) {
    const hr = D.heap_report;
    let html = '';

    // 结论横幅
    const verdictColor = hr.verdict === 'healthy' ? '#3fb950'
        : hr.verdict === 'corrupted' ? '#f85149'
        : hr.verdict === 'stomped' ? '#d29922' : '#8b949e';
    html += '<div style="padding:12px 16px;border-radius:6px;margin-bottom:12px;' +
        'background:' + verdictColor + '18;border-left:4px solid ' + verdictColor + '">' +
        '<div style="font-size:16px;font-weight:700;color:' + verdictColor + '">' +
        hr.headline + '</div></div>';

    // 基本统计
    if (hr.stats && hr.stats.total_chunks > 0) {
        html += '<div style="display:flex;gap:20px;margin-bottom:12px;font-size:13px;color:#8b949e">' +
            '<span>📊 <b style="color:#c9d1d9">' + hr.stats.total_chunks + '</b> 个内存块</span>' +
            '<span>🔴 <b style="color:#c9d1d9">' + hr.stats.inuse_chunks + '</b> 个使用中 (' + hr.stats.inuse_pct + '%)</span>' +
            '<span>📏 总计 <b style="color:#c9d1d9">' + hr.stats.total_kb + ' KB</b></span>' +
            '</div>';
    }

    // 详细解释
    if (hr.detail) {
        html += '<div style="font-size:13px;line-height:1.8;color:#c9d1d9;' +
            'padding:12px;background:rgba(255,255,255,.03);border-radius:6px">' +
            hr.detail.replace(/\n/g, '<br>') + '</div>';
    }

    // 肇事嫌疑
    if (hr.suspect) {
        html += '<div style="margin-top:12px;padding:12px;border-radius:6px;' +
            'background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3)">' +
            '<div style="font-size:13px;font-weight:600;color:#f85149;margin-bottom:6px">🔍 重点嫌疑</div>' +
            '<div style="font-size:13px">' +
            '偏移 <code style="background:#21262d;padding:2px 6px;border-radius:3px">+0x' +
            hr.suspect.offset.toString(16) + '</code> 的内存块（' +
            hr.suspect.size + ' 字节，' + hr.suspect.state + '）</div>' +
            '<div style="font-size:12px;color:#8b949e;margin-top:4px">' + hr.suspect.why + '</div>' +
            '</div>';
    }

    // 证据
    if (hr.evidence && hr.evidence.length > 0) {
        html += '<div style="margin-top:12px"><div style="font-size:13px;font-weight:600;' +
            'color:#d29922;margin-bottom:6px">🧬 肇事线索</div>';
        hr.evidence.forEach(ev => {
            html += '<div style="font-size:12px;padding:6px 10px;margin:4px 0;' +
                'background:rgba(210,153,34,.08);border-radius:4px;' +
                'border-left:2px solid #d29922">' + ev + '</div>';
        });
        html += '</div>';
    }

    heapEl.innerHTML = html;
} else {
    heapEl.innerHTML = '<div style="color:#8b949e;font-size:13px">未检测到堆数据</div>';
}

// ── 结论 ──
const conclEl = document.getElementById('conclusions');
if (D.conclusions && D.conclusions.length > 0) {
    D.conclusions.forEach(c => {
        const div = document.createElement('div');
        div.className = 'concl';
        div.innerHTML =
            '<span class="conf ' + (c.confidence === '确认' ? 'ok' : 'maybe') + '">' +
            '[' + c.confidence + ']</span>' + c.text +
            '<div class="evd">依据: ' + c.evidence + '</div>';
        conclEl.appendChild(div);
    });
} else {
    conclEl.innerHTML = '<div style="color:#8b949e">暂无结论</div>';
}
</script>
</body>
</html>"""


class _VizHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(self.server.page_html.encode("utf-8"))
        elif parsed.path == "/api/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.server.viz_data,
                                        ensure_ascii=False).encode("utf-8"))
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass


def start_visualization(core, heap_result=None, matches=None, traces=None,
                        conclusions=None, cfi_frames=None, scan_results=None,
                        source_root=None, snippets=None,
                        preferred_port=8080, auto_open=True, timeout=0,
                        _prebuilt_data=None):
    if _prebuilt_data:
        viz_data = _prebuilt_data
    else:
        viz_data = build_viz_data(core, heap_result, matches, traces, conclusions,
                                  cfi_frames, scan_results, source_root, snippets)
    port = _find_free_port(preferred_port)
    if port is None:
        raise RuntimeError("端口 %d-%d 全部被占用" % (preferred_port, preferred_port + 99))
    local_ip = _get_local_ip()
    url = "http://%s:%d" % (local_ip, port)
    page_html = _PAGE.replace("__DATA__", json.dumps(viz_data, ensure_ascii=False))
    server = HTTPServer(("0.0.0.0", port), _VizHandler)
    server.page_html = page_html
    server.viz_data = viz_data
    print("\n" + "=" * 60)
    print("  📊 BMC Coredump 崩溃分析面板")
    print("  ➜ 本机:  http://localhost:%d" % port)
    print("  ➜ 局域网: %s" % url)
    print("=" * 60 + "\n")
    if auto_open:
        try:
            webbrowser.open("http://localhost:%d" % port)
        except Exception:
            pass
    if timeout > 0:
        timer = threading.Timer(timeout, server.shutdown)
        timer.daemon = True
        timer.start()
    return server, url

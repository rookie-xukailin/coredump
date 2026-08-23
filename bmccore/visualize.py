# -*- coding: utf-8 -*-
"""内存可视化 Web 面板：启动 HTTP 服务器展示堆/栈/模块映射图。

自动检测可用端口，明确告知用户 IP:PORT，不让用户猜。
纯 Python 标准库（http.server），无外部依赖，离线可用。
"""
import json
import os
import socket
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


def _find_free_port(preferred=8080, max_tries=100):
    """从 preferred 开始找一个可用端口。"""
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
    """获取本机可被局域网访问的 IP（不是 127.0.0.1）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))     # 不真的发包，只是让路由表选接口
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def build_viz_data(core, heap_result=None, matches=None):
    """把 core 的内存布局转为可视化 JSON。"""
    regions = []
    for r in core.regions:
        entry = {
            "start": r.vaddr,
            "end": r.vaddr + r.filesz,
            "size": r.filesz,
            "memsz": r.memsz,
            "flags": ("R" if r.flags & 4 else "-") +
                     ("W" if r.flags & 2 else "-") +
                     ("X" if r.flags & 1 else "-"),
            "type": _classify_region(r, core),
        }
        # 标注模块名
        if matches:
            for m in matches:
                if m.module and m.module.contains(r.vaddr):
                    entry["module"] = m.module.name
                    break
        regions.append(entry)

    threads = []
    for t in core.threads:
        threads.append({
            "tid": t.tid,
            "pc": t.pc,
            "sp": t.sp,
            "is_crash": t.is_crash,
            "signal": t.cursig,
        })

    heap_info = []
    if heap_result:
        for desc, chunks in heap_result.regions:
            chunk_list = [{
                "offset": c.offset,
                "size": c.size,
                "inuse": c.inuse,
            } for c in chunks[:200]]   # 最多展示 200 个
            heap_info.append({"region": desc, "chunks": chunk_list})
        if heap_result.corruptions:
            heap_info.append({
                "corruptions": [{
                    "offset": c.offset,
                    "size": c.size_value,
                    "reason": c.reason,
                } for c in heap_result.corruptions]
            })

    return {
        "regions": regions,
        "threads": threads,
        "heap": heap_info,
        "arch": core.arch.name if core.arch else "unknown",
        "signal": core.threads[0].cursig if core.threads else 0,
        "fault_addr": (core.siginfo or {}).get("addr"),
    }


def _classify_region(r, core):
    """给内存段一个人类可读的类型标签。"""
    if r.exec_bit and r.readable and not r.write_bit:
        return "code"
    if r.write_bit and r.readable and not r.exec_bit:
        # 检查是否是线程栈
        for t in core.threads:
            if r.vaddr <= t.sp < r.vaddr + r.memsz:
                return "stack(tid=%d)" % t.tid
        return "heap/data"
    if r.readable and not r.write_bit and not r.exec_bit:
        return "rodata"
    return "unknown"


_PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<title>BMC Coredump 内存可视化</title>
<style>
body {{ font-family: 'SF Mono', Consolas, monospace; margin: 0; background: #1a1a2e; color: #e0e0e0; }}
.header {{ padding: 16px 24px; background: #16213e; border-bottom: 2px solid #0f3460; }}
.header h1 {{ margin: 0; font-size: 18px; color: #00d4ff; }}
.container {{ display: flex; padding: 16px; gap: 16px; }}
.col {{ flex: 1; }}
.panel {{ background: #16213e; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
.panel h2 {{ font-size: 14px; color: #00d4ff; margin: 0 0 12px 0; border-bottom: 1px solid #0f3460; padding-bottom: 8px; }}
.region {{ display: flex; align-items: center; padding: 4px 8px; margin: 2px 0; border-radius: 4px; font-size: 12px; cursor: pointer; }}
.region:hover {{ background: #0f3460; }}
.region .bar {{ height: 16px; border-radius: 3px; margin-right: 8px; min-width: 4px; }}
.region .addr {{ color: #888; width: 140px; }}
.region .info {{ flex: 1; }}
.thread {{ padding: 8px; margin: 4px 0; border-radius: 4px; background: #0f3460; font-size: 12px; }}
.thread.crash {{ border: 1px solid #ff4444; background: #2a1a1a; }}
.heap-chunk {{ display: inline-block; margin: 1px; height: 12px; border-radius: 2px; }}
.heap-chunk.inuse {{ background: #ff6b6b; }}
.heap-chunk.free {{ background: #4ecdc4; }}
.heap-chunk.corrupt {{ background: #ffd93d; border: 1px solid #ff0000; }}
#tooltip {{ position: fixed; display: none; background: #0f3460; border: 1px solid #00d4ff; padding: 8px 12px; border-radius: 4px; font-size: 11px; pointer-events: none; z-index: 100; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚙ BMC Coredump 内存可视化</h1>
  <span style="color:#888;font-size:12px">架构: {arch} | 信号: SIG{signal} | 出错地址: {fault}</span>
</div>
<div class="container">
  <div class="col" style="flex:1.4">
    <div class="panel">
      <h2>内存映射（{region_count} 段，按地址排序）</h2>
      <div id="regions"></div>
    </div>
  </div>
  <div class="col">
    <div class="panel">
      <h2>线程（{thread_count} 个）</h2>
      <div id="threads"></div>
    </div>
    <div class="panel">
      <h2>堆布局（前 200 chunk）</h2>
      <div id="heap"></div>
    </div>
  </div>
</div>
<div id="tooltip"></div>
<script>
const data = {data};
const max_size = Math.max(...data.regions.map(r => r.size), 1);
const colors = {{code:'#4ecdc4', 'heap/data':'#ff6b6b', rodata:'#45b7d1', unknown:'#95a5a6'}};
const stackColor = '#f9ca24';

// 渲染内存段
const regionsDiv = document.getElementById('regions');
data.regions.sort((a,b) => a.start - b.start).forEach(r => {{
    const div = document.createElement('div');
    div.className = 'region';
    const color = r.type.startsWith('stack') ? stackColor : (colors[r.type] || '#888');
    const width = Math.max(Math.round(r.size / max_size * 200), 4);
    div.innerHTML = `<div class="bar" style="width:${{width}}px;background:${{color}}"></div>` +
        `<span class="addr">0x${{r.start.toString(16)}}-0x${{r.end.toString(16)}}</span>` +
        `<span class="info">${{r.module || r.type}} ${{r.flags}} (${{(r.size/1024).toFixed(1)}}K)</span>`;
    div.onmousemove = (e) => {{
        const tip = document.getElementById('tooltip');
        tip.style.display = 'block';
        tip.style.left = e.pageX + 12 + 'px';
        tip.style.top = e.pageY + 12 + 'px';
        tip.innerHTML = `Start: 0x${{r.start.toString(16)}}<br>End: 0x${{r.end.toString(16)}}<br>` +
            `Size: ${{(r.size/1024).toFixed(2)}} KB<br>Flags: ${{r.flags}}<br>Type: ${{r.type}}` +
            (r.module ? `<br>Module: ${{r.module}}` : '');
    }};
    div.onmouseleave = () => document.getElementById('tooltip').style.display = 'none';
    regionsDiv.appendChild(div);
}});

// 渲染线程
const threadsDiv = document.getElementById('threads');
data.threads.forEach(t => {{
    const div = document.createElement('div');
    div.className = 'thread' + (t.is_crash ? ' crash' : '');
    div.innerHTML = `<b>TID ${{t.tid}}</b> ${{t.is_crash ? '🔴 崩溃线程' : ''}}<br>` +
        `PC: 0x${{t.pc.toString(16)}} SP: 0x${{t.sp.toString(16)}}<br>` +
        `Signal: ${{t.signal || '-'}}`;
    threadsDiv.appendChild(div);
}});

// 渲染堆
const heapDiv = document.getElementById('heap');
if (data.heap && data.heap.length > 0) {{
    data.heap.forEach(h => {{
        if (h.chunks) {{
            const label = document.createElement('div');
            label.style.cssText = 'font-size:11px;color:#888;margin:4px 0;';
            label.textContent = h.region + ' (' + h.chunks.length + ' chunks)';
            heapDiv.appendChild(label);
            const wrap = document.createElement('div');
            h.chunks.forEach(c => {{
                const s = document.createElement('span');
                s.className = 'heap-chunk ' + (c.inuse ? 'inuse' : 'free');
                const w = Math.max(Math.round(c.size / 64), 2);
                s.style.width = Math.min(w, 40) + 'px';
                s.title = `offset:0x${{c.offset.toString(16)}} size:0x${{c.size.toString(16)}} ${{c.inuse?'in-use':'free'}}`;
                wrap.appendChild(s);
            }});
            heapDiv.appendChild(wrap);
        }}
        if (h.corruptions) {{
            const label = document.createElement('div');
            label.style.cssText = 'color:#ff6b6b;font-size:12px;margin:8px 0;';
            label.textContent = '⚠ 损坏点: ' + h.corruptions.map(c =>
                `+0x${{c.offset.toString(16)}} (${{c.reason}})`).join(', ');
            heapDiv.appendChild(label);
        }}
    }});
}} else {{
    heapDiv.innerHTML = '<span style="color:#888">无堆数据</span>';
}}
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
        pass    # 静默 HTTP 日志


def start_visualization(core, heap_result=None, matches=None,
                        preferred_port=8080, auto_open=True, timeout=0):
    """启动可视化服务器。

    返回 (server, url)——url 是可直接在浏览器打开的完整地址。
    timeout > 0 时自动在 N 秒后关闭；timeout == 0 时持续运行直到 Ctrl+C。
    """
    viz_data = build_viz_data(core, heap_result, matches)

    # 端口检测：从 preferred 开始找可用端口
    port = _find_free_port(preferred_port)
    if port is None:
        raise RuntimeError("端口 %d-%d 全部被占用" %
                           (preferred_port, preferred_port + 99))

    # 获取本机 IP（明确告知用户，不让猜）
    local_ip = _get_local_ip()
    url = "http://%s:%d" % (local_ip, port)

    # 渲染 HTML
    page_html = _PAGE_TEMPLATE.format(
        data=json.dumps(viz_data, ensure_ascii=False),
        arch=viz_data["arch"],
        signal=viz_data["signal"],
        fault="0x%x" % viz_data["fault_addr"] if viz_data["fault_addr"] else "-",
        region_count=len(viz_data["regions"]),
        thread_count=len(viz_data["threads"]),
    )

    server = HTTPServer(("0.0.0.0", port), _VizHandler)
    server.page_html = page_html
    server.viz_data = viz_data

    # 明确告知用户
    print()
    print("=" * 60)
    print("  📊 内存可视化面板已启动")
    print("  ➜ 本机访问:  http://localhost:%d" % port)
    print("  ➜ 局域网访问: %s" % url)
    print("  ➜ 按 Ctrl+C 停止" + ("" if timeout == 0 else "（%d 秒后自动关闭）" % timeout))
    print("=" * 60)
    print()

    if auto_open:
        try:
            webbrowser.open("http://localhost:%d" % port)
        except Exception:
            pass    # 无图形界面环境

    if timeout > 0:
        timer = threading.Timer(timeout, server.shutdown)
        timer.daemon = True
        timer.start()

    return server, url

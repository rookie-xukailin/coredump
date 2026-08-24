#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全量格可视化画廊：在 localhost:8080 浏览每一个"维度×架构"格的面板。

数据来自 viz_check.py 预构建的 viz/<tag>.json（含 results.json 状态）。
  /               索引页（全部格 + PASS/FAIL 徽标, 按批次分组）
  /cell/<tag>     该格的完整崩溃分析面板（同 analyze --viz 的页面）
  /api/data/<tag> 该格的面板数据 JSON

用法: python3 tools/viz_gallery.py [workdir] [port]
"""
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

W = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
    else "/tmp/coredump_work"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
PROJ = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "coredump-analyze")
sys.path.insert(0, PROJ)

from bmccore import visualize  # noqa: E402

VIZDIR = os.path.join(W, "viz")

# 分组顺序（批次内按字母序）
BATCHES = [
    ("基础内存维度(12)", ["null_write", "wild_mmio", "stack_overflow",
                     "heap_overflow", "double_free", "uaf_write", "oob_read",
                     "bad_funcptr", "stack_smash", "assert_fail",
                     "thread_crash", "shlib_crash"]),
    ("高难度内存维度(9)", ["ill_jump", "null_poison", "uaf_reuse", "deep_chain",
                      "hugespan", "dlopen_crash", "handler_crash",
                      "blame_thread", "stomped_late"]),
    ("并发资源竞态维度(6)", ["db_reload_race", "rec_delete_race",
                        "shm_truncate_bus", "db_index_corrupt",
                        "dblfree_concurrent", "db_compact_race"]),
    ("数据库引擎/动态库维度(6)", ["sqlite_close_race", "sqlite_corrupt_bus",
                           "sqlite_finalize_uaf", "lmdb_close_race",
                           "lmdb_truncate_bus", "dlclose_race"]),
    ("批次1·传统 C 语言经典(21)", ["realloc_dangling", "stack_local_return",
                            "free_nonheap", "uninit_stack_ptr", "off_by_one",
                            "int_overflow_alloc", "sprintf_overflow",
                            "strlen_noterm", "sizeof_pointer",
                            "union_confusion", "signed_unsigned",
                            "const_rodata_write", "endianness_cast",
                            "timer_after_free", "atexit_stale",
                            "shutdown_order", "fd_exhaust", "malloc_null",
                            "sigpipe_write", "fpe_divzero", "nest_signal"]),
    ("批次2·硬件/平台/嵌入式(10)", ["no_volatile_hw", "unaligned_arm",
                             "dma_alignment", "eeprom_corrupt",
                             "config_array_size", "argv_missing",
                             "init_order", "watchdog_stuck",
                             "thread_hang_kill", "lock_deadlock_kill"]),
    ("批次3·BMC/OpenBMC 特定(9)", ["ipmi_parse_overflow", "fru_corrupt_parse",
                            "sensor_hotplug", "i2c_timeout_stale",
                            "dbus_prop_crash", "power_transition",
                            "sel_full_error", "shm_unlink_alive",
                            "fifo_sigpipe"]),
    ("批次4·消息队列(5)", ["mq_consumer_uaf", "mq_recv_truncate",
                       "mq_deser_overflow", "msgq_rmid_race",
                       "queue_ring_overrun"]),
]
ARCHS = ["arm64", "arm32", "riscv64"]


def load_results():
    p = os.path.join(VIZDIR, "results.json")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return {}


def load_cell(tag):
    p = os.path.join(VIZDIR, tag + ".json")
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as f:
        return f.read()


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_index():
    res = load_results()
    parts = ["""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>BMC Coredump 全量矩阵画廊</title>
<style>
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:24px}
h1{font-size:20px;color:#58a6ff}
h2{font-size:15px;color:#79c0ff;margin:26px 0 8px;border-bottom:1px solid #30363d;padding-bottom:6px}
table{border-collapse:collapse;width:100%;font-size:13px}
td,th{padding:5px 10px;border:1px solid #21262d;text-align:left}
th{color:#8b949e;background:#161b22}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.pass{color:#3fb950;font-weight:600}
.fail{color:#f85149;font-weight:600}
.na{color:#8b949e}
.meta{font-size:12px;color:#8b949e}
.sum{margin:10px 0;padding:10px 14px;background:#161b22;border:1px solid #30363d;border-radius:6px}
</style></head><body>
<h1>⚙ BMC Coredump 全量测试矩阵 · 可视化画廊</h1>
<div class="sum" id="sum"></div>"""]
    cells = {}
    for fn in os.listdir(VIZDIR):
        if fn.endswith(".json") and fn != "results.json":
            tag = fn[:-5]
            if tag.endswith((".arm64", ".arm32", ".riscv64")):
                cells[tag] = True
    total = npass = nfail = 0
    for tag in cells:
        total += 1
        st = (res.get(tag) or {}).get("status")
        if st == "PASS":
            npass += 1
        elif st:
            nfail += 1
    parts.append("<script>document.getElementById('sum').textContent="
                 "'%d 格 · 面板数据校验 PASS %d / FAIL %d · 点击任意格查看完整分析面板';"
                 "</script>" % (total, npass, nfail))
    seen = set()
    for title, names in BATCHES:
        rows = ["<tr><th>维度</th><th>arm64</th><th>arm32</th>"
                "<th>riscv64</th></tr>"]
        any_row = False
        for n in names:
            tds = []
            for a in ARCHS:
                tag = "%s.%s" % (n, a)
                if tag in cells:
                    seen.add(tag)
                    st = (res.get(tag) or {}).get("status", "未校验")
                    cls = "pass" if st == "PASS" else \
                        "fail" if st == "FAIL" else "na"
                    meta = (res.get(tag) or {}).get("meta") or {}
                    hint = "%s @%s · %s线程" % (
                        meta.get("signal", "?"),
                        meta.get("fault_addr", "-"),
                        meta.get("nthreads", "?"))
                    tds.append('<td><a href="/cell/%s" title="%s">'
                               '<span class="%s">%s</span></a>'
                               ' <span class="meta">%s</span></td>'
                               % (tag, esc(hint), cls, st,
                                  esc(meta.get("signal", ""))))
                else:
                    tds.append('<td class="na">—</td>')
            rows.append("<tr><td>%s</td>%s</tr>" % (esc(n), "".join(tds)))
            any_row = True
        if any_row:
            parts.append("<h2>%s</h2><table>%s</table>"
                         % (esc(title), "".join(rows)))
    stray = sorted(set(cells) - seen)
    if stray:
        rows = []
        for tag in stray:
            st = (res.get(tag) or {}).get("status", "未校验")
            cls = "pass" if st == "PASS" else "fail" if st == "FAIL" else "na"
            rows.append('<tr><td><a href="/cell/%s">%s</a></td>'
                        '<td class="%s">%s</td></tr>' % (tag, esc(tag), cls, st))
        parts.append("<h2>其他</h2><table>%s</table>" % "".join(rows))
    parts.append("</body></html>")
    return "".join(parts).encode("utf-8")


NAV = """<div style="position:sticky;top:0;z-index:99;background:#161b22;
border-bottom:1px solid #30363d;padding:8px 20px;font-size:13px">
<a href="/" style="color:#58a6ff;text-decoration:none">← 全量矩阵画廊</a>
<span style="color:#8b949e;margin-left:12px">%s</span></div>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path in ("/", "/index.html"):
            body = build_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif path.startswith("/cell/"):
            tag = path[len("/cell/"):]
            data = load_cell(tag)
            if data is None:
                self.send_error(404, "无该格数据: %s（先运行 viz_check.py）" % tag)
                return
            page = visualize._PAGE.replace("__DATA__", data)
            # 注入导航条
            page = page.replace("<body>",
                                "<body>" + NAV % esc(tag), 1)
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif path.startswith("/api/data/"):
            tag = path[len("/api/data/"):]
            data = load_cell(tag)
            if data is None:
                self.send_error(404, "no such cell")
                return
            body = data.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            self.send_error(404)
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print("=" * 60)
    print("  🖼  BMC Coredump 全量矩阵画廊")
    print("  ➜  http://localhost:%d  (%d 格预构建数据)" % (
        PORT, len([f for f in os.listdir(VIZDIR)
                   if f.endswith(".json") and f != "results.json"])
        if os.path.isdir(VIZDIR) else 0))
    print("=" * 60)
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线矩阵判定：--offline 模式的 99 格全量验证。

规则（与在线版的差异）：
  - backtrace 必须为 skipped（离线禁外部工具；出现 ok 即判定失败）
  - 结论关键词必须命中（同在线）
  - 证据：ev 命中即过；个别"证据天然来自 gdb 回溯"的格按表豁免并注明
  - symbols/triage 必须为 ok（纯 Python 能力，离线不受影响）
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verdict_matrix import EXPECT, EXPECT_ARCH, ARCHS, read, find_report  # noqa

W = "/tmp/coredump_work"
LOGS = W + "/logs/matrix"
REP = W + "/reports_offline"

# 证据豁免（离线时该证据唯一来源是 gdb 回溯；结论本身仍然必须命中）
OFFLINE_EXEMPT = {
    ("stack_overflow", "*"): "结论为栈溢出判定",
    ("hugespan", "*"): "SP 已出所有已转储段，无栈可扫",
    ("handler_crash", "*"): "信号处理函数帧只能由 gdb 展开 sigtramp 链",
    ("null_poison", "*"): "崩溃帧在 libc free 内部，应用帧证据在线由 gdb 内联帧提供",
}


def main():
    summary = read(LOGS + "/summary_offline.log")
    rows, npass, nfail, nskip = [], 0, 0, 0
    for name, base in EXPECT.items():
        for arch in ARCHS:
            over = EXPECT_ARCH.get((name, arch), base)
            if over is None:
                rows.append((name, arch, "SKIP(环境限制)"))
                nskip += 1
                continue
            kw, ev, _deg = over
            tag = "%s.%s" % (name, arch)
            fails = []
            if "[%s] ANALYZE-OK" % tag not in summary:
                fails.append("analyze未成功")
            alog = read(os.path.join(LOGS, tag + ".offline.log"))
            rep = read(find_report_offline(tag))
            if not rep:
                fails.append("无报告")
            m = re.search(r"技能 symbols\s+(\S+)", alog)
            if not m or not m.group(1).startswith("ok"):
                fails.append("symbols非ok")
            m = re.search(r"技能 triage\s+(\S+)", alog)
            if not m or not m.group(1).startswith("ok"):
                fails.append("triage非ok")
            m = re.search(r"技能 backtrace\s+(\S+)", alog)
            if m and m.group(1).startswith("ok"):
                fails.append("离线却调用了gdb")
            concl = "\n".join(l for l in alog.splitlines() if l.strip().startswith("["))
            if not any(k.lower() in concl.lower() for k in kw.split("|")):
                fails.append("结论缺[%s]" % kw)
            if ev not in rep and (name, "*") not in OFFLINE_EXEMPT:
                fails.append("报告缺证据[%s]" % ev)
            st = "PASS" if not fails else "FAIL:" + ",".join(fails)
            if fails:
                nfail += 1
            else:
                npass += 1
            if ev not in rep and (name, "*") in OFFLINE_EXEMPT and not fails:
                st += "(证据豁免:%s)" % OFFLINE_EXEMPT[(name, "*")][:20]
            rows.append((name, arch, st))
    w = max(len(r[0]) for r in rows)
    for name, arch, st in rows:
        print("%-*s %-8s %s" % (w, name, arch, st))
    print("=" * 50)
    print("OFFLINE PASS %d / FAIL %d / SKIP %d" % (npass, nfail, nskip))
    return 1 if nfail else 0


def find_report_offline(tag):
    d = os.path.join(REP, tag)
    if not os.path.isdir(d):
        return ""
    for fn in sorted(os.listdir(d)):
        if fn.endswith("_report.md"):
            return os.path.join(d, fn)
    return ""


if __name__ == "__main__":
    sys.exit(main())

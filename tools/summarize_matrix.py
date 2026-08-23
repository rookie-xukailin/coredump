#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总 60 格：每格输出 确认结论首条 + 回溯崩溃帧 + 技能简况"""
import os
import re

W = "/tmp/coredump_work"
LOGS = W + "/logs/matrix"

CASES = ["null_write", "wild_mmio", "stack_overflow", "heap_overflow", "double_free",
         "uaf_write", "oob_read", "bad_funcptr", "stack_smash", "assert_fail",
         "thread_crash", "shlib_crash", "ill_jump", "null_poison", "uaf_reuse",
         "deep_chain", "hugespan", "dlopen_crash", "handler_crash", "blame_thread"]
ARCHS = ["arm64", "arm32", "riscv64"]


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


for name in CASES:
    print("### %s" % name)
    for arch in ARCHS:
        alog = read("%s/%s.%s.analyze.log" % (LOGS, name, arch))
        # 首条确认结论
        concl = ""
        for l in alog.splitlines():
            ls = l.strip()
            if ls.startswith("[确认]"):
                concl = ls[4:].strip()
                break
        # backtrace/scan 状态
        bt = re.search(r"技能 backtrace\s+(\S+)", alog)
        sc = re.search(r"技能 scan\s+ok: (\d+) 个确认帧", alog)
        # 报告里崩溃线程 bt 的 #0/#1 帧
        rep = ""
        d = "%s/reports/%s.%s" % (W, name, arch)
        if os.path.isdir(d):
            for fn in os.listdir(d):
                if fn.endswith("_report.md"):
                    rep = read(os.path.join(d, fn))
                    break
        frames = []
        crash_sec = re.findall(r"## 线程 LWP \d+ 回溯（崩溃线程）\n+```\n(.*?)```",
                               rep, re.S) or re.findall(r"## 线程 LWP \d+ 回溯\n+```\n(.*?)```", rep, re.S)
        if crash_sec:
            for l in crash_sec[0].splitlines()[:2]:
                mm = re.match(r"#(\d+)\s+(0x[0-9a-f]+|\S+)\s*(.*)", l.strip())
                if mm:
                    frames.append("#%s %s" % (mm.group(1), (mm.group(3) or mm.group(2))[:46]))
        print("  %-8s | %s | bt=%s scan=%s帧 | %s" % (
            arch, (frames[0] if frames else "-")[:52],
            "ok" if (bt and bt.group(1).startswith("ok")) else bt.group(1)[:6] if bt else "?",
            sc.group(1) if sc else "0", concl[:64]))
    print()

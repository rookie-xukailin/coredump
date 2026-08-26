#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可视化面板全量校验：每个"维度×架构"格构建 viz 数据 + 结构断言。

对工作目录 cores/ 下全部 core（99 旧格 + 120 新格）逐格：
  1. intake 解包 -> Pipeline(符号表模式, 同 analyze) -> build_viz_data
  2. 结构断言（summary/story/threads/mem_regions/conclusions/JSON 序列化）
  3. 渲染整页 HTML（长度健全性）
  4. 预构建 JSON 落盘 viz/<tag>.json 供 viz_gallery.py 使用

用法: python3 tools/viz_check.py [workdir] [--cells name.arch,...]
"""
import glob
import json
import os
import re
import sys
import time

W = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
    else "/tmp/coredump_work"
PROJ = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "swrd-skill-coredump-analyze")
sys.path.insert(0, PROJ)
sys.path.insert(0, os.path.join(PROJ, "open", "pyelftools"))

from bmccore.intake import intake                      # noqa: E402
from bmccore.skills import Pipeline                    # noqa: E402
from bmccore.config import Config                      # noqa: E402
from bmccore import visualize                          # noqa: E402

CORES = os.path.join(W, "cores")
LOGS = os.path.join(W, "logs", "matrix")
VIZDIR = os.path.join(W, "viz")

ARCH_RE = re.compile(r"_(arm64|arm32|riscv64)$")


def discover_cells():
    """扫描 cores 目录得到全部 (name, arch) 格。"""
    cells = set()
    for f in os.listdir(CORES):
        m = re.match(r"^(.+?)_(arm64|arm32|riscv64)(?:\.core|\.core\.gz)$", f)
        if m:
            cells.add((m.group(1), m.group(2)))
            continue
        m = re.match(r"^1_core-\d+-(.+)_(arm64|arm32|riscv64)-\d+\.tar\.gz$", f)
        if m:
            cells.add((m.group(1), m.group(2)))
    return sorted(cells)


def find_core(name, arch):
    for pat in ("%s_%s.core", "%s_%s.core.gz"):
        p = os.path.join(CORES, pat % (name, arch))
        if os.path.isfile(p):
            return p
    hits = glob.glob(os.path.join(
        CORES, "1_core-*-%s_%s-*.tar.gz" % (name, arch)))
    return hits[0] if hits else None


def check_cell(name, arch):
    """返回 (status, fails, warns, meta)。"""
    tag = "%s.%s" % (name, arch)
    core_path = find_core(name, arch)
    if not core_path:
        return "NO-CORE", ["core 文件缺失"], [], {}

    res = intake(core_path, keep_temp=False)
    cfg = Config()
    cfg.symbol_table = os.path.join(W, "symtab")
    cfg.source_root = os.path.join(W, "cases")
    cfg.offline = True            # 纯 Python：CFI 回溯 + 栈扫描, 不依赖 gdb
    clog = os.path.join(LOGS, tag + ".console.log")
    if os.path.isfile(clog):
        cfg.console_log = clog

    pipe = Pipeline(res.core_path, cfg, log=lambda m: None)
    results = pipe.run()
    core = results.get("core")
    if core is None:
        return "INTAKE-FAIL", ["Pipeline 未产出 core 对象"], [], {}

    viz_data = visualize.build_viz_data(
        core,
        heap_result=results.get("heap_result"),
        matches=results.get("matches", []),
        traces=results.get("traces"),
        conclusions=results.get("conclusions"),
        cfi_frames=results.get("cfi_frames"),
        scan_results=results.get("scan_results"),
        source_root=cfg.source_root,
        snippets=results.get("snippets"),
        deepdive=results.get("deepdive"),
        framevars=results.get("framevars"),
        regs_deep=results.get("regs_deep"),
        stackdump=results.get("stackdump"),
        lock_result=results.get("lock_result"),
        addr_names=results.get("addr_names"),
    )

    fails, warns = [], []
    s = viz_data.get("summary") or {}
    for k in ("signal", "fault_addr", "arch", "process", "nthreads"):
        if k not in s:
            fails.append("summary 缺 %s" % k)
    if not s.get("signal"):
        fails.append("signal 为空")
    story = viz_data.get("story") or []
    if len(story) < 2:
        fails.append("story 步骤 %d < 2" % len(story))
    threads = viz_data.get("threads") or []
    if not threads:
        fails.append("threads 为空")
    else:
        for t in threads:
            for k in ("tid", "pc", "sp", "stack"):
                if k not in t:
                    fails.append("线程 %s 缺 %s" % (t.get("tid"), k))
        if not any(t.get("is_crash") for t in threads):
            fails.append("无崩溃线程标记")
        else:
            crash = next(t for t in threads if t.get("is_crash"))
            if not crash.get("stack"):
                warns.append("崩溃线程栈为空(渲染占位)")
    if not (viz_data.get("mem_regions") or []):
        fails.append("mem_regions 为空")
    if not (viz_data.get("conclusions") or []):
        fails.append("conclusions 为空")
    # 深度证据区：键必须存在（值可为 None——离线模式无 gdb 时无反汇编）
    for k in ("frame_vars", "registers_deep", "stack_dump", "disasm",
              "expr_evals", "locks"):
        if k not in viz_data:
            fails.append("viz 缺深度字段 %s" % k)
    if not (viz_data.get("registers_deep") or []):
        fails.append("registers_deep 为空")
    story_txt = " ".join(s.get("detail", "") + s.get("hint", "")
                         for s in story)
    story_txt += " " + " ".join(
        c.get("text", "") for c in (viz_data.get("conclusions") or []))
    if not (viz_data.get("stack_dump") or []):
        if "栈溢出" in story_txt:
            warns.append("stack_dump 为空（栈溢出形态：SP 已越出转储区）")
        else:
            fails.append("stack_dump 为空")

    try:
        payload = json.dumps(viz_data, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        return "VIZ-FAIL", ["JSON 序列化失败: %s" % e], warns, {}
    page = visualize._PAGE.replace("__DATA__", payload)
    if len(page) < 20000:
        fails.append("页面 HTML 过小(%d)" % len(page))

    meta = {
        "signal": s.get("signal"),
        "fault_addr": s.get("fault_addr"),
        "arch": s.get("arch"),
        "nthreads": s.get("nthreads"),
        "story_steps": len(story),
        "crash_stack": len(next((t.get("stack") for t in threads
                                 if t.get("is_crash")), [])),
        "conclusions": len(viz_data.get("conclusions") or []),
        "crash_source": bool(viz_data.get("crash_source")),
        "var_trace": len(viz_data.get("var_trace") or []),
        "regs_decoded": len(viz_data.get("registers_deep") or []),
        "stack_words": len(viz_data.get("stack_dump") or []),
        "frame_vars": sum(len(f.get("vars", []))
                          for f in ((viz_data.get("frame_vars") or {})
                                    .get("frames", []))),
    }
    with open(os.path.join(VIZDIR, tag + ".json"), "w",
              encoding="utf-8") as f:
        f.write(payload)
    return ("PASS" if not fails else "FAIL"), fails, warns, meta


def main():
    os.makedirs(VIZDIR, exist_ok=True)
    cells = discover_cells()
    only = None
    if "--cells" in sys.argv:
        only = set(sys.argv[sys.argv.index("--cells") + 1].split(","))
    if only:
        cells = [c for c in cells if "%s.%s" % c in only]

    rows = []
    npass = nfail = 0
    t0 = time.time()
    results_out = {}
    for i, (name, arch) in enumerate(cells):
        tag = "%s.%s" % (name, arch)
        st, fails, warns, meta = check_cell(name, arch)
        rows.append((tag, st, ",".join(fails) if fails else
                     (";" + ";".join(warns) if warns else "")))
        results_out[tag] = {"status": st, "fails": fails, "warns": warns,
                            "meta": meta}
        if st == "PASS":
            npass += 1
        else:
            nfail += 1
        print("[%3d/%3d] %-34s %-8s %s" % (i + 1, len(cells), tag, st,
                                           ";".join(fails + warns)))
        sys.stdout.flush()
    with open(os.path.join(VIZDIR, "results.json"), "w",
              encoding="utf-8") as f:
        json.dump(results_out, f, ensure_ascii=False, indent=1)
    print("=" * 60)
    print("VIZ PASS %d / FAIL %d / 共 %d 格  (%.1fs)" % (
        npass, nfail, len(cells), time.time() - t0))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())

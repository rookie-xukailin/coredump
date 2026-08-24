# -*- coding: utf-8 -*-
"""console 日志解析：提取 glibc 报错等关键证据行。

glibc 检测到堆损坏时打印的原因（free(): invalid pointer 等）只出现在
stderr/console，core 文件里没有——有这份日志，堆取证直接从盲扫升级为定向。"""
import io
import re

_PATTERNS = [
    re.compile(r"(malloc|free|realloc|calloc)\s*\(\s*\)\s*:\s*.+", re.I),
    re.compile(r"double free|corruption|corrupted", re.I),
    re.compile(r"invalid pointer|invalid size|unaligned", re.I),
    re.compile(r"stack smashing detected", re.I),
    re.compile(r"buffer overflow detected|overflow detected", re.I),
    re.compile(r"Segmentation fault|SIGSEGV|Aborted|SIGABRT", re.I),
    re.compile(r"assert", re.I),
    re.compile(r"out of memory|OOM|Cannot allocate", re.I),
    re.compile(r"core dumped", re.I),
]


def extract_key_lines(path, context=1, max_hits=40):
    """返回 [(行号, 文本)]：命中的关键行 ±context 行。"""
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return [], "无法读取 console 日志: %s" % path

    hits = []
    seen = set()
    for i, line in enumerate(lines):
        if any(p.search(line) for p in _PATTERNS):
            for j in range(max(0, i - context), min(len(lines), i + context + 1)):
                if j not in seen:
                    seen.add(j)
                    hits.append((j + 1, lines[j].rstrip()))
            if len(hits) > max_hits * 3:
                break
    return hits, None

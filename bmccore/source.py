# -*- coding: utf-8 -*-
"""技能5：源码联动——按 file:line 到源码树抠片段（崩溃行高亮 ±5 行）。"""
import io
import os


class SourceIndex(object):
    def __init__(self, root):
        self.root = os.path.abspath(root) if root else None
        self._by_name = None       # {basename: [绝对路径, ...]}

    def _build(self):
        self._by_name = {}
        if not self.root or not os.path.isdir(self.root):
            return
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in (".git", ".svn", "out", "build")]
            for fn in filenames:
                if fn.endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".s", ".S")):
                    self._by_name.setdefault(fn, []).append(os.path.join(dirpath, fn))
            if sum(len(v) for v in self._by_name.values()) > 200000:
                break    # 超大工程保护

    def locate(self, file_path):
        """按编译路径（如 /build/proj/src/a.c）在源码树中定位真实文件。"""
        if not self.root:
            return None
        if self._by_name is None:
            self._build()
        base = os.path.basename(file_path.replace("\\", "/"))
        cands = self._by_name.get(base)
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        # 多个同名：取与编译路径后缀匹配最长的
        want = file_path.replace("\\", "/")
        best, best_score = cands[0], -1
        for c in cands:
            cn = c.replace("\\", "/")
            common = 0
            for a, b in zip(reversed(want.split("/")), reversed(cn.split("/"))):
                if a == b:
                    common += 1
                else:
                    break
            if common > best_score:
                best, best_score = c, common
        return best

    def snippet(self, file_path, line, context=5):
        """返回 (真实路径, [(行号, 内容, 是否崩溃行)]) 或 None。"""
        real = self.locate(file_path)
        if not real:
            return None
        try:
            with io.open(real, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return None
        line = max(1, min(int(line), len(lines)))
        lo = max(1, line - context)
        hi = min(len(lines), line + context)
        return real, [(n, lines[n - 1].rstrip("\n"), n == line) for n in range(lo, hi + 1)]

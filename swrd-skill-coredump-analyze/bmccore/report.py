# -*- coding: utf-8 -*-
"""报告输出：report.md（人读，带可信度标注） + report.json（机读）。"""
import io
import json
import os
from datetime import datetime


class Report(object):
    """分节收集，双格式输出。"""

    def __init__(self, title):
        self.title = title
        self.meta = {}
        self.sections = []          # [(级别, 标题, 渲染函数或行列表)]

    def add(self, title, lines, level=2):
        self.sections.append((level, title, list(lines)))

    def add_kv_table(self, title, pairs):
        lines = ["| 项 | 值 |", "|---|---|"]
        for k, v in pairs:
            lines.append("| %s | %s |" % (k, str(v).replace("|", "\\|")))
        self.add(title, lines)

    # ------------------------------------------------------------------
    def render_markdown(self):
        out = ["# %s" % self.title, "",
               "> 生成时间: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""]
        for level, title, lines in self.sections:
            out.append("%s %s" % ("#" * level, title))
            out.append("")
            for ln in lines:
                out.append(str(ln))
            out.append("")
        return "\n".join(out) + "\n"

    def to_dict(self):
        return {"title": self.title, "meta": self.meta,
                "sections": [{"title": t, "lines": lines} for _lv, t, lines in self.sections]}

    def render_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def write(self, outdir, fmt="both", stem="report"):
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        written = []
        if fmt in ("md", "both"):
            p = os.path.join(outdir, stem + ".md")
            with io.open(p, "w", encoding="utf-8") as f:
                f.write(self.render_markdown())
            written.append(p)
        if fmt in ("json", "both"):
            p = os.path.join(outdir, stem + ".json")
            with io.open(p, "w", encoding="utf-8") as f:
                f.write(self.render_json())
            written.append(p)
        return written

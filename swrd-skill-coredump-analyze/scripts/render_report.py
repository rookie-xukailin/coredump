#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""叙事 HTML 报告渲染器（LLM 只写 narrative.json，不碰 HTML）。

用法：
    python3.8 scripts/render_report.py <narrative.json> \
        [--engine <bmccore *_report.json>] \
        [--out <输出.html>] [--case <案例名>]

narrative.json 由 AI 按技能 SKILL.md 叙事六步法产出，字段：
    summary: {process, arch, signal, fault_addr, crash_point, tldr, tldr_level}
    scene:  [叙事段落（markdown：段落/表格/```代码块```/**粗体**/`行内码`）]
    thread_roles: [{tid, role, action, evidence}]
    root_cause: {mechanism(md), culprit(md)}
    fixes:  [{title, body(md)}]
    confidence: [{level, claim, evidence}]
    gaps:   [字符串]
--engine 传入 bmccore 的 *_report.json 时，第 8 节自动附上引擎原始取证
（概览/线程现场还原/回溯/栈扫描/堆取证/锁分析/变量生命周期/console）。
"""
import datetime
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_TMPL = os.path.join(os.path.dirname(_HERE), "templates", "report_template.html")

_EVIDENCE_KEYWORDS = [
    ("概览", "概览"), ("线程现场还原", "线程现场还原（每线程一行）"),
    ("反汇编", "崩溃现场反汇编"), ("帧变量", "崩溃帧变量（运行时值）"),
    ("寄存器", "寄存器全解码"), ("栈内存", "崩溃现场栈内存"),
    ("回溯", "线程回溯（gdb）"), ("栈扫描", "栈扫描兜底"),
    ("堆对象还原", "堆对象还原（字段级）"),
    ("堆取证", "堆取证（glibc）"), ("锁", "线程锁关联分析"),
    ("表达式求值", "gdb 表达式求值"),
    ("变量生命周期", "变量生命周期（vartrace）"), ("console", "console 日志关键行"),
    ("定位结论", "引擎定位结论"), ("技能状态", "技能状态"),
]


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _inline(s):
    """行内 markdown：**粗体** 与 `行内码`（输入须已转义）。"""
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def md_lite(md):
    """极简 markdown → HTML：代码围栏 / 表格 / 无序列表 / 段落 / 行内标记。"""
    if md is None:
        return "<p>（待补）</p>"
    out = []
    lines = str(md).replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>%s</code></pre>" % _esc("\n".join(buf)))
            continue
        if ln.strip().startswith("|") and i + 1 < len(lines) and \
                re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(cells)
                i += 1
            head, body = rows[0], rows[2:] if len(rows) > 2 else []
            t = "<table><tr>%s</tr>%s</table>" % (
                "".join("<th>%s</th>" % _inline(_esc(c)) for c in head),
                "".join("<tr>%s</tr>" % "".join(
                    "<td>%s</td>" % _inline(_esc(c)) for c in r) for r in body))
            out.append(t)
            continue
        if ln.strip().startswith(("- ", "* ")):
            items = []
            while i < len(lines) and lines[i].strip().startswith(("- ", "* ")):
                items.append("<li>%s</li>" % _inline(_esc(lines[i].strip()[2:])))
                i += 1
            out.append("<ul>%s</ul>" % "".join(items))
            continue
        if ln.strip():
            buf = []
            while i < len(lines) and lines[i].strip() and \
                    not lines[i].strip().startswith(("```", "|", "- ", "* ")):
                buf.append(lines[i].strip())
                i += 1
            if not buf:
                # 当前行是表格符开头但未构成表格（无分隔行）等未匹配形态：
                # 按原文消费掉本行，防止外层循环原地踏步
                buf.append(lines[i].strip())
                i += 1
            out.append("<p>%s</p>" % _inline(_esc(" ".join(buf))))
            continue
        i += 1
    return "\n".join(out)


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check(narr):
    """校验 narrative.json 必填/建议字段。返回 (errors, warnings)。"""
    errors, warns = [], []
    s = narr.get("summary") or {}
    if not s.get("tldr"):
        errors.append("summary.tldr 缺失（一句话根因）")
    if not s.get("tldr_level"):
        errors.append("summary.tldr_level 缺失（确认/疑似/建议）")
    if not (narr.get("scene") or []):
        errors.append("scene 缺失（现场还原叙事段落，至少 1 段）")
    rc = narr.get("root_cause") or {}
    if not rc.get("mechanism"):
        errors.append("root_cause.mechanism 缺失（机制解释）")
    # 硬门禁：业务源码证据——scene/mechanism/culprit 合计至少 1 处 file:line
    blob = "\n".join(narr.get("scene") or []) + "\n" + \
        (rc.get("mechanism") or "") + "\n" + (rc.get("culprit") or "")
    if not re.search(r"[\w\-]+\.(?:c|h|cc|cpp|cxx|hpp):\d+", blob):
        errors.append("业务源码证据缺失：scene/root_cause 中没有任何业务源码 "
                      "file:line 引用（DoD 第 4 条硬门禁）。'崩溃在 glibc 内部'"
                      "不是跳过读码的理由——用堆指纹/DIE 变量名/受害结构体把"
                      "嫌疑指回业务模块并读码，或在 gaps 写明卡点")
    if not (narr.get("fixes") or []):
        warns.append("fixes 为空（应有可执行修复建议）")
    if not (narr.get("confidence") or []):
        warns.append("confidence 为空（应逐条标注可信度）")
    if not (narr.get("thread_roles") or []):
        warns.append("thread_roles 为空（多线程场景应有线程角色表）")
    anim = narr.get("animation")
    if anim is None:
        warns.append("animation 缺失（建议提供分镜：事故还原动画，通俗易懂）")
    else:
        if not (anim.get("actors") or []):
            warns.append("animation.actors 为空（应有演员表：线程/锁/对象）")
        steps = anim.get("steps") or []
        if not steps:
            warns.append("animation.steps 为空（至少 1 步分镜）")
        elif len(steps) > 10:
            warns.append("animation.steps 有 %d 步（超过 10 步建议精简）" % len(steps))
        actor_ids = set(a.get("id") for a in anim.get("actors") or [])
        for i, st in enumerate(steps):
            if not st.get("cap"):
                warns.append("animation.steps[%d] 缺 cap（通俗字幕）" % i)
            for key in (st.get("states") or {}):
                if key not in actor_ids:
                    warns.append("animation.steps[%d].states 引用未知演员 %r" % (i, key))
            for ar in (st.get("arrows") or []):
                if len(ar) >= 2 and (ar[0] not in actor_ids or ar[1] not in actor_ids):
                    warns.append("animation.steps[%d].arrows 引用未知演员 %r→%r" % (i, ar[0], ar[1]))
    return errors, warns


def render(narr, engine=None, case=None):
    s = narr.get("summary", {}) or {}
    case = case or narr.get("case") or s.get("process") or "coredump"
    meta_bits = []
    for k, label in (("process", "进程"), ("arch", "架构"), ("signal", "信号"),
                     ("fault_addr", "出错地址"), ("crash_point", "崩溃点")):
        if s.get(k):
            meta_bits.append("<span><b>%s</b>：%s</span>" % (label, _esc(s[k])))
    meta_html = " ".join(meta_bits) or "<span>（待补概览）</span>"

    scene_html = "\n".join(md_lite(p) for p in (narr.get("scene") or [])) \
        or "<p>（待补）</p>"

    roles = narr.get("thread_roles") or []
    if roles:
        roles_html = "<table><tr><th>tid</th><th>角色</th><th>案发时在做的业务动作</th><th>证据</th></tr>%s</table>" % \
            "".join("<tr><td>T%s</td><td>%s</td><td>%s</td><td class='ev'>%s</td></tr>"
                    % (_esc(r.get("tid", "?")), _esc(r.get("role", "")),
                       _inline(_esc(r.get("action", ""))), _esc(r.get("evidence", "")))
                    for r in roles)
    else:
        roles_html = "<p>（待补）</p>"

    rc = narr.get("root_cause") or {}
    rc_html = md_lite(rc.get("mechanism"))
    if rc.get("culprit"):
        rc_html += "<h3>肇事代码</h3>" + md_lite(rc["culprit"])

    fixes = narr.get("fixes") or []
    fixes_html = "\n".join(
        "<div class='fix'><h3>%s</h3>%s</div>" % (_esc(fx.get("title", "")),
                                                  md_lite(fx.get("body")))
        for fx in fixes) or "<p>（待补）</p>"

    conf = narr.get("confidence") or []
    if conf:
        conf_html = "<table><tr><th>可信度</th><th>结论</th><th>依据</th></tr>%s</table>" % \
            "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                    % (_esc(c.get("level", "")), _inline(_esc(c.get("claim", ""))),
                       _esc(c.get("evidence", ""))) for c in conf)
    else:
        conf_html = "<p>（待补）</p>"

    gaps_html = ("<ul class='gaps'>%s</ul>" % "".join(
        "<li>%s</li>" % _inline(_esc(g)) for g in narr.get("gaps") or [])) \
        or "<p>无已知缺口</p>"

    ev_html = ["<p class='ev'>以下为引擎原始取证（未经 AI 润色），供核对叙事证据：</p>"]
    if engine:
        for sec in engine.get("sections", []):
            title = sec.get("title", "")
            for kw, label in _EVIDENCE_KEYWORDS:
                if kw in title:
                    body = md_lite("\n".join(sec.get("lines") or []))
                    ev_html.append(
                        "<details class='ev-panel'><summary>%s</summary>"
                        "<div>%s</div></details>" % (_esc(title), body))
                    break
    else:
        ev_html.append("<p>（未提供 --engine *_report.json，可附加引擎原始取证）</p>")

    with open(_TMPL, encoding="utf-8") as f:
        html = f.read()
    anim = narr.get("animation")
    anim_json = json.dumps(anim if isinstance(anim, dict) else {"absent": True},
                           ensure_ascii=False)
    anim_json = anim_json.replace("</", "<\\/")     # 防 </script> 提前终止
    subs = {
        "__CASE__": _esc(case),
        "__DATE__": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "__META__": meta_html,
        "__TLDR__": _inline(_esc(s.get("tldr", "（待补一句话根因）"))),
        "__TLDR_LEVEL__": _esc(s.get("tldr_level", "疑似")),
        "__SCENE__": scene_html,
        "__THREAD_ROLES__": roles_html,
        "__ROOT_CAUSE__": rc_html,
        "__FIXES__": fixes_html,
        "__CONFIDENCE__": conf_html,
        "__GAPS__": gaps_html,
        "__EVIDENCE__": "\n".join(ev_html),
        "__ANIM_JSON__": anim_json,
    }
    for k, v in subs.items():
        html = html.replace(k, v)
    return html


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    narr_path = sys.argv[1]
    engine = None
    out = None
    case = None
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--engine" and i + 1 < len(args):
            engine = _load(args[i + 1]); i += 2
        elif args[i] == "--out" and i + 1 < len(args):
            out = args[i + 1]; i += 2
        elif args[i] == "--case" and i + 1 < len(args):
            case = args[i + 1]; i += 2
        else:
            i += 1
    narr = _load(narr_path)
    if "--check" in args:
        errors, warns = check(narr)
        for w in warns:
            print("WARN: %s" % w)
        if errors:
            for e in errors:
                print("ERROR: %s" % e)
            print("校验未通过：narrative.json 缺必填字段，先补全再渲染")
            return 1
        print("校验通过：必填字段齐全%s" %
              ("（含 %d 条提醒）" % len(warns) if warns else ""))
        return 0
    html = render(narr, engine, case)
    if not out:
        out = os.path.splitext(os.path.abspath(narr_path))[0] + "_analysis.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print("HTML 报告已生成: %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

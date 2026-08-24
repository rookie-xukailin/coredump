#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""coredump-analyze skill 的辅助脚本：解析 bmccore JSON 报告，提取结构化数据。

bmccore 的 JSON 报告是"sections[].lines[]"格式（markdown 行的堆砌），
本脚本将其转为结构化 dict 供 AI agent 直接使用。
"""
import json
import sys


def parse_report(json_path):
    """解析 bmccore JSON 报告，返回结构化 dict。"""
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    result = {"meta": data.get("meta", {}), "sections": {}}
    for sec in data.get("sections", []):
        title = sec["title"]
        lines = sec["lines"]
        result["sections"][title] = _parse_section(title, lines)
    return result


def _parse_section(title, lines):
    """按节的类型解析行列表为结构化数据。"""
    text = "\n".join(lines)

    # 定位结论表
    if title == "定位结论":
        conclusions = []
        for l in lines:
            if l.startswith("| ") and not l.startswith("| --") and not l.startswith("| 可信度"):
                parts = [p.strip() for p in l.split("|")[1:-1]]
                if len(parts) >= 3:
                    conclusions.append({
                        "confidence": parts[0],
                        "text": parts[1],
                        "evidence": parts[2],
                    })
        return {"conclusions": conclusions}

    # 回溯帧
    if "回溯" in title:
        frames = []
        for l in lines:
            l = l.strip()
            if l.startswith("#"):
                parts = l.split(None, 3)
                if len(parts) >= 3:
                    frames.append({
                        "level": int(parts[0].lstrip("#")),
                        "addr": parts[1],
                        "func_loc": parts[2] if len(parts) > 2 else "",
                    })
        return {"frames": frames, "is_crash_thread": "崩溃线程" in title}

    # 栈扫描
    if "栈扫描" in title:
        frames = []
        overflow = None
        for l in lines:
            if l.startswith("**") and ("栈溢出" in l or "SP" in l):
                overflow = l.strip("*")
            if l.startswith("| ") and "SP+" in l:
                parts = [p.strip() for p in l.split("|")[1:-1]]
                if len(parts) >= 5:
                    frames.append({
                        "stack_off": parts[0],
                        "value": parts[1],
                        "confidence": parts[2],
                        "func_loc": parts[3],
                        "why": parts[4],
                    })
        return {"scan_frames": frames, "overflow": overflow}

    # 堆取证
    if "堆取证" in title:
        notes = [l.lstrip("- ") for l in lines if l.startswith("- ")]
        return {"notes": notes, "raw": text}

    # 源码片段
    if "源码片段" in title:
        return {"location": title, "code": text}

    # 符号配对
    if "符号配对" in title:
        modules = []
        for l in lines:
            if l.startswith("| ") and not l.startswith("| --") and not l.startswith("| 模块"):
                parts = [p.strip() for p in l.split("|")[1:-1]]
                if len(parts) >= 4:
                    modules.append({
                        "module": parts[0],
                        "device_path": parts[1],
                        "status": parts[2],
                        "symbol_file": parts[3],
                    })
        return {"modules": modules}

    # 概览 / 技能状态 / 寄存器
    kv = {}
    for l in lines:
        if l.startswith("| ") and not l.startswith("| --") and not l.startswith("| 项"):
            parts = [p.strip() for p in l.split("|")[1:-1]]
            if len(parts) >= 2:
                kv[parts[0]] = parts[1]
    return kv


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: coredump_analyze.py <report.json>")
        sys.exit(1)
    result = parse_report(sys.argv[1])
    print(json.dumps(result, ensure_ascii=False, indent=2))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导出可分发的精简技能包：python3 tools/export_skill.py

技能包源目录为仓库内的 swrd-skill-coredump-analyze/（自包含：SKILL.md 入口 +
引擎 bmccore.py/bmccore//open/ + scripts/）。本脚本将其整体复制到
dist/ 并附加安装说明与用户手册，打成 zip 供内网摆渡：

    dist/swrd-skill-coredump-analyze/                       ← 文件夹版
    dist/swrd-skill-coredump-analyze-skill-<version>.zip    ← 压缩版

仓库的开发资产（tests/tools/docs/README 等）不随技能分发。
"""
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DIST = os.path.join(ROOT, "dist")
PKG_NAME = "swrd-skill-coredump-analyze"
SRC = os.path.join(ROOT, PKG_NAME)
DOC_FILE = os.path.join(ROOT, "docs", "使用说明.md")
AGENT_FILE = os.path.join(ROOT, "agents", "swrd-agent-coredump-analyze.md")

INSTALL_MD = """# swrd-skill-coredump-analyze 技能安装说明

本目录是自包含技能包：分析引擎（bmccore）已随包内置，无需 pip 安装，
仅需目标机器有 Python 3.8+。把**整个 `swrd-skill-coredump-analyze/` 目录**拷到
对应 Agent 的技能目录即可（目录名保持 `swrd-skill-coredump-analyze`）：

| Agent | 项目级（随仓库共享） | 用户级（个人全局） |
|---|---|---|
| CodeBuddy | `<项目>/.codebuddy/skills/swrd-skill-coredump-analyze/` | `~/.codebuddy/skills/swrd-skill-coredump-analyze/` |
| Claude Code | `<项目>/.claude/skills/swrd-skill-coredump-analyze/` | `~/.claude/skills/swrd-skill-coredump-analyze/` |
| ZCode | `<项目>/.zcode/skills/swrd-skill-coredump-analyze/` | `~/.zcode/skills/swrd-skill-coredump-analyze/` |
| Codex/Cursor 等通用位 | `<项目>/.agents/skills/swrd-skill-coredump-analyze/` | `~/.agents/skills/swrd-skill-coredump-analyze/` |

安装后验证（在技能目录内执行，应正常打印用法/版本信息）：

    python3 bmccore.py --help

## 配套子代理 swrd-agent-coredump-analyze（可选，推荐）

`agents/swrd-agent-coredump-analyze.md` 是配套子代理定义（独立上下文执行
完整分析任务）。拷到对应平台的子代理目录：

| 平台 | 项目级 | 用户级 |
|---|---|---|
| CodeBuddy | `<项目>/.codebuddy/agents/` | `~/.codebuddy/agents/` |
| Claude Code | `<项目>/.claude/agents/` | `~/.claude/agents/` |
| ZCode | 设置 → 子代理 中创建同名子代理，粘贴该文件内容 | 同左 |

技能与子代理可只装其一，也可同时安装：技能让主对话按需加载方法论；
子代理以独立上下文承接委派的完整分析任务（两者共用同一引擎）。

触发方式：在 Agent 对话中提到 core 文件 / tar.gz 崩溃包 /
"进程崩了/段错误/abort/内存被踩" 等关键词，技能自动加载、子代理被委派。

内网提示：
- 分析默认走 `--offline`（纯 Python，零外部程序调用、零网络请求）；
- 请勿设置 `DEBUGINFOD_URLS` 环境变量或 bmccore.toml 的 `debuginfod_url`
  （默认关闭；配置后才会按 build-id 发起 HTTP 拉取符号）；
- 根因分析需要内网可达的符号表目录与源码树，仅有 core 文件时
  技能会退化为"崩在哪"的定位。
"""


def read_version():
    """从技能包 SKILL.md frontmatter 读 version 字段。"""
    path = os.path.join(SRC, "SKILL.md")
    with open(path, encoding="utf-8") as f:
        m = re.search(r"^version:\s*(\S+)", f.read(), re.M)
    if not m:
        raise SystemExit("SKILL.md 缺少 version 字段")
    return m.group(1)


def main():
    if not os.path.isfile(os.path.join(SRC, "SKILL.md")):
        raise SystemExit("缺少技能包源目录: %s" % SRC)
    version = read_version()
    pkg_dir = os.path.join(DIST, PKG_NAME)
    if os.path.isdir(pkg_dir):
        shutil.rmtree(pkg_dir)
    os.makedirs(DIST, exist_ok=True)

    # 技能包整体复制（剔除 __pycache__ / 字节码）
    shutil.copytree(SRC, pkg_dir,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    # 附加：用户手册 + 配套子代理 + 安装说明
    doc_dst = os.path.join(pkg_dir, "docs")
    os.makedirs(doc_dst, exist_ok=True)
    shutil.copy2(DOC_FILE, os.path.join(doc_dst, os.path.basename(DOC_FILE)))
    if os.path.isfile(AGENT_FILE):
        agent_dst = os.path.join(pkg_dir, "agents")
        os.makedirs(agent_dst, exist_ok=True)
        shutil.copy2(AGENT_FILE, os.path.join(agent_dst, os.path.basename(AGENT_FILE)))
    with open(os.path.join(pkg_dir, "INSTALL.md"), "w", encoding="utf-8") as f:
        f.write(INSTALL_MD)

    # 压缩包（放 dist/ 下，与文件夹版并列）
    zip_base = os.path.join(DIST, PKG_NAME)
    zip_path = shutil.make_archive(zip_base, "zip", root_dir=DIST, base_dir=PKG_NAME)
    os.replace(zip_path, "%s-v%s.zip" % (zip_base, version))   # 覆盖旧版，支持重跑

    n_files = sum(len(fs) for _, _, fs in os.walk(pkg_dir))
    print("技能包已导出: %s（%d 个文件）" % (pkg_dir, n_files))
    print("压缩包     : %s-v%s.zip" % (zip_base, version))
    return 0


if __name__ == "__main__":
    sys.exit(main())

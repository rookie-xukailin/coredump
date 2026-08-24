#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导出可分发的精简技能包：python3 tools/export_skill.py

整个仓库即技能包（SKILL.md 在根目录，引擎 bmccore.py/bmccore//open/
随技能自带）。本脚本从仓库组装出**只含运行时文件**的精简包，用于拷入
各 Agent 的技能目录或经内网分发：

    dist/coredump-analyze/                       ← 文件夹版
    dist/coredump-analyze-skill-<version>.zip    ← 压缩版（内网摆渡）

剔除开发资产（.git/tests/tools/docs 其余部分/README），技能加载只认
SKILL.md，额外文件不影响 Agent，但精简包可避免误改与体积膨胀。
"""
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DIST = os.path.join(ROOT, "dist")
PKG_NAME = "coredump-analyze"

# 精简包内容清单：文件 / 目录（目录递归拷贝，自动剔除 __pycache__）
FILES = ["SKILL.md", "bmccore.py", "bmccore.toml.example"]
DIRS = ["bmccore", os.path.join("open", "pyelftools"), "scripts"]
DOC_FILE = os.path.join("docs", "使用说明.md")

INSTALL_MD = """# coredump-analyze 技能安装说明

本目录是自包含技能包：分析引擎（bmccore）已随包内置，无需 pip 安装，
仅需目标机器有 Python 3.8+。把**整个 `coredump-analyze/` 目录**拷到
对应 Agent 的技能目录即可（目录名保持 `coredump-analyze`）：

| Agent | 项目级（随仓库共享） | 用户级（个人全局） |
|---|---|---|
| CodeBuddy | `<项目>/.codebuddy/skills/coredump-analyze/` | `~/.codebuddy/skills/coredump-analyze/` |
| Claude Code | `<项目>/.claude/skills/coredump-analyze/` | `~/.claude/skills/coredump-analyze/` |
| ZCode | `<项目>/.zcode/skills/coredump-analyze/` | `~/.zcode/skills/coredump-analyze/` |
| Codex/Cursor 等通用位 | `<项目>/.agents/skills/coredump-analyze/` | `~/.agents/skills/coredump-analyze/` |

安装后验证（在技能目录内执行，应正常打印用法/版本信息）：

    python3 bmccore.py --help

触发方式：在 Agent 对话中提到 core 文件 / tar.gz 崩溃包 /
"进程崩了/段错误/abort/内存被踩" 等关键词，技能自动加载。

内网提示：
- 分析默认走 `--offline`（纯 Python，零外部程序调用、零网络请求）；
- 请勿设置 `DEBUGINFOD_URLS` 环境变量或 bmccore.toml 的 `debuginfod_url`
  （默认关闭；配置后才会按 build-id 发起 HTTP 拉取符号）；
- 根因分析需要内网可达的符号表目录与源码树，仅有 core 文件时
  技能会退化为"崩在哪"的定位。
"""


def read_version():
    """从 SKILL.md frontmatter 读 version 字段。"""
    path = os.path.join(ROOT, "SKILL.md")
    with open(path, encoding="utf-8") as f:
        m = re.search(r"^version:\s*(\S+)", f.read(), re.M)
    if not m:
        raise SystemExit("SKILL.md 缺少 version 字段")
    return m.group(1)


def main():
    version = read_version()
    pkg_dir = os.path.join(DIST, PKG_NAME)
    if os.path.isdir(pkg_dir):
        shutil.rmtree(pkg_dir)
    os.makedirs(pkg_dir)

    # 拷贝文件
    for rel in FILES:
        src = os.path.join(ROOT, rel)
        if not os.path.isfile(src):
            raise SystemExit("缺少文件: %s" % rel)
        shutil.copy2(src, os.path.join(pkg_dir, rel))

    # 拷贝目录（剔除 __pycache__ / 非 .py 资产按需保留）
    for rel in DIRS:
        src = os.path.join(ROOT, rel)
        if not os.path.isdir(src):
            raise SystemExit("缺少目录: %s" % rel)
        shutil.copytree(src, os.path.join(pkg_dir, rel),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    # 使用说明 + 安装说明
    doc_dst = os.path.join(pkg_dir, "docs")
    os.makedirs(doc_dst)
    shutil.copy2(os.path.join(ROOT, DOC_FILE), os.path.join(doc_dst, os.path.basename(DOC_FILE)))
    with open(os.path.join(pkg_dir, "INSTALL.md"), "w", encoding="utf-8") as f:
        f.write(INSTALL_MD)

    # 压缩包（放 dist/ 下，与文件夹版并列）
    zip_base = os.path.join(DIST, "%s-skill" % PKG_NAME)
    zip_path = shutil.make_archive(zip_base, "zip", root_dir=DIST, base_dir=PKG_NAME)
    os.rename(zip_path, "%s-v%s.zip" % (zip_base, version))

    # 汇总
    n_files = sum(len(fs) for _, _, fs in os.walk(pkg_dir))
    print("技能包已导出: %s（%d 个文件）" % (pkg_dir, n_files))
    print("压缩包     : %s-v%s.zip" % (zip_base, version))
    return 0


if __name__ == "__main__":
    sys.exit(main())

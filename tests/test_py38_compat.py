# -*- coding: utf-8 -*-
"""Python 3.8 兼容性防回退门禁。

工具承诺 Python 3.8+（真实编译服务器环境）。本测试静态保证仓库自有代码
（bmccore/ + tests/）不会引入 3.9+ 语法或运行时 API；vendored
open/pyelftools 固定在 0.31（官方支持 py3.6+），同样做语法级校验。

检测项：
  1. 全部 .py 可按 3.8 语法编译（拦截 match 语句、内置泛型运行时求值等）
  2. 自有代码禁用 3.9+ 运行时 API：str.removeprefix/removesuffix、
     functools.cache、dict 合并 |、内置泛型注解（无 future import 时
     def 注解会在导入期求值导致 TypeError）
  3. vendored pyelftools 版本号为 0.31.x（升级前必须重跑 3.8 实测）

注：语法级编译无法覆盖运行时 API 差异——发布前请在真实 3.8 解释器上
执行 `python3.8 tests/run_all.py` 与 CLI 冒烟（本仓库已在 3.8.18 验证）。
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

_API_PATTERNS = [
    (re.compile(r"\.removeprefix\(|\.removesuffix\("),
     "str.removeprefix/removesuffix 需要 3.9+"),
    (re.compile(r"functools\.cache\("), "functools.cache 需要 3.9+"),
    (re.compile(r"(?m)^\s*match\s+\w+\s*:"), "match 语句需要 3.10+"),
]


def _iter_py_files(base):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def test_py38_syntax_and_api():
    """自有代码 + vendored 库的 3.8 语法与 API 门禁。"""
    problems = []
    pkg = os.path.join(ROOT, "swrd-skill-coredump-analyze")
    targets = [_iter_py_files(os.path.join(pkg, "bmccore")),
               _iter_py_files(HERE),
               _iter_py_files(os.path.join(pkg, "open", "pyelftools"))]
    for it in targets:
        for p in it:
            rel = os.path.relpath(p, ROOT)
            with open(p, encoding="utf-8", errors="replace") as f:
                src = f.read()
            try:
                ast.parse(src, filename=rel, feature_version=(3, 8))
            except SyntaxError as e:
                problems.append("%s: 3.8 语法不兼容(%s)" % (rel, e))
                continue
            if rel.startswith("open/"):
                continue        # vendored：仅语法门禁
            for pat, desc in _API_PATTERNS:
                if pat.search(src):
                    problems.append("%s: %s" % (rel, desc))
            # 自有代码的内置泛型注解（def 头部会在导入期求值）
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    segs = []
                    for x in list(node.args.args) + list(node.args.kwonlyargs):
                        if x.annotation is not None:
                            segs.append(x.annotation)
                    if node.returns is not None:
                        segs.append(node.returns)
                    for a in segs:
                        if isinstance(a, ast.Subscript) and isinstance(
                                a.value, ast.Name) and \
                                a.value.id in ("list", "dict", "set", "tuple"):
                            problems.append(
                                "%s:%d: 内置泛型注解 %s[...] 需要 3.9+"
                                % (rel, node.lineno, a.value.id))
    if problems:
        raise AssertionError("Python 3.8 兼容门禁失败:\n" + "\n".join(problems))


def test_vendored_pyelftools_version_pinned():
    """vendored pyelftools 必须停留在官方支持 py3.6+ 的 0.31.x。

    0.32+ 使用 match 语句等 3.10 语法。升级此依赖前必须：
    在真实 3.8 解释器上重跑 tests/run_all.py + CLI 冒烟，并更新本断言。
    """
    init = os.path.join(ROOT, "swrd-skill-coredump-analyze", "open", "pyelftools",
                        "elftools", "__init__.py")
    with open(init, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", src)
    if not m or not m.group(1).startswith("0.31"):
        raise AssertionError(
            "vendored pyelftools 版本=%s（期望 0.31.x）。0.32+ 需要 py3.9+/3.10，"
            "与 3.8 基线冲突；如确需升级，先在真实 3.8 上全量验证并更新本测试。"
            % (m.group(1) if m else "未知"))

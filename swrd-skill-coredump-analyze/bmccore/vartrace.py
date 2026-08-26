# -*- coding: utf-8 -*-
"""变量生命周期追踪：从崩溃点反推指针从声明→赋值→清零/释放→崩溃的完整轨迹。

针对空指针/UAF/野指针三类崩溃，回答"这个指针到底经历了什么"：
  - 它在哪声明的？
  - 它应该在哪被初始化？
  - 初始化函数被调用了吗？
  - 有谁把它置空了？
  - 崩溃时它是怎么传到这一行的？

纯启发式源码分析（grep + 上下文推断），不要求完美——但给出的每条
线索都有 file:line 依据，工程师可以直接跳转验证。
"""
import os
import re


def _walk_sources(source_root, suffixes=(".c", ".h")):
    """遍历源码树，返回 [(path, content)]。"""
    files = []
    if not source_root or not os.path.isdir(source_root):
        return files
    for dirpath, _dirs, names in os.walk(source_root):
        _dirs[:] = [d for d in _dirs if d not in (".git", "out", "build", "__pycache__")]
        for fn in sorted(names):
            if fn.endswith(suffixes):
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        files.append((p, f.read()))
                except OSError:
                    pass
    return files


def _extract_pointer_from_crash_line(line_text):
    """从崩溃行源码中提取被解引用的指针变量名。

    例：dev->ctrl_reg = 42  →  dev
         f->set_pwm(f, duty)  →  f
         *p = 0x5a             →  p
         n->read_raw = fn      →  n
    """
    # 模式 1: xxx->yyy
    m = re.findall(r"(\w+)->\w+", line_text)
    if m:
        return list(set(m))
    # 模式 2: (*xxx)
    m = re.findall(r"\(\*(\w+)\)", line_text)
    if m:
        return list(set(m))
    # 模式 3: *xxx = ...
    m = re.findall(r"^\s*\*(\w+)\s*=", line_text)
    if m:
        return list(set(m))
    return []


def _find_declarations(sources, var_names):
    """找变量的声明位置。"""
    decls = []
    for var in var_names:
        for path, content in sources:
            for i, line in enumerate(content.splitlines(), 1):
                # 匹配: struct xxx *var / type *var / static type *var
                if re.search(r"\*\s*%s\b" % re.escape(var), line) and \
                   not re.search(r"%s\s*=" % re.escape(var), line) and \
                   not re.search(r"%s->" % re.escape(var), line) and \
                   not re.search(r"%s\." % re.escape(var), line):
                    decls.append({
                        "var": var, "file": os.path.basename(path),
                        "path": path, "line": i, "text": line.strip(),
                        "type": "declaration",
                    })
                    break    # 每个文件只取第一个
    return decls


def _find_assignments(sources, var_names):
    """找变量的所有赋值点。"""
    assigns = []
    for var in var_names:
        for path, content in sources:
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                # 跳过注释和声明
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                    continue
                # 匹配: var = xxx（不匹配 == 、 += 等）
                if re.search(r"\b%s\s*=[^=]" % re.escape(var), stripped):
                    is_null = bool(re.search(r"\b%s\s*=\s*NULL" % re.escape(var), stripped))
                    is_alloc = bool(re.search(
                        r"\b%s\s*=\s*(malloc|calloc|realloc|new)" % re.escape(var), stripped))
                    assigns.append({
                        "var": var, "file": os.path.basename(path),
                        "path": path, "line": i, "text": stripped[:100],
                        "type": "assign_null" if is_null else
                                "assign_alloc" if is_alloc else "assign",
                    })
    return assigns


def _find_free_calls(sources, var_names):
    """找对变量的 free/release 调用。"""
    frees = []
    for var in var_names:
        for path, content in sources:
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if re.search(r"\b(free|kfree|release|cleanup|close|destroy)\s*\(\s*%s\b" %
                             re.escape(var), stripped):
                    frees.append({
                        "var": var, "file": os.path.basename(path),
                        "path": path, "line": i, "text": stripped[:100],
                        "type": "free",
                    })
    return frees


def _find_init_function(sources, var_names):
    """找应该初始化该变量的函数。"""
    inits = []
    for var in var_names:
        # 从赋值中找 malloc 类的赋值所在的函数
        for path, content in sources:
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if re.search(r"\b%s\s*=\s*(malloc|calloc|&|\()" % re.escape(var), line):
                    # 向上找函数签名
                    for j in range(i, max(i - 30, 0), -1):
                        l = lines[j]
                        if re.match(r"^(static\s+)?\w+[\s\*]+\w+\s*\(", l):
                            func_name = re.search(r"(\w+)\s*\(", l)
                            if func_name:
                                inits.append({
                                    "var": var,
                                    "func": func_name.group(1),
                                    "file": os.path.basename(path),
                                    "line": j + 1,
                                    "type": "init_function",
                                })
                            break
                    break    # 每个文件只找第一个
    return inits


def _check_if_called(sources, func_name):
    """检查某函数是否被调用（排除其定义本身）。"""
    call_sites = []
    for path, content in sources:
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            # 跳过定义行
            if re.search(r"^\w+[\s\*]+" + re.escape(func_name) + r"\s*\(", stripped):
                continue
            # 跳过声明行
            if stripped.endswith(";") and re.search(re.escape(func_name) + r"\s*\(", stripped):
                # 可能是函数指针赋值或前向声明，检查上下文
                pass
            # 匹配调用
            if re.search(r"\b" + re.escape(func_name) + r"\s*\(", stripped):
                call_sites.append({
                    "file": os.path.basename(path), "line": i,
                    "text": stripped[:100],
                })
    return call_sites


def trace_variable(source_root, crash_file, crash_line, crash_text,
                   fault_addr=None, runtime_value=None, runtime_sem=None):
    """变量生命周期追踪主入口。

    runtime_value/runtime_sem（可选）：崩溃行指针的运行时取值（来自
    framevars 的 gdb bt full / DIE 参数表恢复）——把静态轨迹与运行时
    现场接通，崩溃时刻事件据此生成。

    返回 list[dict]——每步是一个事件，按时间序排列。
    """
    # 第 1 步：从崩溃行提取被解引用的指针
    pointers = _extract_pointer_from_crash_line(crash_text)
    if not pointers:
        return None, "崩溃行中未找到被解引用的指针变量"

    # 只追踪第一个（最相关的）
    var = pointers[0]
    events = []

    # 第 2 步：加载源码
    sources = _walk_sources(source_root)
    if not sources:
        return None, "源码树不可达"

    # 第 3 步：找声明
    decls = _find_declarations(sources, [var])
    for d in decls[:1]:
        events.append({
            "step": "declaration",
            "icon": "📌",
            "title": "变量声明",
            "detail": "<code>%s</code> 在 <code>%s:%d</code> 声明" % (var, d["file"], d["line"]),
            "code": d["text"],
            "file": d["file"], "line": d["line"],
        })

    # 第 4 步：找所有赋值
    assigns = _find_assignments(sources, [var])
    null_assigns = [a for a in assigns if a["type"] == "assign_null"]
    alloc_assigns = [a for a in assigns if a["type"] == "assign_alloc"]

    # 第 5 步：找初始化函数
    inits = _find_init_function(sources, [var])
    for init in inits[:1]:
        # 检查该函数是否被调用
        call_sites = _check_if_called(sources, init["func"])
        if call_sites:
            events.append({
                "step": "initialization",
                "icon": "✅",
                "title": "初始化函数存在且被调用",
                "detail": "<code>%s()</code> 在 <code>%s:%d</code> 定义，"
                          "在 %d 处被调用" % (init["func"], init["file"],
                                              init["line"], len(call_sites)),
                "code": init.get("code", ""),
                "file": init["file"], "line": init["line"],
            })
        else:
            events.append({
                "step": "initialization_missing",
                "icon": "❌",
                "title": "初始化函数从未被调用！",
                "detail": "<code>%s()</code> 在 <code>%s:%d</code> 定义了"
                          " <code>%s</code> 的初始化，但整个代码中没有任何地方调用它。" %
                          (init["func"], init["file"], init["line"], var),
                "code": "这就是根因：%s 从未被赋值，一直是 NULL" % var,
                "file": init["file"], "line": init["line"],
                "is_root_cause": True,
            })

    # 第 6 步：找置空/释放
    for a in null_assigns[:3]:
        events.append({
            "step": "set_null",
            "icon": "⚠️",
            "title": "被置为 NULL",
            "detail": "在 <code>%s:%d</code> 执行了 <code>%s = NULL</code>" %
                      (a["file"], a["line"], var),
            "code": a["text"],
            "file": a["file"], "line": a["line"],
        })

    frees = _find_free_calls(sources, [var])
    for fr in frees[:3]:
        events.append({
            "step": "free",
            "icon": "🗑️",
            "title": "被释放",
            "detail": "在 <code>%s:%d</code> 调用了 free/cleanup" %
                      (fr["file"], fr["line"]),
            "code": fr["text"],
            "file": fr["file"], "line": fr["line"],
        })

    # 第 7 步：崩溃时刻
    crash_evt = None
    if runtime_value is not None:
        vt = "0x%x" % runtime_value if isinstance(runtime_value, int) else str(runtime_value)
        crash_evt = {
            "step": "crash",
            "icon": "💥",
            "title": "崩溃时刻（运行时值已恢复）",
            "detail": "在 <code>%s:%d</code> 解引用了 <code>%s</code>，"
                      "此时它的值是 <code>%s</code>%s（出错地址 0x%x）" % (
                          os.path.basename(crash_file or "?"), crash_line, var,
                          vt, "（%s）" % runtime_sem if runtime_sem else "",
                          fault_addr if fault_addr is not None else 0),
            "code": crash_text,
            "file": os.path.basename(crash_file or ""), "line": crash_line,
            "is_crash": True,
        }
    elif fault_addr is not None and fault_addr < 0x1000:
        crash_evt = {
            "step": "crash",
            "icon": "💥",
            "title": "崩溃时刻",
            "detail": "在 <code>%s:%d</code> 解引用了 <code>%s</code>，"
                      "此时它的值是 NULL（出错地址 0x%x = NULL + 偏移量）" %
                      (os.path.basename(crash_file or "?"), crash_line, var, fault_addr),
            "code": crash_text,
            "file": os.path.basename(crash_file or ""), "line": crash_line,
            "is_crash": True,
        }
    if crash_evt:
        events.append(crash_evt)

    # 排序：声明 → 初始化 → 赋值 → 释放/置空 → 崩溃
    order = {"declaration": 0, "initialization": 1, "initialization_missing": 1,
             "assign": 2, "assign_alloc": 2, "set_null": 3, "free": 4, "crash": 5}
    events.sort(key=lambda e: order.get(e["step"], 99))

    # 构建结论
    root_cause = None
    for e in events:
        if e.get("is_root_cause"):
            root_cause = e["detail"]
            break
    if not root_cause and null_assigns:
        root_cause = "%s 在 %s:%d 被置为 NULL 后仍然被使用" % (
            var, null_assigns[0]["file"], null_assigns[0]["line"])
    if not root_cause and frees:
        root_cause = "%s 在 %s:%d 被释放后仍然被使用（Use-After-Free）" % (
            var, frees[0]["file"], frees[0]["line"])
    # 运行时值与静态轨迹交叉：值非空但内存不可达 → 悬垂指针（UAF/已解映射）
    if (not root_cause and isinstance(runtime_value, int) and runtime_value
            and runtime_sem and ("未映射" in runtime_sem
                                 or "已释放" in runtime_sem)):
        root_cause = ("%s 崩溃时值为 0x%x（%s）——静态轨迹显示它曾有效，"
                      "崩溃时指向的内存已不可达：悬垂指针（UAF/已解映射）"
                      % (var, runtime_value, runtime_sem))

    return events, root_cause

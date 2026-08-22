# -*- coding: utf-8 -*-
"""交叉工具链发现与封装（gdb / addr2line / objdump）。

按 core 的架构自动找对应的交叉工具链；找不到时优雅降级：
- 没有 gdb  -> 精确回溯技能跳过，栈扫描兜底仍然可用（纯 Python）
- 没有 addr2line -> 行号信息缺失，函数级定位仍可用（symtab）
"""
import os
import shutil
import subprocess

# 各架构常见 triple 前缀（按优先级）
_ARCH_PREFIXES = {
    "arm32": ["arm-linux-gnueabihf", "arm-linux-gnueabi", "arm-none-linux-gnueabihf",
              "armv7-linux-gnueabihf"],
    "arm64": ["aarch64-linux-gnu", "aarch64-none-linux-gnu", "aarch64-buildroot-linux-gnu"],
    "riscv64": ["riscv64-linux-gnu", "riscv64-unknown-linux-gnu", "riscv64-buildroot-linux-gnu"],
    "riscv32": ["riscv32-linux-gnu", "riscv64-linux-gnu", "riscv32-unknown-elf"],
}

_TOOLS = ("gdb", "addr2line", "objdump")


class Toolchain(object):
    def __init__(self, arch_name, tools, source):
        self.arch_name = arch_name
        self.tools = tools              # {"gdb": path or None, ...}
        self.source = source            # 探测来源说明

    def has(self, name):
        return bool(self.tools.get(name))

    def __repr__(self):
        return "<Toolchain %s %s>" % (self.arch_name, self.tools)


def _which(name):
    return shutil.which(name)


def discover(arch_name, config=None):
    """发现指定架构的工具链。返回 Toolchain；一个都没有时 tools 全为 None。"""
    tools = {t: None for t in _TOOLS}
    notes = []

    tc_cfg = {}
    if config and config.toolchain:
        tc_cfg = config.toolchain.get(arch_name) or {}
    explicit = {t: tc_cfg.get(t) for t in _TOOLS if tc_cfg.get(t)}
    for t, p in explicit.items():
        p = os.path.expanduser(str(p))
        if os.path.isfile(p):
            tools[t] = p
        else:
            w = _which(p)          # 允许直接写命令名（如 gdb = "gdb-multiarch"）
            if w:
                tools[t] = w
    if tc_cfg.get("prefix"):
        pfx = tc_cfg["prefix"]
        if pfx.endswith("-"):        # 配置里常见带尾横线的 triple 前缀
            pfx = pfx[:-1]
        for t in _TOOLS:
            if not tools[t]:
                cand = "%s-%s" % (pfx, t)
                w = _which(cand)
                if w:
                    tools[t] = w

    # 通用 gdb-multiarch / gdb 兜底（可打开任意架构 core）
    if not any(tools.values()):
        for t in _TOOLS:
            if t == "gdb":
                for cand in ("gdb-multiarch", "gdb"):
                    w = _which(cand)
                    if w:
                        tools[t] = w
                        notes.append("使用通用 %s" % cand)
                        break

    if not any(tools.values()):
        for prefix in _ARCH_PREFIXES.get(arch_name, []):
            found_any = False
            for t in _TOOLS:
                cand = "%s-%s" % (prefix, t)
                w = _which(cand)
                if w:
                    tools[t] = tools[t] or w
                    found_any = True
            if found_any:
                notes.append("前缀 %s" % prefix)
                break

    src = "; ".join(notes) or ("显式配置" if any(tools.values()) else "未找到任何工具")
    return Toolchain(arch_name, tools, src)


def run(tool, args, timeout=120):
    """执行外部工具，返回 (rc, stdout+stderr)。"""
    cmd = [tool] + list(args)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "执行超时: %s" % " ".join(cmd)
    except OSError as e:
        return 127, str(e)


def gdb_batch(gdb_path, script_lines, timeout=180):
    """以 batch 模式跑 gdb 脚本，返回 (ok, output)。"""
    args = ["-batch", "-nx"]
    for line in script_lines:
        args += ["-ex", line]
    rc, out = run(gdb_path, args, timeout=timeout)
    return rc == 0, out


def addr2line_batch(bin_path, addrs, a2l_path):
    """批量地址翻译。返回 {addr_int: "func @ file:line"}。"""
    if not addrs:
        return {}
    args = ["-e", bin_path, "-f", "-C", "-a"]
    args += ["0x%x" % a for a in addrs]
    rc, out = run(a2l_path, args, timeout=60)
    result = {}
    if rc != 0:
        return result
    # -a 模式下每地址输出三行：0xADDR / 函数 / 文件:行号
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    result = {}
    for i in range(0, len(lines) - 2, 3):
        try:
            addr = int(lines[i], 16)
        except ValueError:
            continue
        result[addr] = (lines[i + 1], lines[i + 2])
    return result

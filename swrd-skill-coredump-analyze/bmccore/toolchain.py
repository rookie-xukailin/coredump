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

# 架构 -> 工具文件名关键字的优先级组（外层按序尝试，组内任一命中即可）。
# riscv/arm32 的第二组放宽到家族名，兼容 riscv-none-elf- / riscv-nuclei-elf- /
# riscv-linux-musl- / arm-xxx- 等不带架构号前缀的商用/定制工具链。
_ARCH_KEYS = {
    "arm32": (("arm-linux", "armv7", "arm-none", "armeb"), ("arm",)),
    "arm64": (("aarch64", "arm64"),),
    "riscv64": (("riscv64", "rv64"), ("riscv",)),
    "riscv32": (("riscv32", "rv32"), ("riscv",)),
}


def _probe_tool_dir(d, arch_name):
    """在目录 d 里找架构匹配的交叉工具，返回 {tool: 绝对路径}（只含找到的）。

    匹配规则：按架构关键字优先级组找 triple 前缀名（如
    riscv64-unknown-linux-gnu-gdb）；没有前缀名时接受目录内裸名
    （gdb 优先 multiarch 变体）。
    """
    try:
        names = os.listdir(d)
    except OSError:
        return {}
    groups = _ARCH_KEYS.get(arch_name, ((arch_name,),))
    tools = {}
    for t in _TOOLS:
        cands = []
        for keys in groups:
            cands = sorted(n for n in names
                           if n.endswith("-%s" % t) and any(k in n for k in keys))
            if cands:
                break
        if cands:
            tools[t] = os.path.join(d, cands[0])
            continue
        for bare in (("gdb-multiarch", "gdb") if t == "gdb" else (t,)):
            if bare in names:
                tools[t] = os.path.join(d, bare)
                break
    return tools


class Toolchain(object):
    def __init__(self, arch_name, tools, source):
        self.arch_name = arch_name
        self.tools = tools              # {"gdb": path or None, ...}
        self.source = source            # 探测来源说明

    def has(self, name):
        return bool(self.tools.get(name))

    def __repr__(self):
        return "<Toolchain %s %s 来源: %s>" % (self.arch_name, self.tools,
                                               self.source)


def _which(name):
    return shutil.which(name)


def discover(arch_name, config=None):
    """发现指定架构的工具链。返回 Toolchain；一个都没有时 tools 全为 None。

    config.offline=True 时进入离线模式：无条件不启用任何外部工具
    （含配置里显式给出的路径）——纯 Python 能力（符号配对/栈扫描/
    DWARF 行号/堆取证）不受影响，gdb 精确回溯技能跳过。
    """
    tools = {t: None for t in _TOOLS}
    notes = []
    offline = bool(config and getattr(config, "offline", False))
    if offline:
        return Toolchain(arch_name, tools, "离线模式（纯Python，不调用外部工具）")

    tc_cfg = {}
    if config and config.toolchain:
        tc_cfg = config.toolchain.get(arch_name) or {}
    explicit = {t: tc_cfg.get(t) for t in _TOOLS if tc_cfg.get(t)}
    for t, p in explicit.items():
        p = os.path.expanduser(str(p))
        if os.path.isfile(p):
            tools[t] = p
        elif not offline:
            w = _which(p)          # 允许直接写命令名（如 gdb = "gdb-multiarch"）
            if w:
                tools[t] = w
    # path：只给一个路径（工具链根目录 / bin 目录 / 以 - 结尾的完整前缀），
    # 其下工具自动发现。优先级低于逐工具显式指定。
    p_path = tc_cfg.get("path") if tc_cfg else None
    if p_path and not offline:
        p_path = os.path.expanduser(str(p_path))
        if os.path.isdir(p_path):
            found = _probe_tool_dir(p_path, arch_name)
            if not any(found.values()):
                found = _probe_tool_dir(os.path.join(p_path, "bin"), arch_name)
            for t, p in found.items():
                tools[t] = tools[t] or p
            if any(found.values()):
                notes.append("路径 %s 自动发现" % p_path)
            else:
                notes.append("配置 path=%s 未匹配到任何工具（检查目录内文件命名，"
                             "或改用 gdb/addr2line 逐项显式指定）" % p_path)
        elif p_path.endswith("-"):
            for t in _TOOLS:
                cand = p_path + t
                if not tools[t] and os.path.isfile(cand):
                    tools[t] = cand
                    notes.append("前缀路径 %s 自动发现" % p_path)
    if tc_cfg.get("prefix") and not offline:
        pfx = tc_cfg["prefix"]
        if os.path.isdir(os.path.expanduser(str(pfx))):
            # 常见笔误：把目录路径填进了 prefix（本应填 triple 前缀）——
            # 按目录探测兜底，而不是拼出 "<目录>-gdb" 静默落空
            found = _probe_tool_dir(os.path.expanduser(str(pfx)), arch_name)
            if not any(found.values()):
                found = _probe_tool_dir(os.path.join(
                    os.path.expanduser(str(pfx)), "bin"), arch_name)
            for t, p in found.items():
                tools[t] = tools[t] or p
            if any(found.values()):
                notes.append("prefix=%s 按目录自动发现" % pfx)
        else:
            if pfx.endswith("-"):        # 配置里常见带尾横线的 triple 前缀
                pfx = pfx[:-1]
            for t in _TOOLS:
                if not tools[t]:
                    cand = "%s-%s" % (pfx, t)
                    w = _which(cand)
                    if w:
                        tools[t] = w

    # 通用 gdb-multiarch / gdb 兜底（可打开任意架构 core）
    if not any(tools.values()) and not offline:
        for t in _TOOLS:
            if t == "gdb":
                for cand in ("gdb-multiarch", "gdb"):
                    w = _which(cand)
                    if w:
                        tools[t] = w
                        notes.append("使用通用 %s" % cand)
                        break

    if not any(tools.values()) and not offline:
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

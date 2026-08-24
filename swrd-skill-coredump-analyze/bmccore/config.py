# -*- coding: utf-8 -*-
"""配置加载：CLI 参数 > bmccore.toml > 自动探测。

toml 只实现本工具需要的子集（[节] / key = value / 注释 / 字符串/整数/布尔），
避免在编译服务器上引入额外依赖（Python<3.11 没有 tomllib）。
"""
import io
import os


class ConfigError(Exception):
    pass


def _parse_scalar(s):
    s = s.strip()
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1]
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1]
    if s.lower() in ("true", "yes", "on"):
        return True
    if s.lower() in ("false", "no", "off"):
        return False
    try:
        return int(s, 0)
    except ValueError:
        return s


def _strip_comment(val):
    """去掉行内注释：带引号的值取闭合引号前的部分，裸值取 # 之前。"""
    s = val.lstrip()
    if s[:1] in ('"', "'"):
        end = s.find(s[0], 1)
        if end != -1:
            return s[:end + 1]
        return s
    i = s.find("#")
    return s[:i].rstrip() if i != -1 else s


def load_toml(path):
    """解析 toml 子集，返回 {section: {key: value}}；顶层键放 '' 节。

    支持点分节名（[toolchain.arm64] -> 嵌套 dict），bmccore.toml.example
    用的就是这种写法。
    """
    out = {"": {}}
    cur = out[""]
    with io.open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = out
                for part in line[1:-1].strip().split("."):
                    cur = cur.setdefault(part, {})
                continue
            if "=" not in line:
                raise ConfigError("%s:%d 无法解析: %r" % (path, ln, line))
            key, _, val = line.partition("=")
            cur[key.strip()] = _parse_scalar(_strip_comment(val))
    return out


DEFAULT_CONFIG_NAME = "bmccore.toml"


class Config(object):
    """全量配置（含默认值）。字段与 CLI 一一对应。"""

    def __init__(self):
        self.core = None             # 待分析 core 路径（可由 toml 指定，CLI 位置参数优先）
        self.symbol_table = None     # 符号表文件/目录的绝对路径（编译阶段单独产出）
        self.source_root = None
        self.sysroot = None
        self.toolchain = {}          # {arch_name: {"prefix": ..., "gdb": ..., ...}}
        self.console_log = None
        self.exe = None
        self.modules = {}            # {soname: path} 手动覆盖
        self.glibc_version = None
        self.skills = None           # None=全部
        self.crash_thread_only = False
        self.output = None
        self.workdir = None         # 解包/中间文件目录（tar包符号表也解到这里）
        self.fmt = "both"
        self.keep_temp = False
        self.debug = False
        self.offline = False        # 离线模式：不探测/调用任何外部工具
        self.max_scan_depth = 65536  # 栈扫描最大深度（字节）
        self.max_frames = 50
        self.debuginfod_url = None   # debuginfod 远程符号服务器
        self.viz = False             # 是否启动可视化
        self.viz_port = 8080         # 可视化首选端口
        self.viz_timeout = 0         # 可视化超时（秒）

    # ------------------------------------------------------------------
    def update_from_toml(self, path):
        data = load_toml(path)
        top = data.get("", {})
        # 空字符串视为未配置（自带模板 toml 的留空项），对应能力如实降级
        for k in ("core", "symbol_table", "source_root", "sysroot", "console_log",
                  "exe", "glibc_version", "output", "workdir"):
            if k in top and top[k] and getattr(self, k) is None:
                setattr(self, k, top[k])
        if "format" in top:
            self.fmt = top["format"]
        if "offline" in top:
            self.offline = bool(top["offline"])
        if "crash_thread_only" in top:
            self.crash_thread_only = bool(top["crash_thread_only"])
        if "max_scan_depth" in top:
            self.max_scan_depth = int(top["max_scan_depth"])
        tc = data.get("toolchain", {})
        if isinstance(tc, dict):
            for k, v in tc.items():
                if isinstance(v, dict):
                    self.toolchain.setdefault(k, {}).update(v)
        mods = data.get("module", {})
        if isinstance(mods, dict):
            self.modules.update(mods)

    def update_from_cli(self, args):
        mapping = {
            "symbol_table": "symbol_table", "source_root": "source_root",
            "sysroot": "sysroot", "console_log": "console_log", "exe": "exe",
            "glibc_version": "glibc_version", "output": "output",
            "workdir": "workdir",
            "fmt": "format", "crash_thread_only": "crash_thread_only",
            "keep_temp": "keep_temp", "debug": "debug",
            "max_scan_depth": "max_scan_depth",
        }
        for cli_k, attr in mapping.items():
            v = getattr(args, cli_k, None)
            if v is not None:
                setattr(self, attr, v)
        # --offline 是开关型参数（缺省 False）：只有显式给出才覆盖 toml，
        # 避免"toml 配了 offline=true、命令未带 --offline"被静默翻回 False
        if getattr(args, "offline", False):
            self.offline = True
        # 兼容旧参数 --artifact-dir（符号表重构后被 --symbol-table 取代）
        art = getattr(args, "artifact_dir", None)
        if art is not None and self.symbol_table is None:
            self.symbol_table = art
        if getattr(args, "skills", None):
            self.skills = [s.strip() for s in args.skills.split(",") if s.strip()]
        if getattr(args, "module", None):
            for m in args.module:
                if "=" not in m:
                    raise ConfigError("--module 需要 soname=路径 形式")
                soname, _, p = m.partition("=")
                self.modules[soname.strip()] = p.strip()
        if getattr(args, "toolchain_prefix", None):
            # 显式前缀覆盖全部架构
            for arch in ("arm32", "arm64", "riscv64", "riscv32"):
                self.toolchain[arch] = {"prefix": args.toolchain_prefix}

    def find_config_file(self, start_dir=None):
        """从当前目录向上找 bmccore.toml。"""
        d = os.path.abspath(start_dir or os.getcwd())
        while True:
            cand = os.path.join(d, DEFAULT_CONFIG_NAME)
            if os.path.isfile(cand):
                return cand
            parent = os.path.dirname(d)
            if parent == d:
                return None
            d = parent

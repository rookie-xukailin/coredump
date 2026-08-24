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

# 技能包自带的配置模板（bmccore/config.py 上两级即技能根目录）
_PKG_WORKSPACE_TOML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "workspace", DEFAULT_CONFIG_NAME)


class Config(object):
    """全量配置（含默认值）。字段与 CLI 一一对应。"""

    def __init__(self):
        self.config_path = None     # 实际加载的 bmccore.toml 路径（日志展示用）
        self.config_extra = None    # 低优先级补缺加载的第二个 toml（技能模板）
        self._toml_seen = set()     # 已被 toml 显式设定过的标量键（多文件先见优先）
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
        self.lock_scan_full = False  # 锁扫描：true=附加 owner 未知的全内存盲扫（O(内存)，大 core 极慢）
        self.viz = False             # 是否启动可视化
        self.viz_port = 8080         # 可视化首选端口
        self.viz_timeout = 0         # 可视化超时（秒）

    # ------------------------------------------------------------------
    def update_from_toml(self, path):
        data = load_toml(path)
        top = data.get("", {})
        # 空字符串视为未配置（自带模板 toml 的留空项），对应能力如实降级；
        # 多文件合并时先见者优先（就近 toml > 技能 workspace 模板）
        for k in ("core", "symbol_table", "source_root", "sysroot", "console_log",
                  "exe", "glibc_version", "output", "workdir"):
            if k in top and top[k] and k not in self._toml_seen:
                setattr(self, k, top[k])
                self._toml_seen.add(k)
        for k in ("format", "offline", "crash_thread_only", "lock_scan_full",
                  "max_scan_depth"):
            if k in top and k not in self._toml_seen:
                self._toml_seen.add(k)
                if k == "format":
                    self.fmt = top[k]
                elif k == "max_scan_depth":
                    self.max_scan_depth = int(top[k])
                else:
                    setattr(self, k, bool(top[k]))
        tc = data.get("toolchain", {})
        if isinstance(tc, dict):
            for k, v in tc.items():
                if isinstance(v, dict):
                    dst = self.toolchain.setdefault(k, {})
                    for kk, vv in v.items():
                        if kk not in dst:      # 先加载的文件优先，后加载只补缺
                            dst[kk] = vv
        mods = data.get("module", {})
        if isinstance(mods, dict):
            for k, v in mods.items():
                if k not in self.modules:
                    self.modules[k] = v

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
        """找 bmccore.toml。优先级：--config 显式指定 > 从 start_dir 向上找就近
        toml > 技能包自带 workspace/bmccore.toml 模板（用户填路径的那份）。

        最后一级回落是关键：不带 --config 时，core 所在目录链上通常没有
        toml，而用户填的是技能目录下的 workspace 模板——不回落就等于
        用户配置从未被加载（曾导致工具链 path 配置"明明配了却不生效"）。
        """
        d = os.path.abspath(start_dir or os.getcwd())
        while True:
            cand = os.path.join(d, DEFAULT_CONFIG_NAME)
            if os.path.isfile(cand):
                return cand
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        if os.path.isfile(_PKG_WORKSPACE_TOML):
            return _PKG_WORKSPACE_TOML
        return None

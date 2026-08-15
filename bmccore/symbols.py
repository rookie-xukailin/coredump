# -*- coding: utf-8 -*-
"""符号配对与符号解析。

两条路径：
1. 产物目录扫描：读每个 ELF 产物的 build-id/soname，与 core 中模块配对
   （build-id 精确 > 文件名降级）；
2. SymbolResolver：从产物 .symtab 做函数级地址定位（纯 pyelftools，无工具链依赖），
   行号信息在 addr2line 可用时叠加。
"""
import os

from elftools.elf.elffile import ELFFile


class Artifact(object):
    def __init__(self, path, build_id, soname, is_exec, machine, elfclass):
        self.path = path
        self.build_id = build_id      # hex 或 None
        self.soname = soname
        self.is_exec = is_exec
        self.machine = machine
        self.elfclass = elfclass

    @property
    def name(self):
        return os.path.basename(self.path)


class MatchResult(object):
    """一个 core 模块与产物的配对结果。status: matched / byname / missing / overridden"""

    def __init__(self, module, artifact=None, status="missing", note=""):
        self.module = module
        self.artifact = artifact
        self.status = status
        self.note = note

    @property
    def confidence(self):
        return {"matched": "高(build-id一致)", "byname": "中(仅文件名一致)",
                "overridden": "手动指定", "missing": "无"}[self.status]


def read_artifact_info(path):
    """快速读产物 build-id / soname / 类型。非 ELF 返回 None。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
            if head != b"\x7fELF":
                return None
            f.seek(0)
            elf = ELFFile(f)
            if elf.header.e_type not in ("ET_EXEC", "ET_DYN"):
                return None
            build_id = None
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_NOTE":
                    for note in seg.iter_notes():
                        if note["n_type"] == "NT_GNU_BUILD_ID":
                            desc = note["n_desc"]
                            # pyelftools 对 build-id 已解码为十六进制字符串
                            build_id = desc if isinstance(desc, str) else bytes(desc).hex()
                            break
                if build_id:
                    break
            soname = None
            if elf.header.e_type == "ET_DYN":
                for sec in elf.iter_sections():
                    if sec.header.sh_type == "SHT_DYNAMIC":
                        for t, v in sec.iter_tags():
                            if t == "DT_SONAME":
                                soname = v.soname
                                break
                    if soname:
                        break
            machine = elf.header["e_machine"]
            if isinstance(machine, str):
                machine = {"EM_ARM": 40, "EM_AARCH64": 183, "EM_RISCV": 243,
                           "EM_386": 3, "EM_X86_64": 62}.get(machine, machine)
            return Artifact(path, build_id, soname,
                            elf.header.e_type == "ET_EXEC", machine, elf.elfclass)
    except Exception:
        return None


def scan_artifacts(root):
    """递归扫描产物目录，返回 Artifact 列表。"""
    arts = []
    if not root or not os.path.isdir(root):
        return arts
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) < 64:
                    continue
            except OSError:
                continue
            info = read_artifact_info(p)
            if info:
                arts.append(info)
    return arts


def match_modules(modules, artifacts, overrides=None, exe_hint=None):
    """core 模块 -> 产物 配对。

    overrides: {soname: path} 手动指定；
    exe_hint: --exe 指定的主程序。
    返回 MatchResult 列表（含主程序，主程序用 exe_hint 或模块表第一项判断）。
    """
    overrides = overrides or {}
    by_bid = {}
    by_name = {}
    for a in artifacts:
        if a.build_id:
            by_bid.setdefault(a.build_id, []).append(a)
        by_name.setdefault(a.soname or a.name, []).append(a)

    results = []
    for mod in modules:
        art = None
        status, note = "missing", ""
        if mod.name in overrides:
            art = read_artifact_info(overrides[mod.name])
            status = "overridden" if art else "missing"
            if not art:
                note = "手动指定的文件不可用: %s" % overrides[mod.name]
        elif mod.build_id and mod.build_id in by_bid:
            arts = by_bid[mod.build_id]
            art = arts[0]
            status = "matched"
            if len(arts) > 1:
                note = "产物目录中有 %d 个同 build-id 文件，取第一个" % len(arts)
        elif mod.name in by_name:
            cands = [a for a in by_name[mod.name]]
            art = cands[0]
            status = "byname"
            if mod.build_id:
                note = "build-id(%s)在产物目录中未找到，按文件名配对" % mod.build_id[:12]
            else:
                note = "core中无法还原该模块build-id，按文件名配对"
        results.append(MatchResult(mod, art, status, note))
    return results


# ---------------------------------------------------------------------------
# 符号解析（函数级，纯 Python）
# ---------------------------------------------------------------------------

class SymbolResolver(object):
    """从产物 .symtab 定位函数；可选叠加 addr2line 行号。"""

    def __init__(self):
        self._files = {}       # path -> sorted [(start, end, name)]

    def load(self, path):
        if path in self._files:
            return self._files[path]
        syms = []
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                for sec in elf.iter_sections():
                    if sec.header.sh_type != "SHT_SYMTAB":
                        continue
                    for s in sec.iter_symbols():
                        v = s["st_value"]
                        sz = s["st_size"]
                        if v and sz and s["st_info"]["type"] == "STT_FUNC":
                            syms.append((v, v + sz, s.name))
        except Exception:
            pass
        syms.sort()
        self._files[path] = syms
        return syms

    def lookup(self, path, addr, base=0):
        """addr 是运行时地址；base 是该产物在 core 里的加载基址。返回函数名或 None。"""
        import bisect
        syms = self.load(path)
        if not syms:
            return None
        off = addr - base
        i = bisect.bisect_right(syms, (off, float("inf"), "")) - 1
        if i < 0:
            return None
        start, end, name = syms[i]
        if start <= off < end:
            return name
        return None


def gdb_symbol_script(exe_artifact, matches, core):
    """生成喂给 gdb 的符号加载脚本行。

    exe 用 file；so 用 add-symbol-file（.text 的运行时地址）。
    """
    lines = ["set pagination off", "set confirm off", "set print demangle on"]
    if exe_artifact:
        lines.append("file %s" % exe_artifact.path)
    for m in matches:
        if m.artifact is None or m.artifact.path == (exe_artifact.path if exe_artifact else None):
            continue
        try:
            text_addr = _text_vaddr(m.artifact.path)
        except Exception:
            text_addr = 0
        if text_addr is None:
            continue
        lines.append("add-symbol-file %s 0x%x" % (m.artifact.path, m.module.base + text_addr))
    return lines


def _text_vaddr(path):
    """产物 .text 的 sh_addr（ET_DYN 下是相对基址的偏移）。"""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".text")
        if sec is None:
            return 0
        return sec.header.sh_addr

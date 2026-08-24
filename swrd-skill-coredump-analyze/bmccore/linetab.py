# -*- coding: utf-8 -*-
"""纯 Python 行号解析：直接读产物的 DWARF 行号表（离线替代 addr2line）。

编译服务器无交叉 addr2line（离线环境）时的替代能力：产物内相对地址 →
"文件名:行号"。基于 vendored pyelftools，支持 DWARF v4/v5 行号表，
按产物路径缓存；只取文件名（源码联动按 basename 匹配，无需拼目录，
也绕开 v4/v5 include_directory 布局差异）。

注意：首次解析某个产物会建立全量行号表（大库如 libc 需数秒、几十 MB
内存），后续同产物查询走缓存。
"""
import bisect
import os

from elftools.elf.elffile import ELFFile

_cache = {}      # path -> (sorted_addrs, [(basename, line), ...])


def _basename(name):
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return name.rsplit("/", 1)[-1]


def _build(path, progress=None):
    addrs, rows = [], []
    try:
        f = open(path, "rb")
    except OSError:
        return addrs, rows
    with f:
        try:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return addrs, rows
            dw = elf.get_dwarf_info()
            n_cu = 0
            for cu in dw.iter_CUs():
                n_cu += 1
                if progress and n_cu % 50 == 0:
                    progress("[行号] %s 已解析 %d 个 CU"
                             % (os.path.basename(path), n_cu))
                try:
                    lp = dw.line_program_for_CU(cu)
                except Exception:
                    lp = None
                if lp is None:
                    continue
                try:
                    files = lp.header["file_entry"]
                    ver = lp.header["version"]
                except Exception:
                    continue
                one_based = 1 if ver < 5 else 0   # v4 文件号 1 起，v5 0 起
                for ent in lp.get_entries():
                    st = ent.state
                    if st is None or st.end_sequence:
                        continue
                    fi = st.file - one_based
                    if not (0 <= fi < len(files)):
                        continue
                    addrs.append(st.address)
                    rows.append((_basename(files[fi].name), st.line))
        except Exception:
            pass
    order = sorted(range(len(addrs)), key=lambda i: addrs[i])
    return ([addrs[i] for i in order], [rows[i] for i in order])


def lookup(path, addr, progress=None):
    """addr 为产物内相对地址；命中返回 'base.c:123'，否则 None。"""
    if path not in _cache:
        _cache[path] = _build(path, progress)
    sa, rr = _cache[path]
    if not sa:
        return None
    i = bisect.bisect_right(sa, addr) - 1
    if i < 0:
        return None
    name, line = rr[i]
    if not name or not line or line < 0:
        return None
    return "%s:%d" % (name, line)


def resolve(path, addrs, progress=None):
    """批量：{相对地址: 'base.c:123'}（无行号信息的地址不出现在结果里）。"""
    out = {}
    for a in addrs:
        loc = lookup(path, a, progress)
        if loc:
            out[a] = loc
    return out

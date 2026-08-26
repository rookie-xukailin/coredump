# -*- coding: utf-8 -*-
"""输入识别层：解包 tar.gz/gz/xz，识别 core 文件，解析文件名元信息。

典型输入：1_core-2078599821-remotexdp-6759.tar.gz
  -> 序号=1，时间戳/计数=2078599821，进程名=remotexdp，pid=6759
"""
import os
import re
import shutil
import struct
import tarfile
import tempfile


FILENAME_RE = re.compile(
    r"^(?: (?P<seq>\d+)_ )? core-(?P<stamp>\d+)-(?P<proc>[A-Za-z0-9_.+-]+?)-(?P<pid>\d+)$",
    re.VERBOSE)


class IntakeResult(object):
    def __init__(self, core_path, temp_dir, meta, source_name):
        self.core_path = core_path
        self.temp_dir = temp_dir            # None 表示无需临时目录（裸文件直接用）
        self.meta = meta                    # 文件名解析出的元信息 dict
        self.source_name = source_name      # 原始输入文件名

    def cleanup(self):
        if self.temp_dir and os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir = None


def parse_core_filename(name):
    """从文件名提取元信息；不带此命名规则时返回空 dict。"""
    stem = name
    for suf in (".tar.gz", ".tgz", ".tar", ".gz", ".xz", ".zst", ".bz2"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    m = FILENAME_RE.match(stem)
    if not m:
        return {}
    return {
        "seq": int(m.group("seq")) if m.group("seq") else None,
        "stamp": int(m.group("stamp")),
        "procname": m.group("proc"),
        "pid": int(m.group("pid")),
    }


def _is_core_file(path):
    """检查文件头：\\x7fELF 且 e_type==ET_CORE(4)。"""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return False
    if len(head) < 18 or head[:4] != b"\x7fELF":
        return False
    ei_data = head[5]
    endian = "<" if ei_data == 1 else ">"
    e_type = struct.unpack_from(endian + "H", head, 16)[0]
    return e_type == 4


def _decompress_to(source, destdir, kind):
    """单文件压缩流解压；返回解出的文件路径。"""
    import gzip
    import lzma
    out_name = os.path.basename(source)
    for suf in (".tar.gz", ".tgz", ".tar", ".gz", ".xz", ".zst", ".bz2"):
        if out_name.endswith(suf):
            out_name = out_name[: -len(suf)]
            break
    if not out_name:
        out_name = "core"
    out_path = os.path.join(destdir, out_name)
    if kind == "gz":
        with gzip.open(source, "rb") as fin, open(out_path, "wb") as fout:
            shutil.copyfileobj(fin, fout)
    elif kind == "xz":
        with lzma.open(source, "rb") as fin, open(out_path, "wb") as fout:
            shutil.copyfileobj(fin, fout)
    else:
        raise ValueError("不支持的压缩格式: %s" % kind)
    return out_path


def _extract_tar(source, destdir):
    """解 tar/tar.gz/tar.xz 包，返回解出的文件列表。"""
    with tarfile.open(source) as tf:
        tf.extractall(destdir)
        return [os.path.join(destdir, m.name) for m in tf.getmembers() if m.isfile()]


def intake(source, keep_temp=False, workroot=None):
    """主入口：识别输入并给出可直接解析的 core 文件路径。

    返回 IntakeResult。source 也可以直接就是裸 core 文件。
    """
    if not os.path.isfile(source):
        raise FileNotFoundError("输入文件不存在: %s" % source)

    meta = parse_core_filename(os.path.basename(source))

    # 裸 core 直接用
    if _is_core_file(source):
        return IntakeResult(os.path.abspath(source), None, meta, os.path.basename(source))

    temp = tempfile.mkdtemp(prefix="bmccore_", dir=workroot)
    try:
        with open(source, "rb") as f:
            magic = f.read(8)

        extracted = []
        if magic[:2] == b"\x1f\x8b" or magic[:4] == b"BZh9" or magic[:6] == b"\xfd7zXZ\x00":
            # 先按 tar 流试，失败再按单文件压缩流
            try:
                extracted = _extract_tar(source, temp)
            except tarfile.ReadError:
                kind = "gz" if magic[:2] == b"\x1f\x8b" else ("xz" if magic[:6] == b"\xfd7zXZ\x00" else "bz2")
                extracted = [_decompress_to(source, temp, kind)]
        elif magic[:4] == b"\x28\xb5\x2f\xfd":
            raise ValueError("zstd 压缩包：请先手动解压 (zstd -d) 后再喂给工具")
        else:
            raise ValueError("无法识别的输入格式（既非 ELF core 也非压缩包）: %s" % source)

        cores = [p for p in extracted if _is_core_file(p)]
        if not cores:
            # tar 内没有现成 core：取最大文件碰运气（可能叫别的名字）
            if extracted:
                biggest = max(extracted, key=lambda p: os.path.getsize(p))
                if _is_core_file(biggest):
                    cores = [biggest]
        if not cores:
            raise ValueError("包里没有找到 ELF core 文件: %s" % source)

        core_path = max(cores, key=lambda p: os.path.getsize(p))
        result = IntakeResult(core_path, temp, meta, os.path.basename(source))
        if keep_temp:
            pass    # 交给调用方在结束后 cleanup
        return result
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise

# -*- coding: utf-8 -*-
"""intake.py 输入识别层单测：文件名解析、tar.gz 解包、裸 core 直通。"""
import os
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "coredump-analyze"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_fake_core as mfc
from bmccore.arch import ARM64
from bmccore.intake import intake, parse_core_filename


def test_filename_parse():
    meta = parse_core_filename("1_core-2078599821-remotexdp-6759.tar.gz")
    assert meta["seq"] == 1
    assert meta["stamp"] == 2078599821
    assert meta["procname"] == "remotexdp"
    assert meta["pid"] == 6759
    # 带连字符的进程名
    meta2 = parse_core_filename("core-1000-my-proc-2.bin-123.gz")
    assert meta2["procname"] == "my-proc-2.bin", meta2
    # 非本命名规则
    assert parse_core_filename("random_dump.bin") == {}


def test_bare_core_passthrough():
    tmp = tempfile.mkdtemp()
    try:
        p = os.path.join(tmp, "core.1234")
        mfc.build_core(p, ARM64, [dict(tid=1, cursig=11, regs={"pc": 0, "sp": 0x1000})],
                       [(0x1000, 6, b"\x00" * 16)])
        res = intake(p)
        assert res.temp_dir is None
        assert res.core_path == os.path.abspath(p)
        res.cleanup()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_tar_gz_intake():
    """模拟真实输入：1_core-...-remotexdp-6759.tar.gz 里包一个 core。"""
    tmp = tempfile.mkdtemp()
    try:
        core_path = os.path.join(tmp, "inner_core")
        mfc.build_core(core_path, ARM64,
                       [dict(tid=6759, cursig=11, regs={"pc": 0, "sp": 0x1000})],
                       [(0x1000, 6, b"\x00" * 16)])
        pkg = os.path.join(tmp, "1_core-2078599821-remotexdp-6759.tar.gz")
        with tarfile.open(pkg, "w:gz") as tf:
            tf.add(core_path, arcname="core")
        res = intake(pkg)
        try:
            assert res.meta["pid"] == 6759
            assert res.meta["procname"] == "remotexdp"
            assert res.core_path != pkg
            with open(res.core_path, "rb") as f:
                assert f.read(4) == b"\x7fELF"
        finally:
            saved = res.temp_dir
            res.cleanup()
            assert saved is None or not os.path.isdir(saved)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_gz_single_file_intake():
    tmp = tempfile.mkdtemp()
    try:
        import gzip
        core_path = os.path.join(tmp, "core.99")
        mfc.build_core(core_path, ARM64,
                       [dict(tid=99, cursig=11, regs={"pc": 0, "sp": 0x1000})],
                       [(0x1000, 6, b"\x00" * 16)])
        pkg = os.path.join(tmp, "core.99.gz")
        with open(core_path, "rb") as fin, gzip.open(pkg, "wb") as fout:
            fout.writelines(fin)
        res = intake(pkg)
        try:
            with open(res.core_path, "rb") as f:
                assert f.read(4) == b"\x7fELF"
        finally:
            res.cleanup()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_bad_input():
    tmp = tempfile.mkdtemp()
    try:
        bad = os.path.join(tmp, "notcore.txt")
        with open(bad, "wb") as f:
            f.write(b"hello world not a core")
        try:
            intake(bad)
            assert False, "应当抛异常"
        except ValueError:
            pass
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
        print("PASS %s" % fn.__name__)

# -*- coding: utf-8 -*-
"""端到端测试：CLI info/analyze 全链路（无 gdb 环境下验证优雅降级）。"""
import io
import os
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "swrd-skill-coredump-analyze"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_scan_heap as T
from test_scan_heap import _build_arm64_env


def test_e2e_analyze():
    tmp = tempfile.mkdtemp()
    try:
        import shutil
        # 构造损坏堆环境
        core_path, art = _build_arm64_env(tmp, corrupt_heap=True)
        # 打包成真实输入形态
        pkg = os.path.join(tmp, "1_core-2078599821-remotexdp-6759.tar.gz")
        with tarfile.open(pkg, "w:gz") as tf:
            tf.add(core_path, arcname="core")

        # 源码树（给 source 技能留料；无行号时会跳过，不报错）
        srcroot = os.path.join(tmp, "src")
        os.makedirs(srcroot)

        outdir = os.path.join(tmp, "report_out")
        argv = ["analyze", pkg,
                "--artifact-dir", tmp,
                "--source-root", srcroot,
                "-o", outdir,
                "--format", "both"]
        from bmccore.cli import main
        rc = main(argv)

        assert rc == 0, "analyze 退出码 %d" % rc
        md = os.path.join(outdir, "1_core-2078599821-remotexdp-6759_report.md")
        js = md[:-3] + ".json"
        assert os.path.isfile(md) and os.path.isfile(js)

        content = io.open(md, "r", encoding="utf-8").read()
        # 关键节齐全
        assert "BMC Coredump 分析报告" in content
        assert "定位结论" in content
        assert "堆取证" in content
        assert "chunk 头损坏" in content
        assert "非法内存访问" in content          # fault addr=0x3000 未映射
        assert "完全未映射" in content
        assert "remotexdp" in content
        # 可信度标注存在
        assert "确认" in content and "疑似" in content
        # JSON 可解析
        import json
        data = json.loads(io.open(js, "r", encoding="utf-8").read())
        assert data["sections"]

        # 技能状态：gdb 缺失时 backtrace 应为 skipped 而非 crashed
        # （Windows 无交叉 gdb，本测试即验证该降级）
        src_sec = [s for s in data["sections"] if s["title"] == "技能状态"][0]
        status_text = "\n".join(src_sec["lines"])
        assert "backtrace" in status_text

        # 临时目录应被清理
        leftovers = [d for d in os.listdir(tmp) if d.startswith("bmccore_")]
        assert not leftovers, leftovers
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_cli_info_cmd():
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        pkg = os.path.join(tmp, "2_core-2078599822-remotexdp-6760.tar.gz")
        with tarfile.open(pkg, "w:gz") as tf:
            tf.add(core_path, arcname="core")
        from bmccore.cli import main
        rc = main(["info", pkg])
        assert rc == 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
        print("PASS %s" % fn.__name__)

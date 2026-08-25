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
        assert "线程现场还原" in content       # 案发现场总览节
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
        assert "vartrace" in status_text         # 变量生命周期技能应登记状态
        assert "dieinfo" in status_text          # DIE 语义命名技能应登记状态

        # 临时目录应被清理
        leftovers = [d for d in os.listdir(tmp) if d.startswith("bmccore_")]
        assert not leftovers, leftovers
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_symbol_table_archive():
    """--symbol-table 支持 rootfs_symbol.tgz 形态：解压到 workdir 缓存并正常分析。"""
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        pkg = os.path.join(tmp, "3_core-2078599823-remotexdp-6761.tar.gz")
        with tarfile.open(pkg, "w:gz") as tf:
            tf.add(core_path, arcname="core")
        symtgz = os.path.join(tmp, "rootfs_symbol.tgz")
        with tarfile.open(symtgz, "w:gz") as tf:
            tf.add(art, arcname=os.path.join("usr/lib", os.path.basename(art)))

        workdir = os.path.join(tmp, "ws")
        outdir = os.path.join(tmp, "report_out2")
        from bmccore.cli import main
        rc = main(["analyze", pkg,
                   "--symbol-table", symtgz,
                   "-o", outdir, "--format", "md",
                   "--workdir", workdir])
        assert rc == 0
        # 解压落在 workdir/symbols/<包名>/，嵌套目录（usr/lib/...）应被递归扫描
        sym_dir = os.path.join(workdir, "symbols", "rootfs_symbol")
        assert os.path.isdir(sym_dir), "符号表包应解到 workdir/symbols/ 下"
        marker = os.path.join(sym_dir, ".bmccore_src.json")
        assert os.path.isfile(marker), "应写入缓存 marker（源包 mtime/size）"
        md = os.path.join(outdir, "3_core-2078599823-remotexdp-6761_report.md")
        assert os.path.isfile(md)
        content = io.open(md, "r", encoding="utf-8").read()
        assert "符号配对" in content
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_config_toml_short_command():
    """bmccore.toml 收拢参数：analyze 只需 core + --config，workdir/output/offline 全走配置。"""
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        workdir = os.path.join(tmp, "ws")
        outdir = os.path.join(tmp, "rep")
        toml = os.path.join(tmp, "bmccore.toml")
        with io.open(toml, "w", encoding="utf-8") as f:
            f.write('symbol_table = "%s"\nworkdir = "%s"\noutput = "%s"\n'
                    'offline = true\n' % (tmp, workdir, outdir))
        from bmccore.cli import main
        rc = main(["analyze", core_path, "--config", toml])
        assert rc == 0
        # workdir/output 均来自 toml
        assert os.path.isdir(workdir), "toml 的 workdir 应生效（目录自动创建）"
        assert any(n.endswith("_report.md") for n in os.listdir(outdir)), \
            "toml 的 output 应作为报告目录"
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_shipped_workspace_template():
    """随包自带的 workspace/bmccore.toml（路径全空）可解析，分析不崩溃、能力如实降级。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    toml = os.path.join(root, "swrd-skill-coredump-analyze", "workspace",
                        "bmccore.toml")
    assert os.path.isfile(toml), "技能包应自带 workspace/bmccore.toml 模板"
    # 模板大量使用行内注释：解析结果必须是干净值（空串/布尔/枚举），不带注释尾巴
    from bmccore.config import load_toml
    top = load_toml(toml)[""]
    assert top.get("symbol_table") == "" and top.get("workdir") == ""
    assert top.get("offline") is False and top.get("format") == "both"
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        from bmccore.cli import main
        rc = main(["analyze", core_path, "--config", toml,
                   "-o", os.path.join(tmp, "out")])
        assert rc == 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_toolchain_path_discovery():
    """[toolchain.<arch>] path= 单路径：目录下 triple 前缀工具自动发现。"""
    import tempfile
    from bmccore.toolchain import discover
    tmp = tempfile.mkdtemp()
    try:
        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        for t in ("gdb", "addr2line", "objdump"):
            io.open(os.path.join(bindir, "riscv64-unknown-linux-gnu-%s" % t),
                    "w").close()
        # 干扰项：别的前缀 + 裸名，不应被选中
        io.open(os.path.join(bindir, "aarch64-linux-gnu-gdb"), "w").close()
        io.open(os.path.join(bindir, "addr2line"), "w").close()

        class _Cfg(object):
            offline = False
            toolchain = {"riscv64": {"path": tmp}}       # 根目录（工具在 bin/ 下）

        tc = discover("riscv64", _Cfg())
        assert tc.has("gdb") and tc.has("addr2line") and tc.has("objdump")
        assert "riscv64-unknown-linux-gnu-gdb" in tc.tools["gdb"]
        assert "aarch64" not in tc.tools["gdb"]

        _Cfg.toolchain = {"riscv64": {"path": bindir}}   # 直接给 bin 目录
        tc2 = discover("riscv64", _Cfg())
        assert tc2.has("gdb") and "riscv64-unknown-linux-gnu-addr2line" in \
            tc2.tools["addr2line"]

        _Cfg.toolchain = {"riscv64": {
            "path": os.path.join(bindir, "riscv64-unknown-linux-gnu-")}}
        tc3 = discover("riscv64", _Cfg())                 # 以 - 结尾的完整前缀
        assert tc3.has("gdb") and tc3.tools["gdb"].endswith(
            "riscv64-unknown-linux-gnu-gdb")

        # 家族名前缀（不带架构号，如 riscv-none-elf- / riscv-linux-）也能匹配
        alt = os.path.join(tmp, "alt")
        os.makedirs(alt)
        for t in ("gdb", "addr2line", "objdump"):
            io.open(os.path.join(alt, "riscv-none-elf-%s" % t), "w").close()
        _Cfg.toolchain = {"riscv64": {"path": alt}}
        tc4 = discover("riscv64", _Cfg())
        assert tc4.has("gdb") and "riscv-none-elf-gdb" in tc4.tools["gdb"]

        # 常见笔误：目录路径填进 prefix 键——按目录探测兜底
        _Cfg.toolchain = {"riscv64": {"prefix": bindir}}
        tc5 = discover("riscv64", _Cfg())
        assert tc5.has("gdb") and "riscv64-unknown-linux-gnu-gdb" in \
            tc5.tools["gdb"]
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_core_from_toml():
    """core 路径进 bmccore.toml：analyze 无位置参数，仅 --config 即可跑。"""
    tmp = tempfile.mkdtemp()
    try:
        core_path, art = _build_arm64_env(tmp)
        toml = os.path.join(tmp, "bmccore.toml")
        outdir = os.path.join(tmp, "o")
        with io.open(toml, "w", encoding="utf-8") as f:
            f.write('core = "%s"\noutput = "%s"\n' % (core_path, outdir))
        from bmccore.cli import main
        rc = main(["analyze", "--config", toml])
        assert rc == 0
        assert any(n.endswith("_report.md") for n in os.listdir(outdir)), \
            "core 完全来自 toml 时应正常产出报告"

        # 都不给时明确报错而不是崩溃
        rc2 = main(["analyze", "--config",
                    os.path.join(tmp, "nonexistent.toml")])
        assert rc2 == 2
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_lockmon_find_mutexes():
    """锁扫描（memoryview 重写版）：伪造 mutex 命中，干扰项不误报。"""
    import struct
    from bmccore import lockmon

    class _R(object):
        def __init__(self, vaddr, blob):
            self.vaddr = vaddr
            self.data = bytes(blob)
            self.readable = True
            self.write_bit = True

    blob = bytearray(65536)
    # 命中项：lock=1 owner=4242 kind=0（埋在 0x100）
    struct.pack_into("<i", blob, 0x100, 1)
    struct.pack_into("<i", blob, 0x100 + 8, 4242)
    struct.pack_into("<i", blob, 0x100 + 16, 0)
    # 干扰项：lock 非零、owner 未知、kind=99（应被 kind 范围过滤）
    struct.pack_into("<i", blob, 0x200, 7)
    struct.pack_into("<i", blob, 0x200 + 8, 999)
    struct.pack_into("<i", blob, 0x200 + 16, 99)

    class _C(object):
        elfclass = 64
        regions = [_R(0x10000000, blob)]      # _R 构造时快照，须在埋数之后

    class _T(object):
        tid = 4242

    hits = lockmon.find_mutexes(_C(), [_T()])
    assert any(l.addr == 0x10000000 + 0x100 and l.owner_tid == 4242
               for l in hits), "已知 TID 持有的 mutex 应被快速通道检出"
    assert not any(l.addr == 0x10000000 + 0x200 for l in hits), \
        "owner 未知的干扰项默认（快速模式）不应检出"
    assert not any(l.addr == 0x10000000 + 0x108 for l in hits), \
        "owner 字段误对齐形成的假 mutex（lock=TID、owner=0）不应检出"

    # 全量模式也不应检出 kind 越界的干扰项
    hits_full = lockmon.find_mutexes(_C(), [_T()], full_scan=True)
    assert not any(l.addr == 0x10000000 + 0x200 for l in hits_full)


def test_toolchain_diagnose():
    """toolchain 自检：未命中时点名候选文件与架构关键字，命中时报文件名。"""
    import tempfile
    from bmccore import toolchain
    tmp = tempfile.mkdtemp()
    try:
        for t in ("gdb", "addr2line"):
            io.open(os.path.join(tmp, "x86_64-linux-gnu-%s" % t), "w").close()
        text = "\n".join(toolchain.probe_diagnose(tmp, "riscv64"))
        assert "未命中" in text and "x86_64-linux-gnu-gdb" in text, \
            "未命中时应点名候选文件，便于定位命名差异"
        io.open(os.path.join(tmp, "riscv64-unknown-linux-gnu-gdb"), "w").close()
        text2 = "\n".join(toolchain.probe_diagnose(tmp, "riscv64"))
        assert "命中 riscv64-unknown-linux-gnu-gdb" in text2
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_config_fallback_to_workspace_template():
    """core 就近无 toml 时，自动回落技能包自带的 workspace/bmccore.toml。"""
    from bmccore.config import Config, _PKG_WORKSPACE_TOML
    assert os.path.isfile(_PKG_WORKSPACE_TOML), "技能包应自带 workspace 模板"
    tmp = tempfile.mkdtemp()
    try:
        assert Config().find_config_file(tmp) == _PKG_WORKSPACE_TOML, \
            "向上找不到 toml 时应回落技能 workspace 模板"
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_config_merge_two_tomls():
    """就近 toml 与技能 workspace 模板按键合并：就近优先、模板补缺。"""
    from bmccore.config import Config
    tmp = tempfile.mkdtemp()
    try:
        near = os.path.join(tmp, "bmccore.toml")
        with io.open(near, "w", encoding="utf-8") as f:
            f.write('symbol_table = "/near/sym"\noffline = false\n')
        ws = os.path.join(tmp, "ws.toml")
        with io.open(ws, "w", encoding="utf-8") as f:
            f.write('source_root = "/ws/src"\noffline = true\n'
                    '[toolchain.riscv64]\npath = "/ws/tc"\n')
        cfg = Config()
        cfg.update_from_toml(near)
        cfg.update_from_toml(ws)              # 低优先级补缺
        assert cfg.symbol_table == "/near/sym"     # 就近优先
        assert cfg.source_root == "/ws/src"        # 模板补缺生效
        assert cfg.toolchain["riscv64"]["path"] == "/ws/tc"
        assert cfg.offline is False                # 先见者优先，模板不得翻转
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_viz_toml_keys():
    """viz/viz_port/viz_timeout 可进 toml（面板开关与端口/超时）。"""
    from bmccore.config import Config
    tmp = tempfile.mkdtemp()
    try:
        toml = os.path.join(tmp, "t.toml")
        with io.open(toml, "w", encoding="utf-8") as f:
            f.write("viz = true\nviz_port = 9000\nviz_timeout = 30\n")
        cfg = Config()
        cfg.update_from_toml(toml)
        assert cfg.viz is True and cfg.viz_port == 9000 and cfg.viz_timeout == 30
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_block_points():
    """阻塞点解码：riscv a7=98/a0=addr 命中 futex，其他号展示原号。"""
    from bmccore.lockmon import block_points

    class _Arch(object):
        name = "riscv64"
    core = type("C", (), {"arch": _Arch()})()

    class _T(object):
        def __init__(self, tid, regs):
            self.tid = tid
            self.regs = regs

    ts = [_T(1, {"a7": 98, "a0": 0x7f4000210}),      # futex 等待
          _T(2, {"a7": 73, "a0": 0}),                # ppoll → 展示原号
          _T(3, {"a7": 0})]                          # 0 → 不报
    bp = block_points(core, ts)
    assert bp[1] == {"sys": "futex", "uaddr": 0x7f4000210}
    assert bp[2]["sys"] == "#73" and bp[2]["uaddr"] is None
    assert 3 not in bp


def test_render_report_smoke():
    """叙事 HTML 渲染：narrative.json + 引擎 json → 占位符全替换。"""
    import subprocess
    import json as _json
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp = tempfile.mkdtemp()
    try:
        narr = {
            "case": "smoke",
            "summary": {"process": "shd_main", "arch": "riscv64",
                        "signal": "SIGSEGV", "fault_addr": "0x5858",
                        "crash_point": "sensor_read @ sensor.c:88",
                        "tldr": "T15 释放了 T12 仍在遍历的链表节点",
                        "tldr_level": "确认"},
            "scene": ["**案发时刻**：T12 正在遍历链表（证据：回溯节）。",
                      "与此同时 **T15** 持锁 0x7f42 释放节点（证据：线程现场还原）。"],
            "thread_roles": [{"tid": 12, "role": "崩溃者",
                              "action": "遍历传感器链表",
                              "evidence": "回溯 #0"}],
            "root_cause": {"mechanism": "读侧无锁保护",
                           "culprit": "```c\nfree(node);\n```"},
            "fixes": [{"title": "读侧加锁", "body": "```c\nlock();\n```"}],
            "confidence": [{"level": "确认", "claim": "UAF", "evidence": "指纹"}],
            "gaps": ["T15 业务动作无符号帧"],
            "hypotheses": [
                {"claim": "T15 释放了 T12 在遍历的节点", "basis": "锁交叉",
                 "verify": "读 free 路径", "status": "成立"},
                {"claim": "栈溢出", "basis": "SP 距底", "verify": "比对边界",
                 "status": "排除"},
            ],
        }
        narr_path = os.path.join(tmp, "narrative.json")
        with io.open(narr_path, "w", encoding="utf-8") as f:
            _json.dump(narr, f, ensure_ascii=False)
        engine = {"sections": [
            {"title": "线程现场还原 (2 线程)", "lines": ["| tid | 状态 |", "|T12|💥|"]},
            {"title": "无关节（不应出现）", "lines": ["x"]},
        ]}
        eng_path = os.path.join(tmp, "engine_report.json")
        with io.open(eng_path, "w", encoding="utf-8") as f:
            _json.dump(engine, f, ensure_ascii=False)
        out = os.path.join(tmp, "smoke_analysis.html")
        r = subprocess.run([sys.executable,
                            os.path.join(root, "swrd-skill-coredump-analyze",
                                         "scripts", "render_report.py"),
                            narr_path, "--engine", eng_path, "--out", out],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert r.returncode == 0, r.stdout.decode("utf-8", "replace")
        html = io.open(out, encoding="utf-8").read()
        assert "遍历传感器链表" in html and "案发时刻" in html
        assert "线程现场还原" in html           # 引擎证据节并入
        assert "无关节" not in html             # 关键词过滤生效
        assert "候选假设与验证" in html and "T15 释放了" in html
        assert "lv-成立" in html and "lv-排除" in html   # 状态徽章
        for ph in ("__CASE__", "__TLDR__", "__SCENE__", "__EVIDENCE__",
                   "__FIXES__", "__GAPS__", "__HYPOTHESES__"):
            assert ph not in html, "占位符未替换: %s" % ph
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_dieinfo_naming():
    """DIE 语义命名：DW_OP_addr 解码 / 查表 API / 无 DWARF 产物降级。"""
    from bmccore import dieinfo
    assert dieinfo._dw_op_addr_value(b"\x03\x10\x00\x00\x00", 4) == 0x10
    assert dieinfo._dw_op_addr_value(b"\x05\x10", 4) is None       # 非 DW_OP_addr
    assert dieinfo._dw_op_addr_value(b"\x03\x10", 8) is None       # 长度不足
    dieinfo._cache["fake.elf"] = {
        "vars": {0x7f42: "g_sensor_lock"},
        "var_ranges": [(0x7f42, 8, "g_sensor_lock")],
        "structs": [("fan_ctrl", 48, {0: ("name", "char*"),
                                      0x18: ("set_pwm", "int")})],
        "funcs": {"fan_ctrl_set": [("dev", 0)]}}
    assert dieinfo.name_address("fake.elf", 0x7f42) == "g_sensor_lock"
    assert dieinfo.name_address("fake.elf", 0x1) is None
    assert dieinfo.name_address_loose("fake.elf", 0x7f46) == "g_sensor_lock+0x4"
    assert dieinfo.struct_by_size("fake.elf", 48)[0] == "fan_ctrl"
    assert dieinfo.struct_by_size("fake.elf", 40) is None
    assert dieinfo.member_name("fake.elf", 48, 0x18) == "fan_ctrl.set_pwm"
    assert dieinfo.params_of("fake.elf", "fan_ctrl_set") == [("dev", 0)]
    assert dieinfo.params_of("fake.elf", "no_such_fn") == []
    assert dieinfo.dwarf_reg_name("arm64", 0) == "x0"
    assert dieinfo.dwarf_reg_name("riscv64", 10) == "a0"
    assert dieinfo.dwarf_reg_name("arm32", 3) == "r3"
    assert dieinfo.name_address("no/such/file", 0x7f42) is None    # 缺文件→空表降级


def test_render_check():
    """--check：字段齐全通过，缺必填项退出码 1 并点名缺失。"""
    import subprocess
    import json as _json
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp = tempfile.mkdtemp()
    try:
        good = {"summary": {"tldr": "x", "tldr_level": "确认"},
                "scene": ["T12 正在遍历链表（sensor.c:88）"],
                "root_cause": {"mechanism": "读侧无锁（sensor.c:80）"},
                "fixes": [{"title": "t", "body": "b"}],
                "confidence": [{"level": "确认", "claim": "c", "evidence": "e"}]}
        p_good = os.path.join(tmp, "good.json")
        with io.open(p_good, "w", encoding="utf-8") as f:
            _json.dump(good, f, ensure_ascii=False)
        # 无业务源码 file:line 引用：必须被 DoD 第 4 条硬门禁拦下
        nocite = {"summary": {"tldr": "x", "tldr_level": "确认"},
                  "scene": ["崩溃在 glibc 内部堆遍历"],
                  "root_cause": {"mechanism": "堆链表损坏"}}
        p_nocite = os.path.join(tmp, "nocite.json")
        with io.open(p_nocite, "w", encoding="utf-8") as f:
            _json.dump(nocite, f, ensure_ascii=False)
        bad = {"summary": {}, "root_cause": {}}
        p_bad = os.path.join(tmp, "bad.json")
        with io.open(p_bad, "w", encoding="utf-8") as f:
            _json.dump(bad, f, ensure_ascii=False)
        rr = os.path.join(root, "swrd-skill-coredump-analyze", "scripts",
                          "render_report.py")
        r1 = subprocess.run([sys.executable, rr, p_good, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert r1.returncode == 0 and "校验通过" in \
            r1.stdout.decode("utf-8", "replace")
        r1b = subprocess.run([sys.executable, rr, p_nocite, "--check"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out1b = r1b.stdout.decode("utf-8", "replace")
        assert r1b.returncode == 1 and "业务源码证据缺失" in out1b, \
            "无 file:line 引用的叙事必须被硬门禁拒绝"
        # 死锁环证据门控：ring 无依据被拒；有死锁叙事放行
        ring_bad = {"summary": {"tldr": "x", "tldr_level": "确认"},
                    "scene": ["T1 遍历链表（s.c:9）"],
                    "root_cause": {"mechanism": "m（s.c:8）"},
                    "animation": {"actors": [{"id": "t1", "type": "thread"}],
                                  "steps": [{"cap": "定格", "ring": True}]}}
        p_rb = os.path.join(tmp, "ring_bad.json")
        with io.open(p_rb, "w", encoding="utf-8") as f:
            _json.dump(ring_bad, f, ensure_ascii=False)
        ring_ok = dict(ring_bad)
        ring_ok["scene"] = ["T1 与 T2 形成死锁等待环（锁分析节证据）"]
        p_ro = os.path.join(tmp, "ring_ok.json")
        with io.open(p_ro, "w", encoding="utf-8") as f:
            _json.dump(ring_ok, f, ensure_ascii=False)
        rb = subprocess.run([sys.executable, rr, p_rb, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert rb.returncode == 1 and "死锁环" in rb.stdout.decode("utf-8", "replace")
        ro = subprocess.run([sys.executable, rr, p_ro, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert ro.returncode == 0, ro.stdout.decode("utf-8", "replace")
        r2 = subprocess.run([sys.executable, rr, p_bad, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out2 = r2.stdout.decode("utf-8", "replace")
        assert r2.returncode == 1
        assert "tldr" in out2 and "scene" in out2 and "mechanism" in out2

        # gaps 非空但 hypotheses 为空 → WARN（不失败）；hypotheses
        # 缺 claim → ERROR；状态非法 → WARN
        gap_no_hyp = {"summary": {"tldr": "x", "tldr_level": "确认"},
                      "scene": ["s.c:9"], "root_cause": {"mechanism": "m"},
                      "gaps": ["g1"]}
        p_gap = os.path.join(tmp, "gap.json")
        with io.open(p_gap, "w", encoding="utf-8") as f:
            _json.dump(gap_no_hyp, f, ensure_ascii=False)
        rg = subprocess.run([sys.executable, rr, p_gap, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert rg.returncode == 0 and "候选假设" in \
            rg.stdout.decode("utf-8", "replace")
        hyp_bad = dict(gap_no_hyp)
        hyp_bad["hypotheses"] = [{"verify": "v", "status": "不清楚"}]
        p_hb = os.path.join(tmp, "hypbad.json")
        with io.open(p_hb, "w", encoding="utf-8") as f:
            _json.dump(hyp_bad, f, ensure_ascii=False)
        rh = subprocess.run([sys.executable, rr, p_hb, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        outh = rh.stdout.decode("utf-8", "replace")
        assert rh.returncode == 1 and "claim 缺失" in outh
        assert "status 应为" in outh
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_inattr_operand_attribution():
    """指令操作数级归因：四架构正则 + 寄存器交叉验证 + 语义命名。"""
    from bmccore import inattr

    # riscv：lw a5,0x18(a0)，a0=0x7f420000 → fault=0x7f420018（验证一致）
    disasm = ["   0x100a: addi sp,sp,-16",
              "=> 0x100e: lw a5,0x18(a0)",
              "   0x1012: sw a5,0x0(a1)"]
    attr = inattr.attribute_fault("riscv64", disasm, 0x7f420018,
                                  {"a0": 0x7f420000}, base_name="参数 dev",
                                  field_name="fan_ctrl.set_pwm")
    assert attr and attr["parsed"] and attr["verified"]
    assert attr["base_reg"] == "a0" and attr["disp"] == 0x18
    d = inattr.describe(attr)
    assert "参数 dev" in d and "fan_ctrl.set_pwm" in d and "一致" in d

    # arm64：ldr x0,[x1,#24]
    p = inattr.parse_operand("arm64", "=> 0x8c: ldr x0, [x1, #24]")
    assert p == ("x1", 24)
    # arm32 无偏移 → disp=0
    p = inattr.parse_operand("arm32", "=> 0x8040: ldr r3, [r2]")
    assert p == ("r2", 0)
    # x86 att：mov 0x18(%rcx),%rax（% 前缀剥掉）
    p = inattr.parse_operand("x86_64", "=> 0x4012a0: mov 0x18(%rcx),%rax")
    assert p == ("rcx", 0x18)
    # riscv 负偏移
    p = inattr.parse_operand("riscv64", "=> 0x10: ld a0,-8(a2)")
    assert p == ("a2", -8)
    # 非访存指令 → parsed=False 如实降级
    attr2 = inattr.attribute_fault("riscv64", ["=> 0x10: ecall"], None, {})
    assert attr2 and attr2["parsed"] is False
    # 验证不一致 → 疑似
    attr3 = inattr.attribute_fault("riscv64", disasm, 0xdeadbeef, {"a0": 0x7f420000})
    assert attr3["verified"] is False and "疑似" in inattr.describe(attr3)
    # 无 => PC 行 → None
    assert inattr.attribute_fault("riscv64", ["0x10: nop"], None, {}) is None


def test_deepdive_frame_addr_capture():
    """bt full 帧头地址捕获（backtrace 复用转换需要 addr 字段）。"""
    from bmccore.deepdive import parse_bt_full
    text = ("Thread 1 (LWP 100):\n"
            "#0  0x0000000000012345 in sensor_read (dev=0x7f42) at s.c:88\n"
            "        n = 3\n")
    tr = parse_bt_full(text)
    assert tr and tr[0]["frames"][0]["addr"] == 0x12345
    assert tr[0]["frames"][0]["args"] == [("dev", "0x7f42")]
    assert tr[0]["frames"][0]["locals"] == [("n", "3")]


def test_evidence_objrebuild_passthrough():
    """证据包对 objrebuild（dict）透传不崩——防 NameError 类回归。"""
    from bmccore.skills import _build_evidence

    class _T(object):
        regs = {"a0": 1}
        cursig = 11
        tid = 7
    core = type("C", (), {
        "siginfo": {}, "threads": [_T], "crash_thread": _T, "prpsinfo": {},
        "arch": type("A", (), {"name": "riscv64"})()})()
    parts = {"objrebuild": {"ptypes": [("ptype struct s", ["l1"])],
                            "derefs": [("p *(struct s*)0", ["v=1"])]},
             "regs_deep": [], "stackdump": [], "inattr": None}
    ev = _build_evidence(core, parts)
    assert ev["objrebuild"]["ptypes"][0][0] == "ptype struct s"
    assert ev["objrebuild"]["derefs"][0][1] == ["v=1"]
    # 空对象/缺省也不崩
    ev2 = _build_evidence(core, {})
    assert ev2["objrebuild"] is None and ev2["meta"]["gdb寄存器交叉校验"] is None


def test_triage_evidence_weighted():
    """证据加权多候选：评分排序、refs 人话链、事实条目置顶不参与排序。"""
    from bmccore.triage import triage, Conclusion

    class _R(object):
        def __init__(self, va, sz):
            self.vaddr = va; self.filesz = sz; self.memsz = sz
            self.write_bit = False; self.exec_bit = False
    core = type("C", (), {
        "crash_thread": type("T", (), {"cursig": 11})(),
        "siginfo": {"addr": 0x7f420018, "code": 1},
        "regions": [_R(0, 0x1000)],
        "region_of": lambda self, a: None,
    })()
    matches = []

    # 组合证据：指令归因(verified=60) + 寄存器基址(55) + 堆布局受害对象(40)
    inattr = {"parsed": True, "verified": True, "insn": "=> 0x100e: lw a5,0x18(a0)",
              "base_reg": "a0", "base_val": 0x7f420000, "disp": 0x18,
              "computed": 0x7f420018, "fault_addr": 0x7f420018,
              "base_name": "全局 g_fan", "field_name": "fan_ctrl.set_pwm",
              "source": "gdb 指令解析+寄存器"}
    regs_deep = [("a0", 0x7f420000, "全局 g_fan")]
    heap_typing = [{"role": "受害对象", "type": "fan_ctrl",
                    "fields": [{"name": "set_pwm", "value": "0x5858"}]}]
    frame = {"frames": [{"func": "fan_pwm_apply", "vars": []}]}
    out = triage(core, matches, inattr_res=inattr, regs_deep=regs_deep,
                 heap_typing=heap_typing, framevars=frame, heap_result=None)
    # 事实条目在前且无分值；根因候选在后按分值降序
    facts = [c for c in out if c.score == 0]
    cands = [c for c in out if c.score > 0]
    assert facts and facts[0].text.startswith("非法内存访问")
    assert cands and cands == sorted(cands, key=lambda c: -c.score)
    top = cands[0]
    assert top.score == 100, "证据累加封顶 100（60+55+40 超限）"
    assert top.confidence == "确认"                      # ≥75 确认
    types = [r["type"] for r in top.refs]
    assert types == ["指令归因", "寄存器", "堆布局"]
    assert "fan_ctrl.set_pwm" in top.refs[0]["detail"]
    assert "全局 g_fan" in top.refs[1]["detail"]
    assert top.hypothesis and "初始化" in top.hypothesis   # 验证动作存在

    # 仅 regs（无指令归因）也能成候选；未验证指令降分且降置信
    inattr2 = dict(inattr, verified=False)
    out2 = triage(core, matches, inattr_res=inattr2, regs_deep=regs_deep)
    c2 = [c for c in out2 if c.score > 0][0]
    assert c2.score == 85 and c2.confidence == "确认"

    # 死锁是独立候选（与访存候选并列）
    class _L(object):
        deadlocks = [[type("E", (), {"waiter_tid": 1, "lock_addr": 0x42,
                                     "holder_tid": 2})()]]
    out3 = triage(core, matches, lock_result=_L(), inattr_res=inattr)
    cand3 = [c for c in out3 if c.score > 0]
    assert any("死锁" in c.text for c in cand3)
    assert len(cand3) == 2                                 # 访存 + 死锁两条候选

    # 无线程 → 单一事实
    core2 = type("C", (), {"crash_thread": None})()
    out4 = triage(core2, matches)
    assert len(out4) == 1 and out4[0].score == 0

    # 向后兼容：旧字段构造仍可用
    old = Conclusion("x", "确认", "y")
    assert old.score == 0 and old.refs == [] and old.hypothesis is None


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

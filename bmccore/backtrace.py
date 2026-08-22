# -*- coding: utf-8 -*-
"""技能1：GDB 精确回溯（-batch 驱动 + 输出解析 + ?? 检测）。

?? 检测是触发栈扫描兜底的依据。
"""
import re

from . import toolchain as tc

_THREAD_HEAD = re.compile(r"^Thread (\d+) \(LWP (\d+)\):")
_FRAME = re.compile(r"^#(\d+)\s+(?:0x([0-9a-f]+) in )?(.+)$")
_FUNC_AT = re.compile(r"^(.*?)\s*\([^)]*\)\s+at\s+(.+?):(\d+)$")


class Frame(object):
    def __init__(self, level, addr, func, loc):
        self.level = level
        self.addr = addr          # int 或 None
        self.func = func          # 原始函数串（可能含参数）
        self.loc = loc            # "file:line" 或 None

    @property
    def is_unknown(self):
        return "??" in self.func or (not self.func.strip())

    def __repr__(self):
        return "#%d 0x%x %s @ %s" % (self.level, self.addr or 0, self.func, self.loc)


class ThreadTrace(object):
    def __init__(self, thread_no, lwp):
        self.thread_no = thread_no
        self.lwp = lwp
        self.frames = []

    @property
    def unknown_count(self):
        return sum(1 for f in self.frames if f.is_unknown)

    @property
    def suspicious(self):
        """帧数异常少或含大量 ??，需要触发栈扫描兜底。"""
        if not self.frames:
            return True
        return self.unknown_count > 0 or len(self.frames) < 2


def parse_bt_output(text):
    """解析 `thread apply all bt` 输出。"""
    traces = []
    cur = None
    for line in text.splitlines():
        line = line.rstrip()
        m = _THREAD_HEAD.match(line)
        if m:
            cur = ThreadTrace(int(m.group(1)), int(m.group(2)))
            traces.append(cur)
            continue
        m = _FRAME.match(line)
        if m and cur is not None:
            level = int(m.group(1))
            addr = int(m.group(2), 16) if m.group(2) else None
            rest = m.group(3)
            func, loc = rest, None
            ma = _FUNC_AT.match(rest)
            if ma:
                func, loc = ma.group(1), "%s:%s" % (ma.group(2), ma.group(3))
            else:
                func = rest.split(" in ")[-1] if " in " in rest else rest
            cur.frames.append(Frame(level, addr, func.strip(), loc))
    return traces


def run_backtrace(gdb_path, core_path, symbol_script, max_frames=50):
    """跑 gdb 回溯；返回 (ok, traces, raw_output)。"""
    script = list(symbol_script) + [
        "core %s" % core_path,
        "echo \\n=====BT=====\\n",
        "thread apply all bt %d" % max_frames,
    ]
    ok, out = tc.gdb_batch(gdb_path, script, timeout=240)
    if "=====BT=====" in out:
        bt_part = out.split("=====BT=====", 1)[1]
        traces = parse_bt_output(bt_part)
        return ok and bool(traces), traces, out
    return False, [], out

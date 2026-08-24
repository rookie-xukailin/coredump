# -*- coding: utf-8 -*-
"""线程锁关联分析：从 core 内存检测死锁/持锁等待链。

原理：glibc 的 pthread_mutex_t 在内存中有固定布局——
  - 正常状态: __lock=0（未锁）或 线程 ID（已锁）
  - 死锁状态: 多个线程的栈上有 futex_wait，各自等对方的锁

通过扫描所有线程栈上的 futex_wait 调用 + 全内存搜索 mutex 结构，
自动构建"谁持锁→谁等锁"的等待图，检测环路（死锁）。
"""
import struct


# glibc pthread_mutex_t 布局（64位，偏移字节）
# struct __pthread_mutex_s {
#   int __lock;          +0   0=未锁 / TID=已锁 / 2=等待者
#   unsigned int __count; +4
#   int __owner;          +8  持锁线程 TID
#   unsigned int __nusers;+12
#   int __kind;           +16 0=normal 1=errorcheck 2=recursive...
#   short __spins;        +20
#   short __elision;      +22
#   __pthread_list_t __list; +24
# }
_MUTEX_LOCK_OFF = 0
_MUTEX_OWNER_OFF = 8
_MUTEX_SIZE = 48          # 64 位 sizeof(pthread_mutex_t)
_MUTEX_SIZE_32 = 24       # 32 位

# futex 相关的栈帧特征（glibc futex_wait 的返回地址在 libc 的特定区域）
_FUTEX_SYSCALL_NUM = {
    64: 202,   # x86_64
    32: 240,   # i386 (但 ARM/RISC-V 不同)
    "arm64": 98,    # SYS_futex
    "arm32": 240,
    "riscv64": 98,
}


class LockInfo(object):
    """一个被检测到的锁。"""
    __slots__ = ("addr", "owner_tid", "lock_state", "kind")

    def __init__(self, addr, owner_tid, lock_state, kind):
        self.addr = addr
        self.owner_tid = owner_tid
        self.lock_state = lock_state
        self.kind = kind

    def __repr__(self):
        return "<Lock 0x%x owner=%d state=%d kind=%d>" % (
            self.addr, self.owner_tid, self.lock_state, self.kind)


class WaitEdge(object):
    """线程 A 在等线程 B 持有的锁。"""
    __slots__ = ("waiter_tid", "lock_addr", "holder_tid")

    def __init__(self, waiter_tid, lock_addr, holder_tid):
        self.waiter_tid = waiter_tid
        self.lock_addr = lock_addr
        self.holder_tid = holder_tid

    def __repr__(self):
        return "T%d --[lock 0x%x]--> T%d" % (
            self.waiter_tid, self.lock_addr, self.holder_tid)


class LockAnalysis(object):
    """锁分析结果。"""
    def __init__(self):
        self.locks = []           # 所有检测到的活跃锁
        self.wait_graph = []      # WaitEdge 列表
        self.deadlocks = []       # 检测到的死锁环
        self.notes = []

    @property
    def has_deadlock(self):
        return bool(self.deadlocks)


def find_mutexes(core, threads, progress=None, full_scan=False):
    """在 core 内存中扫描 pthread_mutex_t 结构。

    快速通道（默认）：mutex 的 __owner 字段必然是某已知线程的 TID——
    用各 TID 的小端字节模式做 C 级正则搜索（re.finditer），命中处 -8
    即 mutex 候选，再校验 __lock 非 0。复杂度与内存大小几乎无关，
    GB 级 core 也是秒级。

    全量通道（full_scan=True，bmccore.toml 的 lock_scan_full）：
    逐 8 字节盲扫全部可写内存，可发现 owner 未知/为 0 的锁，但大 core
    下为 O(内存) 的纯 Python 循环（用户实测可静默数十分钟），默认关闭。
    """
    import re

    mutex_size = _MUTEX_SIZE if core.elfclass == 64 else _MUTEX_SIZE_32
    known_tids = set(t.tid for t in threads)
    locks = []
    seen = set()
    regions = [r for r in core.regions if r.readable and r.write_bit]

    patterns = [(tid, re.compile(struct.pack("<I", tid)))
                for tid in sorted(known_tids)]

    for ri, r in enumerate(regions, 1):
        data = r.data
        if progress:
            progress("[锁] 扫描可写内存找锁：区域 %d/%d（0x%x，%.1fMB）"
                     % (ri, len(regions), r.vaddr, len(data) / 1048576.0))
        # 快速通道：已知 TID 字节模式 C 级搜索
        for tid, pat in patterns:
            for m in pat.finditer(data):
                owner_off = m.start()
                if owner_off % 8 != 0:
                    continue
                off = owner_off - 8           # owner 在 mutex+8
                if off < 0:
                    continue
                lock_val = struct.unpack_from("<I", data, off)[0]
                if lock_val == 0:
                    continue
                addr = r.vaddr + off
                if addr in seen:
                    continue
                seen.add(addr)
                kind = struct.unpack_from("<I", data, off + 16)[0]
                locks.append(LockInfo(addr, tid, lock_val, kind))

    if full_scan:
        # 全量通道：owner 未知/为 0 的锁（O(内存)，默认不开）
        for ri, r in enumerate(regions, 1):
            data = r.data
            n4 = len(data) // 4
            if n4 < 6:
                continue
            words = memoryview(data)[: n4 * 4].cast("I")
            for i in range(0, n4 - 4, 2):
                lock_val = words[i]
                if lock_val == 0:
                    continue
                owner = words[i + 2]
                if owner != 0 and owner in known_tids:
                    continue        # 快速通道已覆盖
                if owner != 0:
                    kind = words[i + 4]
                    if kind > 5:
                        continue
                addr = r.vaddr + i * 4
                if addr in seen:
                    continue
                seen.add(addr)
                locks.append(LockInfo(addr, owner, lock_val, words[i + 4]))

    return locks


def build_wait_graph(core, threads, locks):
    """构建线程等待图：谁在 futex_wait 等谁的锁。

    方法：扫描每个线程的栈，找 futex 相关帧；
    结合已发现的 mutex 列表构建边。
    """
    edges = []
    lock_by_addr = {l.addr: l for l in locks}

    for t in threads:
        # 方法 1：检查线程 PC 是否在 futex_wait 系统调用区域
        # （libc 的 futex_wait / __lll_lock_wait）
        r = core.region_of(t.pc)
        if r and r.readable:
            # 检查线程是否在等待（PC 在 libc 的锁等待区域）
            # 启发式：如果线程 PC 在 libc 内且不是崩溃线程，检查栈上的锁参数
            pass

        # 方法 2：扫描线程栈上的 mutex 指针
        # 线程调用 pthread_mutex_lock(m) 时，m 的地址在栈或寄存器上
        sp = t.sp
        stack_region = core.region_of(sp)
        if stack_region is None:
            continue
        word = 8 if core.elfclass == 64 else 4
        fmt = "<Q" if word == 8 else "<I"

        stack_data = stack_region.data
        sp_off = sp - stack_region.vaddr
        # 扫描栈上 256 个字，找指向 mutex 的指针
        for i in range(min(256 * word, len(stack_data) - sp_off - word)):
            try:
                val = struct.unpack_from(fmt, stack_data, sp_off + i)[0]
                if val in lock_by_addr:
                    lock = lock_by_addr[val]
                    if lock.owner_tid != 0 and lock.owner_tid != t.tid:
                        edges.append(WaitEdge(t.tid, lock.addr, lock.owner_tid))
                        break    # 每线程只取第一个
            except struct.error:
                break

    return edges


def detect_deadlock(edges):
    """在等待图中检测环路（死锁）。"""
    if not edges:
        return []

    # 构建邻接表
    graph = {}
    for e in edges:
        graph.setdefault(e.waiter_tid, []).append(e.holder_tid)

    # DFS 找环
    cycles = []
    visited = set()
    path = []

    def dfs(node, start):
        if node in visited:
            return
        visited.add(node)
        path.append(node)
        for neighbor in graph.get(node, []):
            if neighbor == start and len(path) > 1:
                # 找到环
                cycle = list(path)
                cycles.append(cycle)
            elif neighbor not in path:
                dfs(neighbor, start)
        path.pop()

    for node in graph:
        visited.discard(node)
        path.clear()
        dfs(node, node)

    return cycles


def analyze_locks(core, threads, progress=None, full_scan=False):
    """锁分析主入口。返回 LockAnalysis。"""
    result = LockAnalysis()

    # 1. 扫描活跃 mutex
    result.locks = find_mutexes(core, threads, progress=progress,
                                full_scan=full_scan)
    if not full_scan:
        result.notes.append("锁扫描模式：已知线程 owner 匹配（快速）；"
                            "owner 未知的全内存盲扫未启用"
                            "（bmccore.toml 设 lock_scan_full=true 开启，大 core 耗时高）")
    if result.locks:
        result.notes.append("检测到 %d 个活跃锁" % len(result.locks))
        for l in result.locks[:10]:
            result.notes.append("  锁 0x%x: owner=TID %d, state=%d, kind=%d"
                                % (l.addr, l.owner_tid, l.lock_state, l.kind))

    # 2. 构建等待图
    result.wait_graph = build_wait_graph(core, threads, result.locks)
    if result.wait_graph:
        result.notes.append("等待关系 %d 条" % len(result.wait_graph))
        for e in result.wait_graph[:10]:
            result.notes.append("  %r" % e)

    # 3. 检测死锁
    result.deadlocks = detect_deadlock(result.wait_graph)
    if result.deadlocks:
        for cycle in result.deadlocks:
            result.notes.append(
                "⚠ 死锁检测：线程 %s 形成等待环！" %
                " → ".join("T%d" % tid for tid in cycle))

    return result

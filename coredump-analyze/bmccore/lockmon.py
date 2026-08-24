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


def find_mutexes(core, threads):
    """在 core 全内存中扫描 pthread_mutex_t 结构。

    启发式：一个 48 字节区域，__lock 非 0 且 __owner 是已知线程 TID
    或 __kind 在合法范围（0-5），且后续字段看起来合理。
    """
    word = 8 if core.elfclass == 64 else 4
    fmt = "<Q" if word == 8 else "<I"
    mutex_size = _MUTEX_SIZE if core.elfclass == 64 else _MUTEX_SIZE_32

    known_tids = set(t.tid for t in threads)
    locks = []

    for r in core.regions:
        if not r.readable or not r.write_bit:
            continue
        data = r.data
        for off in range(0, len(data) - mutex_size, 8):
            try:
                lock_val = struct.unpack_from("<i", data, off + _MUTEX_LOCK_OFF)[0]
                if lock_val == 0:
                    continue
                owner = struct.unpack_from("<i", data, off + _MUTEX_OWNER_OFF)[0]
                # 启发式判定
                if owner == 0 and lock_val == 0:
                    continue
                # owner 必须是已知线程（或看起来像 TID）
                if owner not in known_tids and owner != 0:
                    # 检查 kind 字段是否合法
                    kind = struct.unpack_from("<i", data, off + 16)[0]
                    if kind < 0 or kind > 5:
                        continue
                addr = r.vaddr + off
                # 避免重复
                if any(l.addr == addr for l in locks):
                    continue
                kind = struct.unpack_from("<i", data, off + 16)[0]
                locks.append(LockInfo(addr, owner, lock_val, kind))
            except (struct.error, IndexError):
                continue

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


def analyze_locks(core, threads):
    """锁分析主入口。返回 LockAnalysis。"""
    result = LockAnalysis()

    # 1. 扫描活跃 mutex
    result.locks = find_mutexes(core, threads)
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

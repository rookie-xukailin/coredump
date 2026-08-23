# -*- coding: utf-8 -*-
"""Minidump（Google Breakpad）格式解析。

Breakpad minidump 是跨平台崩溃转储格式（Chrome/Firefox/Steam 用），
体积远小于 ELF core（KB vs MB），适合嵌入式设备上传。

支持的最小流集合：
  - MD_THREAD_LIST_STREAM：线程列表（TID + 寄存器位置）
  - MD_MEMORY_LIST_STREAM：内存区域
  - MD_MODULE_LIST_STREAM：已加载模块（路径 + build-id）
  - MD_EXCEPTION_STREAM：崩溃信息（信号/出错地址）
  - MD_SYSTEM_INFO_STREAM：CPU 架构
"""
import struct

# Minidump 流类型
MD_THREAD_LIST_STREAM = 3
MD_MODULE_LIST_STREAM = 4
MD_EXCEPTION_STREAM = 6
MD_SYSTEM_INFO_STREAM = 7
MD_MEMORY_LIST_STREAM = 5
MD_MEMORY_64_LIST_STREAM = 9

# 架构编号
MD_CPU_X86 = 0
MD_CPU_AMD64 = 4
MD_CPU_ARM = 5
MD_CPU_ARM64 = 12
MD_CPU_RISCV = 0x8000 + 243    # 自定义（无官方编号）

# 异常信号（Linux）
EXC_SIGNAL = 0


class MinidumpThread(object):
    def __init__(self, tid, stack_start, stack_size, regs_location, regs_size):
        self.tid = tid
        self.stack_start = stack_start
        self.stack_size = stack_size
        self.regs_location = regs_location    # 文件内偏移
        self.regs_size = regs_size
        self.regs = {}


class MinidumpModule(object):
    def __init__(self, base, size, path, build_id=None):
        self.base = base
        self.size = size
        self.path = path
        self.build_id = build_id


class MinidumpException(object):
    def __init__(self, tid, signal_code, fault_addr):
        self.tid = tid
        self.signal_code = signal_code
        self.fault_addr = fault_addr


class MinidumpMemory(object):
    def __init__(self, start, size, file_offset):
        self.start = start
        self.size = size
        self.file_offset = file_offset


class MinidumpFile(object):
    """解析后的 Minidump 文件。"""
    def __init__(self, path):
        self.path = path
        self.threads = []
        self.modules = []
        self.exception = None
        self.memory_regions = []
        self.arch_name = None
        self._parse(path)

    def _parse(self, path):
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 32 or data[:4] != b"MDMP":
            raise ValueError("%s 不是 Minidump 文件" % path)

        # 头部
        num_streams, stream_dir_rva = struct.unpack_from("<II", data, 8)

        # 读流目录
        streams = {}
        for i in range(num_streams):
            off = stream_dir_rva + i * 12
            if off + 12 > len(data):
                break
            stype, sz, rva = struct.unpack_from("<III", data, off)
            streams.setdefault(stype, []).append((sz, rva))

        # 系统信息（架构）
        if MD_SYSTEM_INFO_STREAM in streams:
            _, rva = streams[MD_SYSTEM_INFO_STREAM][0]
            if rva + 4 <= len(data):
                cpu_arch = struct.unpack_from("<H", data, rva)[0]
                self.arch_name = {
                    MD_CPU_X86: "i386",
                    MD_CPU_AMD64: "x86_64",
                    MD_CPU_ARM: "arm32",
                    MD_CPU_ARM64: "arm64",
                }.get(cpu_arch, "unknown(cpu=%d)" % cpu_arch)

        # 异常信息
        if MD_EXCEPTION_STREAM in streams:
            _, rva = streams[MD_EXCEPTION_STREAM][0]
            if rva + 24 <= len(data):
                tid, _align = struct.unpack_from("<II", data, rva)
                exc_code = struct.unpack_from("<I", data, rva + 8)[0]
                fault = struct.unpack_from("<Q", data, rva + 24)[0]
                self.exception = MinidumpException(tid, exc_code, fault)

        # 线程列表
        if MD_THREAD_LIST_STREAM in streams:
            _, rva = streams[MD_THREAD_LIST_STREAM][0]
            if rva + 4 <= len(data):
                count = struct.unpack_from("<I", data, rva)[0]
                off = rva + 4
                for _ in range(min(count, 256)):
                    if off + 48 > len(data):
                        break
                    tid, _suspend, _prio, _teb, stack_start, stack_size, \
                        stack_rva, _stack_sz, regs_rva, regs_cnt = \
                        struct.unpack_from("<IIIIIIIIII", data, off)
                    t = MinidumpThread(tid, stack_start, stack_size,
                                       regs_rva, regs_cnt * 4)
                    # 读寄存器（按架构布局不同，这里简化为 raw）
                    if regs_rva and regs_rva + regs_cnt * 4 <= len(data):
                        raw = struct.unpack_from(
                            "<%dI" % regs_cnt, data, regs_rva)
                        t.regs = dict(enumerate(raw))
                    self.threads.append(t)
                    off += 48

        # 模块列表
        if MD_MODULE_LIST_STREAM in streams:
            _, rva = streams[MD_MODULE_LIST_STREAM][0]
            if rva + 4 <= len(data):
                count = struct.unpack_from("<I", data, rva)[0]
                off = rva + 4
                for _ in range(min(count, 256)):
                    if off + 108 > len(data):
                        break
                    base, size = struct.unpack_from("<QQ", data, off)
                    # CV 记录（build-id）
                    cv_rva, cv_size = struct.unpack_from("<II", data, off + 80)
                    build_id = None
                    if cv_rva and cv_rva + 16 <= len(data):
                        # PDB70 格式: signature + guid + age + pdb_path
                        sig = data[cv_rva:cv_rva + 4]
                        if sig in (b"RSDS", b"NB10"):
                            guid = data[cv_rva + 4:cv_rva + 20]
                            build_id = guid.hex()
                    # 模块名（UTF-16LE）
                    name_rva = struct.unpack_from("<I", data, off + 96)[0]
                    path = ""
                    if name_rva and name_rva + 4 <= len(data):
                        name_len = struct.unpack_from("<I", data, name_rva)[0]
                        if name_rva + 4 + name_len <= len(data):
                            path = data[name_rva + 4:name_rva + 4 + name_len] \
                                .decode("utf-16-le", "replace")
                    self.modules.append(MinidumpModule(base, size, path, build_id))
                    off += 108

        # 内存列表
        if MD_MEMORY_LIST_STREAM in streams:
            _, rva = streams[MD_MEMORY_LIST_STREAM][0]
            if rva + 4 <= len(data):
                count = struct.unpack_from("<I", data, rva)[0]
                off = rva + 4
                for _ in range(min(count, 1024)):
                    if off + 16 > len(data):
                        break
                    start = struct.unpack_from("<Q", data, off)[0]
                    sz = struct.unpack_from("<I", data, off + 8)[0]
                    mem_rva = struct.unpack_from("<I", data, off + 12)[0]
                    self.memory_regions.append(
                        MinidumpMemory(start, sz, mem_rva))
                    off += 16

    def read_mem(self, addr, size):
        """读 minidump 中的内存。"""
        with open(self.path, "rb") as f:
            for m in self.memory_regions:
                if m.start <= addr and addr + size <= m.start + m.size:
                    f.seek(m.file_offset + (addr - m.start))
                    return f.read(size)
        return None

    def summary(self):
        """返回概览 dict（与 CoreFile.summary() 对齐）。"""
        exc = self.exception
        return {
            "path": self.path,
            "arch": self.arch_name,
            "elfclass": 64 if self.arch_name in ("x86_64", "arm64", "riscv64") else 32,
            "signal": exc.signal_code if exc else None,
            "fault_addr": exc.fault_addr if exc else None,
            "nthreads": len(self.threads),
            "nmodules": len(self.modules),
            "format": "minidump",
        }

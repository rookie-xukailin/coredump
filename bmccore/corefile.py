# -*- coding: utf-8 -*-
"""core 文件（ELF ET_CORE）解析：架构识别、note 段、线程、内存读取。

不使用 pyelftools 对 NT_PRSTATUS 的自动解析（其寄存器命名只覆盖 x86 系），
note 段由本模块自行迭代与解码，ARM32/ARM64/RISC-V 的寄存器布局来自 arch.py。
pyelftools 仅用于 ELF 头/程序头/段数据访问。
"""
import struct

from elftools.elf.elffile import ELFFile

from .arch import arch_for

# note 类型常量
NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRPSINFO = 3
NT_TASKSTRUCT = 4
NT_AUXV = 6
NT_SIGINFO = 0x53494749        # "SIGI"
NT_FILE = 0x46494c45           # "FILE"

# 内核 fs/binfmt_elf.c 的 elf_prstatus 布局：
#   elf_siginfo(3*int) + short cursig + pad + ulong sigpend + ulong sighold
#   + 4*pid(int) + 4*timeval(2*long) + gregset + int fpvalid
# 寄存器区偏移：64位=112，32位=72（timeval 按 2*long 对齐推导，与 GDB 源码一致）。
_PRSTATUS_REGS_OFF = {64: 112, 32: 72}


class Thread(object):
    """一个线程（一个 NT_PRSTATUS note）。"""

    def __init__(self, index, tid, ppid, regs, cursig, siginfo):
        self.index = index            # core 中出现顺序，0 号为崩溃线程
        self.tid = tid
        self.ppid = ppid
        self.regs = regs              # dict: 寄存器名 -> int
        self.cursig = cursig          # 收到的信号
        self.siginfo = siginfo        # dict 或 None: signo/code/errno/addr
        self.is_crash = (index == 0)

    @property
    def pc(self):
        return self.regs.get("pc", 0)

    @property
    def sp(self):
        return self.regs.get("sp", 0)

    @property
    def lr(self):
        for n in ("lr", "x30", "ra"):
            if n in self.regs:
                return self.regs[n]
        return 0

    def __repr__(self):
        return "<Thread %d tid=%d sig=%d pc=0x%x sp=0x%x>" % (
            self.index, self.tid, self.cursig, self.pc, self.sp)


class FileMapping(object):
    """NT_FILE 中一条文件映射。"""

    def __init__(self, start, end, fofs, path):
        self.start = start            # 映射起始 vaddr
        self.end = end                # 映射结束 vaddr（开区间）
        self.fofs = fofs              # 文件内偏移（字节）
        self.path = path              # 设备上的绝对路径

    @property
    def name(self):
        return self.path.rsplit("/", 1)[-1] if self.path else ""

    def contains(self, addr):
        return self.start <= addr < self.end

    def __repr__(self):
        return "<FileMap %s 0x%x-0x%x +0x%x>" % (self.path, self.start, self.end, self.fofs)


class LoadRegion(object):
    """core 的一个 PT_LOAD：一段被转储下来的内存。"""

    def __init__(self, vaddr, filesz, memsz, flags, data):
        self.vaddr = vaddr
        self.filesz = filesz          # 实际转储字节数（memsz>filesz 的尾部是空洞）
        self.memsz = memsz
        self.flags = flags            # PF_R=4 PF_W=2 PF_X=1
        self.data = data              # bytes，长度 filesz

    @property
    def readable(self):
        return self.filesz > 0

    @property
    def exec_bit(self):
        return bool(self.flags & 1)

    @property
    def write_bit(self):
        return bool(self.flags & 2)

    def contains(self, addr, require_data=True):
        end = self.filesz if require_data else self.memsz
        return self.vaddr <= addr < self.vaddr + end

    def __repr__(self):
        return "<LoadRegion 0x%x-0x%x fl=%d>" % (self.vaddr, self.vaddr + self.filesz, self.flags)


def _iter_notes(elffile):
    """遍历所有 PT_NOTE 段里的 note：(name, ntype, desc_bytes)。

    自行解析而非用 pyelftools 的 iter_notes，避免其对非 x86 架构
    PRSTATUS 的寄存器解码失败。
    """
    endian = "<" if elffile.little_endian else ">"
    for seg in elffile.iter_segments():
        if seg.header.p_type != "PT_NOTE":
            continue
        buf = seg.data()
        off = 0
        while off + 12 <= len(buf):
            namesz, descsz, ntype = struct.unpack_from(endian + "III", buf, off)
            off += 12
            name = buf[off:off + namesz]
            off += (namesz + 3) & ~3
            desc = buf[off:off + descsz]
            off += (descsz + 3) & ~3
            yield name.rstrip(b"\x00").decode("ascii", "replace"), ntype, desc


class CoreFile(object):
    """解析后的 core 文件。"""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self._elf = ELFFile(f)
            if self._elf.header.e_type != "ET_CORE":
                raise ValueError("%s 不是 core 文件 (e_type=%s)" % (path, self._elf.header.e_type))
            self.elfclass = self._elf.elfclass
            self.little_endian = self._elf.little_endian
            machine = self._elf.header["e_machine"]
            if isinstance(machine, str):
                machine_no = {"EM_ARM": 40, "EM_AARCH64": 183, "EM_RISCV": 243,
                              "EM_386": 3, "EM_X86_64": 62}.get(machine)
            else:
                machine_no = machine
            self.arch = arch_for(machine_no, self.elfclass)
            self._load_regions()
            self._parse_notes()
            self._close_elf()

    # ------------------------------------------------------------------
    def _close_elf(self):
        self._elf.stream.close()

    def _load_regions(self):
        self.regions = []
        for seg in self._elf.iter_segments():
            h = seg.header
            if h.p_type != "PT_LOAD":
                continue
            self.regions.append(LoadRegion(h.p_vaddr, h.p_filesz, h.p_memsz,
                                           h.p_flags, seg.data()))

    # ------------------------------------------------------------------
    def _parse_notes(self):
        self.threads = []
        self.prpsinfo = None
        self.auxv = {}
        self.siginfo = None
        self.file_mappings = []
        endian = "<" if self.little_endian else ">"
        for name, ntype, desc in _iter_notes(self._elf):
            if ntype == NT_PRSTATUS:
                self.threads.append(self._parse_prstatus(desc, endian))
            elif ntype == NT_PRPSINFO:
                self.prpsinfo = self._parse_prpsinfo(desc, endian)
            elif ntype == NT_AUXV:
                self.auxv = self._parse_auxv(desc, endian)
            elif ntype == NT_SIGINFO and self.siginfo is None:
                self.siginfo = self._parse_siginfo(desc, endian)
            elif ntype == NT_FILE:
                self.file_mappings = self._parse_nt_file(desc, endian)

    # ------------------------------------------------------------------
    def _parse_prstatus(self, desc, endian):
        regs_off = _PRSTATUS_REGS_OFF[self.elfclass]
        # siginfo 三字段按无符号读仅作参考，权威信号取 pr_cursig / NT_SIGINFO
        signo, _pad, _code, cursig = struct.unpack_from(endian + "IIIh", desc, 0)
        if self.elfclass == 64:
            pid, ppid = struct.unpack_from(endian + "ii", desc, 32)
        else:
            pid, ppid = struct.unpack_from(endian + "ii", desc, 24)
        regnames = self.arch.regnames
        fmt = "%s%d%s" % (endian, len(regnames), "I" if self.elfclass == 32 else "Q")
        raw = struct.unpack_from(fmt, desc, regs_off)
        regs = dict(zip(regnames, raw))
        sig = {"signo": signo}
        return Thread(len(self.threads), pid, ppid, regs, cursig, sig)

    # ------------------------------------------------------------------
    def _parse_prpsinfo(self, desc, endian):
        """PRPSINFO：fname/psargs 的偏移在内核版本间存在差异，
        先按常见布局尝试，全部失败则启发式扫描（16 字节可打印块 + 80 字节可打印块）。
        """
        info = {"state": "?", "fname": "", "psargs": ""}
        try:
            info["state"] = chr(desc[0])
        except Exception:
            pass

        def printable(b):
            return all(0x20 <= c < 0x7F or c == 0 for c in b) and any(0x20 <= c < 0x7F for c in b)

        # 先启发式扫描（16字节可打印块 + 紧跟80字节可打印块 = fname+psargs），
        # 不中再退回常见内核固定布局（uid 字段个数随内核版本有差异）。
        for off in range(0, max(len(desc) - 95, 0), 4):
            if printable(desc[off:off + 16]) and printable(desc[off + 16:off + 96]):
                cand_fname = desc[off:off + 16].rstrip(b"\x00").decode("ascii", "replace")
                cand_psargs = desc[off + 16:off + 96].rstrip(b"\x00").decode("ascii", "replace")
                if len(cand_fname) >= 3:
                    info["fname"] = cand_fname
                    info["psargs"] = cand_psargs
                    return info
        for fo, po in ([(48, 64), (40, 56)] if self.elfclass == 64
                       else [(32, 48), (40, 56), (28, 44)]):
            try:
                fname = desc[fo:fo + 16]
                psargs = desc[po:po + 80]
                if printable(fname):
                    info["fname"] = fname.rstrip(b"\x00").decode("ascii", "replace")
                    info["psargs"] = psargs.rstrip(b"\x00").decode("ascii", "replace")
                    return info
            except Exception:
                pass
        return info

    # ------------------------------------------------------------------
    def _parse_auxv(self, desc, endian):
        fmtsz = "I" if self.elfclass == 32 else "Q"
        out = {}
        for off in range(0, len(desc) - 2 * struct.calcsize(fmtsz) + 1,
                         2 * struct.calcsize(fmtsz)):
            k, v = struct.unpack_from(endian + fmtsz * 2, desc, off)
            if k == 0:
                break
            out[int(k)] = int(v)
        return out

    # ------------------------------------------------------------------
    def _parse_siginfo(self, desc, endian):
        """siginfo：signo/errno/code 三个 int，其后（64位补齐到8）是联合体。
        SIGSEGV/SIGBUS 的联合体第一个字段就是出错地址。"""
        signo, _errno, code = struct.unpack_from(endian + "iii", desc, 0)
        info = {"signo": signo, "errno": _errno, "code": code, "addr": None}
        if signo in (11, 7, 4, 5, 2):     # SEGV/BUS/ILL/TRAP/FPE
            if self.elfclass == 64:
                info["addr"] = struct.unpack_from(endian + "Q", desc, 16)[0]
            else:
                info["addr"] = struct.unpack_from(endian + "I", desc, 12)[0]
        return info

    # ------------------------------------------------------------------
    def _parse_nt_file(self, desc, endian):
        fmtsz = struct.calcsize(endian + ("I" if self.elfclass == 32 else "Q"))
        f3 = endian + ("III" if self.elfclass == 32 else "QQQ")
        count, page = struct.unpack_from(endian + ("II" if self.elfclass == 32 else "QQ"), desc, 0)
        off = 2 * fmtsz
        triples = []
        for _ in range(count):
            triples.append(struct.unpack_from(f3, desc, off))
            off += 3 * fmtsz
        names = desc[off:].split(b"\x00")
        maps = []
        for (start, end, fofs_pages), name in zip(triples, names):
            path = name.decode("utf-8", "replace") if name else ""
            maps.append(FileMapping(start, end, fofs_pages * page, path))
        return maps

    # ------------------------------------------------------------------
    # 内存访问
    # ------------------------------------------------------------------
    def read_mem(self, addr, size):
        """按地址读 core 中转储的内存；读不到（未转储）返回 None，跨段返回 None。"""
        for r in self.regions:
            if r.vaddr <= addr and addr + size <= r.vaddr + r.filesz:
                start = addr - r.vaddr
                return r.data[start:start + size]
        return None

    def region_of(self, addr):
        """地址落在哪个 PT_LOAD（有数据的）。"""
        for r in self.regions:
            if r.contains(addr):
                return r
        return None

    def exec_regions(self):
        return [r for r in self.regions if r.exec_bit and r.readable]

    def file_mapping_of(self, addr):
        for m in self.file_mappings:
            if m.contains(addr):
                return m
        return None

    def is_code_addr(self, addr):
        r = self.region_of(addr)
        return bool(r and r.exec_bit)

    # ------------------------------------------------------------------
    @property
    def crash_thread(self):
        return self.threads[0] if self.threads else None

    @property
    def exe_path(self):
        """主程序设备路径：优先 auxv AT_PHDR 所在映射；否则取 NT_FILE 首条。"""
        at_phdr = self.auxv.get(3)      # AT_PHDR=3
        if at_phdr:
            for m in self.file_mappings:
                if m.contains(at_phdr) and m.fofs == 0:
                    return m.path
        if self.file_mappings:
            return self.file_mappings[0].path
        if self.prpsinfo and self.prpsinfo.get("psargs"):
            return self.prpsinfo["psargs"].split(" ", 1)[0]
        return ""

    def capability(self):
        """能力探测：core 里到底转储了哪些内存，供技能降级判断。"""
        caps = {
            "regions": len(self.regions),
            "threads": len(self.threads),
            "has_file_mappings": bool(self.file_mappings),
            "has_auxv": bool(self.auxv),
            "anon_rw_bytes": 0,
            "stack_covered": {},
        }
        for t in self.threads:
            caps["stack_covered"][t.tid] = self.region_of(t.sp) is not None
        for r in self.regions:
            fm = None
            for m in self.file_mappings:
                if m.start <= r.vaddr < m.end:
                    fm = m
                    break
            if fm is None and r.write_bit and r.readable:
                caps["anon_rw_bytes"] += r.filesz
        return caps

    def summary(self):
        caps = self.capability()
        return {
            "path": self.path,
            "arch": self.arch.name if self.arch else "unknown",
            "elfclass": self.elfclass,
            "signal": self.threads[0].cursig if self.threads else None,
            "fault_addr": (self.siginfo or {}).get("addr"),
            "exe": self.exe_path,
            "fname": (self.prpsinfo or {}).get("fname", ""),
            "psargs": (self.prpsinfo or {}).get("psargs", ""),
            "nthreads": len(self.threads),
            "nmodules": len(self.file_mappings),
            "capability": caps,
        }

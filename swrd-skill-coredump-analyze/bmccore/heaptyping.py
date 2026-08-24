# -*- coding: utf-8 -*-
"""堆对象结构化解码：受害/嫌疑/引用 chunk 的字段级还原 + 持有链。

heap 技能走查出的 chunk 只是"偏移+大小"；本模块用 dieinfo 的结构体表
（尺寸匹配 + 成员偏移/类型）把 chunk 内容解码成字段表，并回答：
  - 这块内存"是"什么类型的对象
  - 每个字段的运行时值及其语义（指针→全局变量名/其他 chunk/栈位置）
  - 谁持有指向它的指针（searchref 引用点 × 值语义 = 持有链）
"""
from . import dieinfo as dieinfo_mod


def _read_scalar(data, off, size):
    if off + size > len(data):
        return None
    return int.from_bytes(data[off:off + size], "little")


def decode_chunk(core, decoder, artifact_paths, region_start, chunk, max_fields=16):
    """chunk → {"type": "struct X", "fields": [...]}；匹配不到类型返回 None。"""
    r = core.region_of(region_start + chunk.offset)
    if r is None:
        return None
    # chunk 头 16B（64位）/8B（32位）之后是数据
    hdr = 16 if core.elfclass == 64 else 8
    data = r.data[chunk.offset + hdr: chunk.offset + chunk.size]
    if not data:
        return None
    usable = len(data)
    for path in artifact_paths:
        st = dieinfo_mod.struct_by_size(path, usable)
        if st is None:
            st = dieinfo_mod.struct_by_size(path, chunk.size - hdr)
        if st is None:
            continue
        name, members = st
        fields = []
        for off in sorted(members.keys()):
            mname, mtype = members[off]
            if off >= len(data):
                break
            if "char" in (mtype or "") and "[" not in (mtype or ""):
                v = data[off:off + 24].split(b"\x00")[0]
                try:
                    val = '"%s"' % v.decode("utf-8", "replace")
                except Exception:
                    val = repr(v)
                sem = "字符串"
            elif "*" in (mtype or ""):
                pv = _read_scalar(data, off, 8 if core.elfclass == 64 else 4)
                val = "0x%x" % pv if pv is not None else "?"
                sem = decoder.decode(pv) if pv else "0（NULL）"
            elif "long" in (mtype or "") or "int64" in (mtype or ""):
                pv = _read_scalar(data, off, 8)
                val = "0x%x" % pv if pv is not None else "?"
                sem = str(pv) if pv is not None and pv < (1 << 40) else val
            else:
                pv = _read_scalar(data, off, 4)
                val = "0x%x" % pv if pv is not None else "?"
                sem = str(pv) if pv is not None else val
            fields.append({"offset": off, "name": mname, "type": mtype,
                           "value": val, "sem": sem})
            if len(fields) >= max_fields:
                break
        return {"type": name, "size": usable, "fields": fields,
                "evidence": "DIE 尺寸/成员偏移匹配"}
    return None


def holder_chain(core, decoder, heap_result, target_start, target_end, limit=6):
    """指向 [target_start, target_end) 的引用 → 持有链描述列表。

    searchref 给出 (where, addr, value)；where 的语义（哪个全局变量/哪个
    栈帧）就是"谁拿着这个指针"。
    """
    out = []
    for w, a, v in (heap_result.references or []):
        if not (target_start <= v < target_end):
            continue
        where_sem = decoder.decode(a)
        out.append("0x%x(值 0x%x → %s) 持有指向受害区的指针 [%s]"
                   % (a, v, "0x%x" % v, where_sem))
        if len(out) >= limit:
            break
    return out

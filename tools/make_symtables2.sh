#!/usr/bin/env bash
# 重建符号表目录：直接拷贝编译产物（未 strip ELF，含完整 .text + DWARF + build-id）
set -u
W=/tmp/coredump_work
B=$W/build
ST=$W/symtab
rm -rf $ST && mkdir -p $ST

# 主程序（全部案例三架构产物：33 旧维度 + 40 新维度）
for f in $B/*_arm64 $B/*_arm32 $B/*_riscv64; do
    [ -f "$f" ] && cp "$f" "$ST/" && echo "  $(basename $f)"
done

# 共享库
for f in $B/libsensord_*.so $B/libplug.so $B/libsqlite3_*.so $B/liblmdb_*.so; do
    [ -f "$f" ] && cp "$f" "$ST/" && echo "  $(basename $f)"
done

# libc/ld（三架构）
for pair in "libc_a64.elf /usr/aarch64-linux-gnu/lib/libc.so.6" \
            "ld_a64.elf /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1" \
            "libc_a32.elf /usr/arm-linux-gnueabihf/lib/libc.so.6" \
            "ld_a32.elf /usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3" \
            "libc_rv64.elf /usr/riscv64-linux-gnu/lib/libc.so.6" \
            "ld_rv64.elf /usr/riscv64-linux-gnu/lib/ld-linux-riscv64-lp64d.so.1"; do
    set -- $pair
    cp "$2" "$ST/$1" && echo "  $1"
done

echo "===== 符号表文件数: $(ls $ST | wc -l) ====="

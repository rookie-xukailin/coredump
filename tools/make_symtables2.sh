#!/usr/bin/env bash
# 重建符号表目录：直接拷贝编译产物（未 strip ELF，含完整 .text + DWARF + build-id）
set -u
W=/tmp/coredump_work
B=$W/build
ST=$W/symtab
rm -rf $ST && mkdir -p $ST

# 主程序
for f in $B/null_write_* $B/wild_mmio_* $B/stack_overflow_* $B/heap_overflow_* \
         $B/double_free_* $B/uaf_write_* $B/oob_read_* $B/bad_funcptr_* \
         $B/stack_smash_* $B/assert_fail_* $B/thread_crash_* $B/shlib_crash_* \
         $B/ill_jump_* $B/null_poison_* $B/uaf_reuse_* $B/deep_chain_* \
         $B/hugespan_* $B/dlopen_crash_* $B/handler_crash_* $B/blame_thread_* \
         $B/stomped_late_* $B/db_reload_race_* $B/rec_delete_race_* \
         $B/shm_truncate_bus_* $B/db_index_corrupt_* $B/dblfree_concurrent_* \
         $B/db_compact_race_* $B/sqlite_close_race_* $B/sqlite_corrupt_bus_* \
         $B/sqlite_finalize_uaf_* $B/lmdb_close_race_* $B/lmdb_truncate_bus_* \
         $B/dlclose_race_*; do
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

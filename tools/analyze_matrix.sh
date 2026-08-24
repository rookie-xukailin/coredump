#!/usr/bin/env bash
# 全矩阵分析：60 格逐个 bmccore analyze，日志落到 logs/matrix/<tag>.analyze.log
set -u
W=/tmp/coredump_work
PROJ=$W/proj
CORES=$W/cores
LOGS=$W/logs
OUT=$W/reports
mkdir -p $OUT

cp /mnt/d/AI_Workspace/Coredump/work/bmccore_symtab.toml $W/bmccore.toml

CASES="null_write wild_mmio stack_overflow heap_overflow double_free uaf_write oob_read bad_funcptr stack_smash assert_fail thread_crash shlib_crash ill_jump null_poison uaf_reuse deep_chain hugespan dlopen_crash handler_crash blame_thread stomped_late db_reload_race rec_delete_race shm_truncate_bus db_index_corrupt dblfree_concurrent db_compact_race sqlite_close_race sqlite_corrupt_bus sqlite_finalize_uaf lmdb_close_race lmdb_truncate_bus dlclose_race realloc_dangling stack_local_return free_nonheap uninit_stack_ptr off_by_one int_overflow_alloc sprintf_overflow strlen_noterm sizeof_pointer union_confusion signed_unsigned const_rodata_write endianness_cast timer_after_free atexit_stale shutdown_order fd_exhaust malloc_null sigpipe_write fpe_divzero nest_signal no_volatile_hw unaligned_arm dma_alignment eeprom_corrupt config_array_size argv_missing init_order watchdog_stuck thread_hang_kill lock_deadlock_kill ipmi_parse_overflow fru_corrupt_parse sensor_hotplug i2c_timeout_stale dbus_prop_crash power_transition sel_full_error shm_unlink_alive fifo_sigpipe mq_consumer_uaf mq_recv_truncate mq_deser_overflow msgq_rmid_race queue_ring_overrun"
ARCHS="arm64 arm32 riscv64"

for NAME in $CASES; do
    for ARCH in $ARCHS; do
        TAG="$NAME.$ARCH"
        LOG=$LOGS/matrix/$TAG.analyze.log
        # 找 core 文件
        CORE=""
        for f in $CORES/${NAME}_${ARCH}.core $CORES/${NAME}_${ARCH}.core.gz $CORES/1_core-*-${NAME}_${ARCH}-*.tar.gz; do
            [ -f "$f" ] && { CORE="$f"; break; }
        done
        if [ -z "$CORE" ]; then
            echo "[$TAG] NO-CORE" | tee -a $LOGS/matrix/summary.log
            continue
        fi
        ARGS=(analyze "$CORE" -o $OUT/$TAG)
        CLOG=$LOGS/matrix/$TAG.console.log
        [ -f "$CLOG" ] && ARGS+=(--console-log "$CLOG")
        ( cd $CORES && python3 $PROJ/coredump-analyze/bmccore.py "${ARGS[@]}" ) > $LOG 2>&1
        RC=$?
        if [ $RC -ne 0 ]; then
            echo "[$TAG] ANALYZE-RC=$RC" | tee -a $LOGS/matrix/summary.log
        else
            echo "[$TAG] ANALYZE-OK" | tee -a $LOGS/matrix/summary.log
        fi
    done
done
echo "ALL-ANALYZE-DONE" | tee -a $LOGS/matrix/summary.log

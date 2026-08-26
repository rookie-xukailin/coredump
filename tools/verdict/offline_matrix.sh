#!/usr/bin/env bash
# 全量 99 格离线矩阵：--offline 模式分析，报告/日志独立目录
set -u
W=/tmp/coredump_work
PROJ=$W/proj
CORES=$W/cores
LOGS=$W/logs/matrix
mkdir -p $W/reports_offline $LOGS
rm -f $LOGS/summary_offline.log

CASES="null_write wild_mmio stack_overflow heap_overflow double_free uaf_write oob_read bad_funcptr stack_smash assert_fail thread_crash shlib_crash ill_jump null_poison uaf_reuse deep_chain hugespan dlopen_crash handler_crash blame_thread stomped_late db_reload_race rec_delete_race shm_truncate_bus db_index_corrupt dblfree_concurrent db_compact_race sqlite_close_race sqlite_corrupt_bus sqlite_finalize_uaf lmdb_close_race lmdb_truncate_bus dlclose_race"

for NAME in $CASES; do
    for ARCH in arm64 arm32 riscv64; do
        TAG="$NAME.$ARCH"
        CORE=""
        for f in $CORES/${NAME}_${ARCH}.core $CORES/${NAME}_${ARCH}.core.gz $(ls -t $CORES/1_core-*-${NAME}_${ARCH}-*.tar.gz 2>/dev/null | head -1); do
            [ -f "$f" ] && { CORE="$f"; break; }
        done
        if [ -z "$CORE" ]; then
            echo "[$TAG] NO-CORE" | tee -a $LOGS/summary_offline.log
            continue
        fi
        ARGS=(analyze "$CORE" -o $W/reports_offline/$TAG --offline)
        CLOG=$LOGS/$TAG.console.log
        [ -f "$CLOG" ] && ARGS+=(--console-log "$CLOG")
        ( cd $CORES && python3 $PROJ/swrd-skill-coredump-analyze/bmccore.py "${ARGS[@]}" ) > $LOGS/${TAG}.offline.log 2>&1
        RC=$?
        [ $RC -ne 0 ] && echo "[$TAG] ANALYZE-RC=$RC" | tee -a $LOGS/summary_offline.log \
                     || echo "[$TAG] ANALYZE-OK" | tee -a $LOGS/summary_offline.log
    done
done
echo "ALL-OFFLINE-DONE" | tee -a $LOGS/summary_offline.log

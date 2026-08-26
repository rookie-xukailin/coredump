#!/usr/bin/env bash
# 全矩阵生成：20 案例 × 3 架构 = 60 个 core
# 每格：编译 → qemu -g → gcore → riscv prstatus 扩容 → NT_SIGINFO 注入 → 打包 → 产物归档
set -u
W=/tmp/coredump_work
CS=$W/cases
BUILD=$W/build
CORES=$W/cores
ART=$W/artifacts
LOGS=$W/logs
mkdir -p $BUILD $CORES $ART $LOGS $LOGS/matrix

# ---- 架构表 ----
# 编译基线：-g -O1（用户固件真实级别；不加帧指针，回溯依赖 DWARF CFI）
declare -A CC QEMU SYSROOT BASEFLAGS
CC[arm64]=aarch64-linux-gnu-gcc;  QEMU[arm64]=qemu-aarch64-static;  SYSROOT[arm64]=/usr/aarch64-linux-gnu;  BASEFLAGS[arm64]="-g -O1"
CC[arm32]=arm-linux-gnueabihf-gcc; QEMU[arm32]=qemu-arm-static;      SYSROOT[arm32]=/usr/arm-linux-gnueabihf; BASEFLAGS[arm32]="-g -O1 -marm"
CC[riscv64]=riscv64-linux-gnu-gcc; QEMU[riscv64]=qemu-riscv64-static; SYSROOT[riscv64]=/usr/riscv64-linux-gnu; BASEFLAGS[riscv64]="-g -O1"

# ---- 案例表: name|src|signo|code|addrsrc|fmt|cflags_extra|ldflags|console
# addrsrc: log/pc/sp/0   fmt: bare/gz/tar
CASES="
null_write|null_write.c|11|1|log|bare|||
wild_mmio|wild_mmio.c|11|1|log|gz|thumb||1
stack_overflow|stack_overflow.c|11|1|sp|bare|||
heap_overflow|heap_overflow.c|6|-6|0|tar|||1
double_free|double_free.c|6|-6|0|gz|||1
uaf_write|uaf_write.c|11|1|log|bare|||
oob_read|oob_read.c|11|1|log|gz|||
bad_funcptr|bad_funcptr.c|11|1|pc|tar|||1
stack_smash|stack_smash.c|11|1|pc|bare|nsp,nofort||1
assert_fail|assert_fail.c|6|-6|0|bare|||1
thread_crash|thread_crash.c|11|1|log|bare||-pthread|
shlib_crash|@shlib|11|1|log|tar|||1
ill_jump|ill_jump.c|4|2|log|bare|||1
null_poison|null_poison.c|6|-6|0|gz|nofort||1
uaf_reuse|uaf_reuse.c|11|1|log|bare|||1
deep_chain|deep_chain.c|11|1|log|gz|||
hugespan|hugespan.c|11|1|sp|bare|||
dlopen_crash|@dlopen|11|1|log|tar|-ldl|-Wl,-rpath,$BUILD|1
handler_crash|handler_crash.c|11|1|log|bare|||1
blame_thread|blame_thread.c|6|-6|0|tar||-pthread|1
stomped_late|stomped_late.c|11|1|pc|gz|||1
db_reload_race|db_reload_race.c|11|1|log|gz||-pthread|1
rec_delete_race|rec_delete_race.c|11|1|log|bare||-pthread|1
shm_truncate_bus|shm_truncate_bus.c|7|2|log|tar|||1
db_index_corrupt|db_index_corrupt.c|11|1|log|gz|||1
dblfree_concurrent|dblfree_concurrent.c|6|-6|0|tar||-pthread|1
db_compact_race|db_compact_race.c|11|1|log|bare||-pthread|1
sqlite_close_race|sqlite_close_race.c|11|1|none|gz|sqlite|-pthread|1
sqlite_corrupt_bus|sqlite_corrupt_bus.c|7|2|none|tar|sqlite||1
sqlite_finalize_uaf|sqlite_finalize_uaf.c|11|1|none|bare|sqlite|-pthread|1
lmdb_close_race|lmdb_close_race.c|11|1|none|gz|lmdb|-pthread|1
lmdb_truncate_bus|lmdb_truncate_bus.c|7|2|none|tar|lmdb||1
dlclose_race|dlclose_race.c|11|1|log|bare|@dlplug|-pthread|1
# ---- 批次 1：传统 C 语言经典（#34~#54）----
realloc_dangling|realloc_dangling.c|11|1|log|gz|||
stack_local_return|stack_local_return.c|11|1|pc|bare|||
free_nonheap|free_nonheap.c|6|-6|0|bare|||1
uninit_stack_ptr|uninit_stack_ptr.c|11|1|log|gz|||
off_by_one|off_by_one.c|11|2|log|bare|||
int_overflow_alloc|int_overflow_alloc.c|11|1|log|gz|||
sprintf_overflow|sprintf_overflow.c|6|-6|0|bare|||1
strlen_noterm|strlen_noterm.c|11|1|log|gz|||
sizeof_pointer|sizeof_pointer.c|11|1|log|tar|||1
union_confusion|union_confusion.c|11|1|log|bare|||
signed_unsigned|signed_unsigned.c|11|1|log|gz|||
const_rodata_write|const_rodata_write.c|11|2|log|bare|||1
endianness_cast|endianness_cast.c|11|1|log|gz|||
timer_after_free|timer_after_free.c|11|1|log|bare|||1
atexit_stale|atexit_stale.c|11|1|log|gz|||
shutdown_order|shutdown_order.c|11|1|log|tar||-pthread|
fd_exhaust|fd_exhaust.c|11|1|log|gz|||
malloc_null|malloc_null.c|11|1|log|bare|||
sigpipe_write|sigpipe_write.c|13|0|sigpipe|bare|||1
fpe_divzero|fpe_divzero.c|8|1|0|bare|||1
nest_signal|nest_signal.c|11|1|log|gz|||
# ---- 批次 2：硬件/平台/嵌入式特定（#55~#64）----
no_volatile_hw|no_volatile_hw.c|11|1|log|gz|||
unaligned_arm|unaligned_arm.c|7|1|log|bare|||1
dma_alignment|dma_alignment.c|7|1|log|gz|||
eeprom_corrupt|eeprom_corrupt.c|11|1|log|tar|||1
config_array_size|config_array_size.c|11|1|log|gz|||
argv_missing|argv_missing.c|11|1|log|bare|||
init_order|init_order.c|11|1|log|gz|||
watchdog_stuck|watchdog_stuck.c|6|-6|0|tar||-pthread|1
thread_hang_kill|thread_hang_kill.c|6|-6|0|bare||-pthread|1
lock_deadlock_kill|lock_deadlock_kill.c|6|-6|0|gz||-pthread|1
# ---- 批次 3：BMC/OpenBMC 特定（#65~#73）----
ipmi_parse_overflow|ipmi_parse_overflow.c|11|1|log|gz|||
fru_corrupt_parse|fru_corrupt_parse.c|11|1|log|bare|||
sensor_hotplug|sensor_hotplug.c|11|1|log|gz|||
i2c_timeout_stale|i2c_timeout.c|11|1|log|tar|||1
dbus_prop_crash|dbus_prop_crash.c|11|1|log|gz|||
power_transition|power_transition.c|11|1|log|bare|||
sel_full_error|sel_full_error.c|11|1|log|gz|||
shm_unlink_alive|shm_unlink_alive.c|7|2|log|tar|||1
fifo_sigpipe|fifo_sigpipe.c|13|0|sigpipe|gz|||1
# ---- 批次 4：消息队列（#74~#78）----
mq_consumer_uaf|mq_consumer_uaf.c|11|1|log|gz|-pthread||1
mq_recv_truncate|mq_recv_truncate.c|11|1|log|bare|||
mq_deser_overflow|mq_deser_overflow.c|11|2|log|gz|||
msgq_rmid_race|msgq_rmid_race.c|11|1|log|tar|||1
queue_ring_overrun|queue_ring_overrun.c|11|2|log|bare|||
"

ARCHS="arm64 arm32 riscv64"

gen_cell() {  # gen_cell <case-line> <arch>
    local IFS='|'
    read -r NAME SRC SIGNO CODE ADDRSRC FMT FX LX CONSOLE <<< "$1"
    IFS=$' \t\n'   # 恢复默认分词，否则 CFLAGS 会被当成单个参数
    local ARCH=$2
    local TAG="$NAME.$ARCH"
    local BIN=$BUILD/${NAME}_${ARCH}
    local CFLAGS="${BASEFLAGS[$ARCH]}"
    local LDFLAGS="$LX"
    local SRCFILES=$CS/$SRC

    # 附加编译特性（FX 逗号组合）
    for f in ${FX//,/ }; do
        [ "$f" = "thumb" ] && [ "$ARCH" = "arm32" ] && CFLAGS="$CFLAGS -mthumb"
        [ "$f" = "nsp" ] && CFLAGS="$CFLAGS -fno-stack-protector"
        [ "$f" = "nofort" ] && CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0"   # Ubuntu 会在 -U 后重启用，须显式置 0
    done

    # 第三方库（sqlite/lmdb）链接：库文件按架构后缀命名（riscv64→rv64）
    local LIBTAG=$ARCH
    [ "$ARCH" = "riscv64" ] && LIBTAG=rv64
    case "$FX" in
      sqlite)
        CFLAGS="$CFLAGS -I$W/third/sqlite"
        LDFLAGS="$LDFLAGS -L$BUILD -lsqlite3_${LIBTAG} -Wl,-rpath,$BUILD" ;;
      lmdb)
        CFLAGS="$CFLAGS -I$W/third/lmdb"
        LDFLAGS="$LDFLAGS -L$BUILD -llmdb_${LIBTAG} -Wl,-rpath,$BUILD" ;;
    esac

    # 特殊构建器
    local RUNENV=""
    case "$NAME" in
      shlib_crash)
        rm -f $BUILD/libsensord_${ARCH}.so
        ${CC[$ARCH]} $CFLAGS -fPIC -shared -o $BUILD/libsensord_${ARCH}.so $CS/sensord.c -I$CS || return 1
        SRCFILES="$CS/shlib_main.c -I$CS"
        LDFLAGS="$LDFLAGS -L$BUILD -lsensord_${ARCH} -Wl,-rpath,$BUILD"
        cp -f $BUILD/libsensord_${ARCH}.so $ART/ ;;
      dlopen_crash)
        rm -f $BUILD/libplug.so   # 主程序里写死了这个路径
        ${CC[$ARCH]} $CFLAGS -fPIC -shared -o $BUILD/libplug.so $CS/plugin.c || return 1
        SRCFILES="$CS/plug_main.c"
        cp -f $BUILD/libplug.so $ART/libplug_${ARCH}.so ;;
      dlclose_race)
        rm -f $BUILD/libdlplug.so
        ${CC[$ARCH]} -g -O0 -fPIC -shared -o $BUILD/libdlplug.so $CS/libdlplug.c || return 1
        cp -f $BUILD/libdlplug.so $ART/libdlplug_${ARCH}.so ;;
    esac

    if ! ${CC[$ARCH]} $CFLAGS -o $BIN $SRCFILES $LDFLAGS 2>$LOGS/matrix/$TAG.build.log; then
        echo "[$TAG] COMPILE-FAIL"; return 1
    fi
    cp -f $BIN $ART/

    local PORT
    local ATTEMPT
    rm -f /tmp/bmc_*.flag /tmp/bmc_*.bin    # fork 类案例的进程间同步文件
    rm -f $CORES/${NAME}_${ARCH}.core $CORES/${NAME}_${ARCH}.core.gz \
          $CORES/1_core-*-${NAME}_${ARCH}-*.tar.gz   # 清掉旧格, 防止重生成后分析取旧核
    for ATTEMPT in 1 2; do
        PORT=$((21000 + RANDOM % 20000))
        ( export LD_LIBRARY_PATH=$BUILD BMC_QEMU_EPIPE_PROBE=1 ; ${QEMU[$ARCH]} -L ${SYSROOT[$ARCH]} -g $PORT $BIN ) 2>$LOGS/matrix/$TAG.console.log &
        local QPID=$!
        sleep 2
        gdb-multiarch -batch -nx \
          -ex "set pagination off" -ex "set sysroot ${SYSROOT[$ARCH]}" \
          -ex "file $BIN" -ex "target remote :$PORT" \
          -ex "handle SIGPIPE stop nopass" \
          -ex "handle SIG34 nostop noprint pass" \
          -ex "break ipc_sigpipe_default" \
          -ex "continue" \
          -ex "gcore $CORES/${NAME}_${ARCH}.core" \
          -ex "echo \n===REGS===\n" -ex "info registers pc sp" \
          -ex "echo \n===BT===\n" -ex "thread apply all bt 30" \
          > $LOGS/matrix/$TAG.gdb.log 2>&1
        kill $QPID 2>/dev/null; wait $QPID 2>/dev/null
        [ -s $CORES/${NAME}_${ARCH}.core ] && break
        echo "[$TAG] gcore attempt $ATTEMPT failed, retry..."
        rm -f $CORES/${NAME}_${ARCH}.core
        sleep 2
    done

    if [ ! -s $CORES/${NAME}_${ARCH}.core ]; then
        echo "[$TAG] GCORE-FAIL"; return 1
    fi

    # riscv: PRSTATUS 扩容到 376
    [ "$ARCH" = "riscv64" ] && \
      python3 /mnt/d/AI_Workspace/Coredump/work/fix_riscv_prstatus.py $CORES/${NAME}_${ARCH}.core

    # 信号与 si_code 优先取 gdb 停止事件的真实上报（各架构 qemu 翻译层
    # 可能差异，如 riscv 越界文件页报 SEGV 而非 SIGBUS），manifest 仅兜底
    local SIGPAIR=""
    case "$(grep -oE 'received signal SIG[A-Z]+' $LOGS/matrix/$TAG.gdb.log | tail -1 | awk '{print $3}')" in
      SIGSEGV)  SIGPAIR="11 1" ;;
      SIGBUS)   SIGPAIR="7 2" ;;
      SIGABRT)  SIGPAIR="6 -6" ;;
      SIGILL)   SIGPAIR="4 2" ;;
      SIGTRAP)  SIGPAIR="5 1" ;;
      SIGFPE)   SIGPAIR="8 1" ;;
    esac
    if [ -n "$SIGPAIR" ]; then
        SIGNO=${SIGPAIR%% *}
        CODE=${SIGPAIR##* }
    fi

    # 崩溃地址来源
    local ADDR=0
    case $ADDRSRC in
      log)
        FA=$(grep -o 'FAULT_ADDR=0x[0-9a-f]*' $LOGS/matrix/$TAG.console.log | tail -1 | cut -d= -f2)
        if [ -z "$FA" ]; then
            grep -q 'FAULT_ADDR=(nil)' $LOGS/matrix/$TAG.console.log && FA=0x0
        fi
        ADDR=${FA:-0} ;;
      pc)
        ADDR=$(sed -n '/===BT===/,$p' $LOGS/matrix/$TAG.gdb.log | grep -oE '0x0*[0-9a-f]{6,16} in \?\? \(\)' | tail -1 | awk '{print $1}')
        [ -z "$ADDR" ] && ADDR=$(grep -A3 '===REGS===' $LOGS/matrix/$TAG.gdb.log | grep -oE '(^|[[:space:]])(pc|rip)[[:space:]]+0x[0-9a-f]+' | grep -oE '0x[0-9a-f]+' | head -1) ;;
      sp)
        ADDR=$(grep -A3 '===REGS===' $LOGS/matrix/$TAG.gdb.log | grep -oE '(^|[[:space:]])sp[[:space:]]+0x[0-9a-f]+' | grep -oE '0x[0-9a-f]+' | head -1) ;;
    esac

    # addrsrc=none：崩溃在第三方库内部、真实出错地址不可知（qemu 不传 siginfo），
    # 不注入 NT_SIGINFO —— 工具按"无 siginfo"路径如实报告信号
    # addrsrc=sigpipe：qemu stub 不回停 SIGPIPE——在 ipc_sigpipe_default
    # 断点取核后注入 NT_SIGINFO(13) 并修补 pr_cursig，还原信号现场
    if [ "$ADDRSRC" = "sigpipe" ]; then
        SIGNO=13; CODE=0
        python3 /mnt/d/AI_Workspace/Coredump/work/inject_siginfo.py \
            $CORES/${NAME}_${ARCH}.core 13 0 0 13 >/dev/null
    elif [ "$ADDRSRC" != "none" ]; then
        python3 /mnt/d/AI_Workspace/Coredump/work/inject_siginfo.py $CORES/${NAME}_${ARCH}.core $SIGNO $CODE "${ADDR:-0}" >/dev/null
    fi

    # 打包
    case $FMT in
      gz) gzip -c $CORES/${NAME}_${ARCH}.core > $CORES/${NAME}_${ARCH}.core.gz; rm -f $CORES/${NAME}_${ARCH}.core ;;
      tar)
        local STAMP=$((2000000000 + RANDOM % 999999999))
        local PID=$((1000 + RANDOM % 9000))
        rm -rf $W/tarstage; mkdir -p $W/tarstage
        cp $CORES/${NAME}_${ARCH}.core $W/tarstage/core
        tar -czf $CORES/1_core-$STAMP-${NAME}_${ARCH}-$PID.tar.gz -C $W/tarstage core
        rm -rf $W/tarstage $CORES/${NAME}_${ARCH}.core ;;
    esac
    echo "[$TAG] OK"
    return 0
}

N=0; FAIL=0
ARCHS="${ARCHS_OVERRIDE:-$ARCHS}"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    NAME_ONLY="${line%%|*}"
    if [ -n "${CASES_OVERRIDE:-}" ] && ! grep -q "^$NAME_ONLY|" <<< "$CASES_OVERRIDE"; then
        continue
    fi
    for ARCH in $ARCHS; do
        gen_cell "$line" "$ARCH" || FAIL=$((FAIL+1))
        N=$((N+1))
    done
done <<< "$CASES"

echo "===================="
echo "generated $N cells, fail $FAIL"
ls $CORES | wc -l

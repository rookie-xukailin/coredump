#!/usr/bin/env bash
# 清僵尸 qemu + 重采全部 60 格 console 日志（普通 qemu 运行，无需 gdb）
set -u
W=/tmp/coredump_work
pkill -f 'qemu-.*-static -g' 2>/dev/null
sleep 1

CASES="null_write wild_mmio stack_overflow heap_overflow double_free uaf_write oob_read bad_funcptr stack_smash assert_fail thread_crash shlib_crash ill_jump null_poison uaf_reuse deep_chain hugespan dlopen_crash handler_crash blame_thread"
declare -A QEMU SYSROOT
QEMU[arm64]=qemu-aarch64-static;  SYSROOT[arm64]=/usr/aarch64-linux-gnu
QEMU[arm32]=qemu-arm-static;      SYSROOT[arm32]=/usr/arm-linux-gnueabihf
QEMU[riscv64]=qemu-riscv64-static; SYSROOT[riscv64]=/usr/riscv64-linux-gnu

for n in $CASES; do
    for a in arm64 arm32 riscv64; do
        BIN=$W/build/${n}_${a}
        [ -x "$BIN" ] || { echo "no bin $n.$a"; continue; }
        # shlib 需要库路径；dlopen 主程序写死了 build/libplug.so（最后一次构建是哪个架构就取决于顺序，
        # 为保证正确：按架构先重建一次 libplug）
        if [ "$n" = "dlopen_crash" ]; then
            ${QEMU[$a]} >/dev/null 2>&1 || true
            case $a in
              arm64)   gcc=aarch64-linux-gnu-gcc ;;
              arm32)   gcc=arm-linux-gnueabihf-gcc ;;
              riscv64) gcc=riscv64-linux-gnu-gcc ;;
            esac
            $gcc -g -O0 -fPIC -shared -o $W/build/libplug.so $W/cases/plugin.c
        fi
        ( cd $W && LD_LIBRARY_PATH=$W/build timeout 25 ${QEMU[$a]} -L ${SYSROOT[$a]} $BIN ) \
            > /dev/null 2> $W/logs/matrix/$n.$a.console.log
        echo "$n.$a rc=$? : $(head -c 120 $W/logs/matrix/$n.$a.console.log | head -1)"
    done
done
echo DONE

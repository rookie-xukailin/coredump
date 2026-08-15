#!/usr/bin/env bash
# 在 Linux 编译服务器上生成三架构真实 crash core，用于 bmccore 集成验证。
#
# 依赖:
#   - 交叉工具链: ${PFX}gcc 与 ${PFX}gdb（或 gdb-multiarch）
#   - qemu-user: qemu-aarch64-static / qemu-arm-static / qemu-riscv64-static
# 用法:
#   ARM64_PFX=aarch64-linux-gnu- ./tools/gen_real_cases.sh out_dir
#
# 原理: qemu-user -g 起 gdbserver，交叉 gdb 连上后 run 到崩溃，再 gcore
#       导出目标架构的 ELF core（比让 qemu 直接 dump 兼容性好）。

set -euo pipefail

OUT="${1:-real_cases}"
ARM32_PFX="${ARM32_PFX:-arm-linux-gnueabihf-}"
ARM64_PFX="${ARM64_PFX:-aarch64-linux-gnu-}"
RISCV_PFX="${RISCV_PFX:-riscv64-linux-gnu-}"

mkdir -p "$OUT"

cat > "$OUT/crash_null.c" <<'EOF'
#include <stdlib.h>
struct dev { int id; char name[32]; };
static struct dev *g_dev;  /* 故意不初始化 = NULL */
int main(void) { g_dev->id = 42; return 0; }          /* 空指针写 */
EOF

cat > "$OUT/crash_stack.c" <<'EOF'
#include <string.h>
static void rec(int d) { char buf[512]; memset(buf, d & 0xff, sizeof buf);
    if (d > 0) rec(d - 1); }
int main(void) { rec(1 << 20); return 0; }            /* 递归栈溢出 */
EOF

cat > "$OUT/crash_heap.c" <<'EOF'
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *a = malloc(0x100); char *b = malloc(0x100);
    memset(a, 0x41, 0x100 + 32);                      /* 越界写穿下一 chunk 头 */
    free(b);                                          /* 在 free 时暴雷 */
    free(a);
    return 0;
}
EOF

gen_one() {  # gen_one <arch> <prefix> <qemu> <src> <name>
    local pfx="$1" qemu="$2" src="$3" name="$4"
    local gdb="${pfx}gdb"; command -v "$gdb" >/dev/null 2>&1 || gdb=gdb-multiarch
    command -v "$gdb" >/dev/null || { echo "!! 缺 $gdb / gdb-multiarch，跳过 $name"; return 0; }
    command -v "$qemu" >/dev/null || { echo "!! 缺 $qemu，跳过 $name"; return 0; }

    "${pfx}gcc" -g -O0 -o "$OUT/${name}.bin" "$src"
    local port; port=$((20000 + RANDOM % 20000))
    "$qemu" -g "$port" "$OUT/${name}.bin" &
    local qpid=$!
    sleep 1
    "$gdb" -batch -nx \
        -ex "set architecture auto" \
        -ex "file $OUT/${name}.bin" \
        -ex "target remote :$port" \
        -ex "run" \
        -ex "gcore $OUT/${name}.core" \
        >/dev/null 2>&1 || true
    kill $qpid 2>/dev/null || true
    if [ -s "$OUT/${name}.core" ]; then
        gzip -c "$OUT/${name}.core" > "$OUT/${name}.core.gz"
        rm -f "$OUT/${name}.core"
        echo "OK  $OUT/${name}.core.gz"
    else
        echo "!! $name core 生成失败（检查 qemu/-g 与 gdb 版本）"
    fi
}

for src_name in crash_null crash_stack crash_heap; do
    gen_one "$ARM64_PFX" qemu-aarch64-static    "$OUT/${src_name}.c" "${src_name}_arm64"
    gen_one "$ARM32_PFX" qemu-arm-static        "$OUT/${src_name}.c" "${src_name}_arm32"
    gen_one "$RISCV_PFX" qemu-riscv64-static    "$OUT/${src_name}.c" "${src_name}_riscv64"
done

echo
echo "生成完毕。验证示例："
echo "  python3 bmccore.py info    $OUT/crash_null_arm64.core.gz"
echo "  python3 bmccore.py analyze $OUT/crash_heap_arm64.core.gz --artifact-dir <产物目录>"

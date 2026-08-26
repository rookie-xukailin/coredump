#!/usr/bin/env bash
# 批次 2：硬件/平台/嵌入式特定维度 10 例（#55~#64）
# 缺 volatile 的寄存器读/非对齐访问/DMA 对齐/EEPROM 垃圾函数指针/
# 配置数组尺寸/argv 缺失/初始化顺序/看门狗卡死/线程挂死/锁死锁
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 55. no_volatile_hw: 状态寄存器缺 volatile → 编译器缓存过期值 ----------
cat > $CS/no_volatile_hw.c <<'EOF'
/* BUG: 硬件状态寄存器地址没有 volatile——轮询循环被 -O1 外提成一次
   读, 后续全用寄存器里的过期值当通道号 → 野地址 */
#include <stdio.h>
#include <stdlib.h>

static unsigned int g_hw_status = 0x77770000u;   /* 模拟 MMIO 状态寄存器(缺 volatile) */

__attribute__((noinline))
static int hw_dma_setup(unsigned char *buf)
{
    unsigned int s = 0;
    for (int i = 0; i < 8; i++)
        s = g_hw_status;                   /* LICM: 只读一次, 旧值常驻 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(buf + s));
    *(volatile unsigned int *)(buf + s) = 0x1;   /* 崩溃行: 过期值=2GB 偏移 */
    return 1;
}

__attribute__((noinline))
static int hw_bus_init(void)
{
    unsigned char *buf = malloc(64);
    if (!buf) return 0;
    buf[0] = 0;
    return hw_dma_setup(buf);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return hw_bus_init() & 1;
}
EOF

# ---------- 56. unaligned_arm: 字节流 +1 偏移直接 cast 成 uint32_t* ----------
cat > $CS/unaligned_arm.c <<'EOF'
/* BUG: 网络字节流 (uint32_t*)(buf+1) 非对齐解引用——对齐检查开启的
   核上 SIGBUS; 未开启的核上读到"旋转"错值当偏移 → 野地址 */
#include <stdio.h>
#include <stdint.h>

static const uint8_t g_rx[8] = {0xAA, 0x00, 0x00, 0x00, 0x77, 0x55, 0x55, 0x55};

__attribute__((noinline))
static uint32_t net_ld_word(const uint8_t *p)
{
    return *(const uint32_t *)p;           /* 崩溃点A: 非对齐陷阱 SIGBUS */
}

__attribute__((noinline))
static int net_rx_frame(const uint8_t *raw, uint8_t *base)
{
    uint32_t v;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(raw + 1));
    v = net_ld_word(raw + 1);              /* BUG: 非对齐 cast */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(base + v));
    *(volatile uint8_t *)(base + v) = 1;   /* 崩溃点B: 旋转错值=2GB 偏移 */
    return 1;
}

__attribute__((noinline))
static int net_pkt_recv(const uint8_t *raw, uint8_t *base)
{
    return net_rx_frame(raw, base);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    static uint8_t base[64];
    return net_pkt_recv(g_rx, base) & 1;
}
EOF

# ---------- 57. dma_alignment: DMA 控制器要求 32B 对齐, 驱动没保证 ----------
cat > $CS/dma_alignment.c <<'EOF'
/* BUG: DMA 描述符要求 32B 对齐, 驱动把描述符建在 buffer+1——控制器
   取描述符即非对齐; 不设对齐检查的核上回读错值当帧长 → 野地址 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const uint8_t g_desc_tpl[8] = {0x00, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00};

__attribute__((noinline))
static int dma_start_xfer(uint8_t *ring)
{
    uint8_t *desc = ring + 1;              /* BUG: 未对齐到 32B */
    volatile uint32_t len;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)desc);
    len = *(volatile uint32_t *)desc;      /* 非对齐取帧长(对齐核上陷阱);
                                               否则错位读出 0x77000000 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(ring + len));
    *(volatile uint8_t *)(ring + len) = 1; /* 崩溃行: 错位巨值当帧长 */
    return 1;
}

__attribute__((noinline))
static int dma_engine_submit(uint8_t *ring)
{
    memcpy(ring, g_desc_tpl, 8);
    return dma_start_xfer(ring);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    static uint8_t ring[64];
    return dma_engine_submit(ring) & 1;
}
EOF

# ---------- 58. eeprom_corrupt: EEPROM 读出垃圾值当函数指针调用 ----------
cat > $CS/eeprom_corrupt.c <<'EOF'
/* BUG: 校验和跳过时把 EEPROM 读出的 0xDEADBEEF 当板级钩子函数指针
   直接调用 → 跳入未映射执行 → SEGV @0xdeadbeef */
#include <stdio.h>
#include <stdint.h>

static volatile uint32_t g_eeprom_word = 0xDEADBEEFu;   /* 损坏的 EEPROM 内容 */

typedef int (*board_hook_fn)(int);

__attribute__((noinline))
static int board_hook_invoke(board_hook_fn f, int arg)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)f);
    return f(arg);                         /* 崩溃行: call 0xdeadbeef */
}

__attribute__((noinline))
static int board_late_init(void)
{
    board_hook_fn hook = (board_hook_fn)(uintptr_t)g_eeprom_word;
    return board_hook_invoke(hook, 3);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return board_late_init() & 1;
}
EOF

# ---------- 59. config_array_size: 配置值 99999 直接当数组大小 ----------
cat > $CS/config_array_size.c <<'EOF'
/* BUG: 配置文件条数 99999 按 uint16 尺寸申请(200KB), 初始化循环却按
   64B 大条目写 6.4MB——越过 mmap 分配末尾 → SEGV */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static volatile uint32_t g_cfg_n = 99999u;   /* 配置读出的条目数 */

struct dev_ent {
    char name[60];
    int id;
};                                          /* 64B 大条目 */

__attribute__((noinline))
static int cfg_load_table(void)
{
    uint32_t n = g_cfg_n;
    uint8_t *p = malloc(n * sizeof(uint16_t));   /* BUG: 尺寸按 2B 算 */
    if (!p) return 0;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(p + n * sizeof(uint16_t)));
    for (uint32_t i = 0; i < n; i++) {
        struct dev_ent *e = (struct dev_ent *)(p + i * sizeof(struct dev_ent));
        e->id = (int)i;                    /* 崩溃行: 越过 200KB 映射 */
    }
    return 1;
}

__attribute__((noinline))
static int cfg_service_reload(void)
{
    return cfg_load_table();
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return cfg_service_reload() & 1;
}
EOF

# ---------- 60. argv_missing: argv[1] 没查 argc → NULL 字符串 strcpy ----------
cat > $CS/argv_missing.c <<'EOF'
/* BUG: 无参运行时 argv[1]==NULL, 命令行处理不查 argc 直接 strcpy
   源指针 → 读 NULL → SEGV */
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
static int cli_run_request(const char *arg)
{
    char buf[32];
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)arg);
    strcpy(buf, arg);                      /* 崩溃行: 源=NULL */
    return buf[0];
}

__attribute__((noinline))
static int cli_serve(int argc, char **argv)
{
    (void)argc;                            /* BUG: argc 被无视 */
    return cli_run_request(argv[1]);
}

int main(int argc, char **argv)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return cli_serve(argc, argv) & 1;
}
EOF

# ---------- 61. init_order: 依赖模块未初始化, ops 表还是 NULL ----------
cat > $CS/init_order.c <<'EOF'
/* BUG: 驱动 B 先于它依赖的总线模块 A 初始化——A 注册的 ops 表还是
   NULL, B 的读取路径穿 ops 调用 → 空指针 */
#include <stdio.h>

struct bus_ops {
    int (*read)(int reg);
};

struct bus_dev {
    int unit;
    struct bus_ops *ops;                   /* A 初始化后才非 NULL */
};

static struct bus_dev g_i2c_bus = { 3, NULL };   /* A 未 init: ops=NULL */

__attribute__((noinline))
static int sensor_bus_read(struct bus_dev *bus, int reg)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)bus->ops);
    return bus->ops->read(reg);            /* 崩溃行: NULL->read() */
}

__attribute__((noinline))
static int sensor_svc_poll(void)
{
    return sensor_bus_read(&g_i2c_bus, 0x10);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    /* 正常顺序应先 i2c_bus_register() 再 sensor_init(), 此处反了 */
    return sensor_svc_poll() & 1;
}
EOF

# ---------- 62. watchdog_stuck: 线程死循环 → 看门狗超时 SIGABRT ----------
cat > $CS/watchdog_stuck.c <<'EOF'
/* BUG: 采样线程在坏分支里死循环不再喂狗——软看门狗超时后
   raise(SIGABRT) 复位进程 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

static volatile long g_feed;

__attribute__((noinline))
static void *worker_spin(void *arg)
{
    (void)arg;
    for (;;) {
        g_feed++;                          /* BUG: 坏分支死循环, 不再喂狗 */
    }
    return NULL;
}

__attribute__((noinline))
static int wd_expire(void)
{
    raise(SIGABRT);                        /* 崩溃行: 看门狗超时杀进程 */
    return 0;
}

__attribute__((noinline))
static void *wd_watch(void *arg)
{
    (void)arg;
    usleep(300000);                        /* 300ms 无喂狗 → 超时 */
    wd_expire();
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    pthread_t tw, td;
    pthread_create(&tw, NULL, worker_spin, NULL);
    pthread_create(&td, NULL, wd_watch, NULL);
    pthread_join(td, NULL);
    pthread_join(tw, NULL);
    return 0;
}
EOF

# ---------- 63. thread_hang_kill: 线程阻塞在 syscall → 看门狗定向杀 ----------
cat > $CS/thread_hang_kill.c <<'EOF'
/* BUG: 命令线程阻塞在无数据的 read 上——看门狗超时后 pthread_kill
   向挂死线程发 SIGABRT（崩溃线程停在系统调用里） */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

static pthread_t g_main_tid;

__attribute__((noinline))
static int cli_cmd_wait(int fd)
{
    char b[8];
    return (int)read(fd, b, sizeof b);     /* 崩溃行: 永久阻塞被杀 */
}

__attribute__((noinline))
static int cli_serve(int fd)
{
    return cli_cmd_wait(fd);
}

__attribute__((noinline))
static void *wd_watch(void *arg)
{
    (void)arg;
    usleep(300000);
    pthread_kill(g_main_tid, SIGABRT);     /* 挂死线程定向击杀 */
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    int fds[2];
    pthread_t td;
    if (pipe(fds) != 0) return 1;
    g_main_tid = pthread_self();
    pthread_create(&td, NULL, wd_watch, NULL);
    cli_serve(fds[0]);                     /* 无数据: 阻塞 */
    pthread_join(td, NULL);
    return 0;
}
EOF

# ---------- 64. lock_deadlock_kill: 两线程互等锁 → 外部看门狗杀 ----------
cat > $CS/lock_deadlock_kill.c <<'EOF'
/* BUG: 线程 A 锁序 L1→L2、线程 B 锁序 L2→L1 交叉互等——看门狗超时后
   向 A 发 SIGABRT（崩溃线程停在 futex 等待, 另一线程持锁被卡） */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>

static pthread_mutex_t L1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t L2 = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_a_held, g_b_held;
static pthread_t g_tid_a;

__attribute__((noinline))
static void *net_cfg_apply(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&L1);
    g_a_held = 1;
    while (!g_b_held) sched_yield();
    pthread_mutex_lock(&L2);               /* 崩溃行: 与 B 互等, 被杀 */
    g_a_held = 2;
    pthread_mutex_unlock(&L2);
    pthread_mutex_unlock(&L1);
    return NULL;
}

__attribute__((noinline))
static void *net_stat_apply(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&L2);
    g_b_held = 1;
    while (!g_a_held) sched_yield();
    pthread_mutex_lock(&L1);               /* 死锁对端 */
    g_b_held = 2;
    pthread_mutex_unlock(&L1);
    pthread_mutex_unlock(&L2);
    return NULL;
}

__attribute__((noinline))
static void *wd_watch(void *arg)
{
    (void)arg;
    usleep(500000);
    pthread_kill(g_tid_a, SIGABRT);        /* 看门狗杀死锁线程 */
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    pthread_t ta, tb, td;
    pthread_create(&ta, NULL, net_cfg_apply, NULL);
    g_tid_a = ta;
    pthread_create(&tb, NULL, net_stat_apply, NULL);
    pthread_create(&td, NULL, wd_watch, NULL);
    pthread_join(td, NULL);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    return 0;
}
EOF

echo "batch2: 10 cases written"

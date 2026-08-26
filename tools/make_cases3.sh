#!/usr/bin/env bash
# 批次 1：传统 C 语言经典维度 21 例（#34~#54）
# 悬垂指针/返回栈地址/非堆 free/未初始化指针/差一越界/整数回绕/
# sprintf 溢出/strlen 无终止/sizeof 参数退化/union 混用/符号转换/
# 只读段写/字节序/定时器 UAF/atexit UAF/关闭顺序/fd 耗尽/malloc NULL/
# SIGPIPE/SIGFPE/嵌套信号
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 34. realloc_dangling: realloc 搬迁后旧指针悬垂写 ----------
cat > $CS/realloc_dangling.c <<'EOF'
/* BUG: p=malloc(大块) 后 q=realloc(p, 更大)——超 mmap 阈值的搬迁必然
   munmap 旧区，代码仍持有旧指针 p 并写入 → 悬垂写已解映射内存 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile int g_zone_v = 0x5A5A;

__attribute__((noinline))
static int fw_config_save(void *zone, int v)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", zone);
    *(volatile int *)zone = v;             /* 崩溃行: 写已被 munmap 的旧块 */
    return v;
}

__attribute__((noinline))
static int fw_upgrade_stage(void *old_zone, int v)
{
    int rc = fw_config_save(old_zone, v);
    g_zone_v += rc;                        /* volatile 后置：防尾调用吞帧 */
    return rc;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    unsigned char *p = malloc(2u << 20);   /* 2MB: mmap 直供 */
    unsigned char *q;
    if (!p) return 1;
    memset(p, 0x31, 2u << 20);             /* 触碰使页驻留 */
    q = realloc(p, 8u << 20);              /* 8MB: 必搬迁, 旧 2MB 被 munmap */
    if (!q) return 1;
    memset(q, 0x32, 8u << 20);
    return fw_upgrade_stage(p, g_zone_v) & 1;   /* BUG: p 已悬垂 */
}
EOF

# ---------- 35. stack_local_return: 返回栈上 buffer 地址, 调用方当指针用 ----------
cat > $CS/stack_local_return.c <<'EOF'
/* BUG: 函数返回栈上局部 buffer 地址, 调用方拿"栈已回退"的悬垂地址继续
   用——后续调用复用该栈区写满垃圾, 悬垂内容被按 char** 解释解引用 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static volatile int g_off = 0;

__attribute__((noinline))
static char *hide_addr(void *real)
{
    char *out;
    memcpy(&out, &real, sizeof out);   /* 经内存转一手：阻断 -Wreturn-local-addr
                                          把"返回局部地址"静态改写为 NULL */
    return out;
}

__attribute__((noinline))
static char *cli_get_label(void)
{
    char buf[64];
    memset(buf, 'L', sizeof buf);
    return hide_addr(buf);             /* 真实栈地址逃逸(悬垂) */
}

__attribute__((noinline))
static void paint_prime(int depth)
{
    volatile char pad[2048];                /* 深层调用复用悬垂栈区 */
    for (unsigned i = 0; i < sizeof pad; i++)
        pad[i] = (char)0xAB;
    if (depth > 0)
        paint_prime(depth - 1);
}

__attribute__((noinline))
static int ui_draw_header(void)
{
    char **slot;
    char *label = cli_get_label();         /* 栈已回退的悬垂地址 */
    paint_prime(8);                        /* 复用并写满 0xAB 垃圾 */
    slot = (char **)label;                 /* 悬垂内容当指针解释 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)*slot);
    *(*slot) = 1;                          /* 崩溃行: 解引用栈垃圾 0xABAB.. */
    return 1;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    volatile int rc = ui_draw_header();
    return rc & 1;
}
EOF

# ---------- 36. free_nonheap: 在全局数据段内部指针上调用 free ----------
cat > $CS/free_nonheap.c <<'EOF'
/* BUG: 资源清理把全局数组的中间偏移当堆指针 free——非堆且不对齐,
   glibc 立即 abort: free(): invalid pointer */
#include <stdio.h>
#include <stdlib.h>

static int g_res_pool[8];                  /* .bss 全局——绝不是堆 */

__attribute__((noinline))
static void audit_release_zone(void *p)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", p);
    free(p);                               /* 崩溃行: free 非堆指针 → ABRT */
}

__attribute__((noinline))
static int audit_shutdown(void)
{
    audit_release_zone((void *)&g_res_pool[1]);  /* +4 偏移: 不对齐必炸 */
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_res_pool[0] = 42;
    return audit_shutdown() & 1;
}
EOF

# ---------- 37. uninit_stack_ptr: 未初始化局部指针恰好含栈垃圾 ----------
cat > $CS/uninit_stack_ptr.c <<'EOF'
/* BUG: 指针声明后未赋值直接解引用——同一栈区刚被 4 层递归播撒
   0xB5 垃圾, 指针槽复用脏值 → 解引用野地址 */
#include <stdio.h>
#include <string.h>

struct ring_frame {
    char pad[160];
    void *p;
};

__attribute__((noinline))
static void bus_prime_garbage(int depth)
{
    volatile char pad[4096];
    for (unsigned i = 0; i < sizeof pad; i++)
        pad[i] = (char)0xB5;               /* 大跨度播撒 0xB5B5B5... */
    if (depth > 0)
        bus_prime_garbage(depth - 1);      /* 4 层递归: 16KB 全覆盖 */
}

__attribute__((noinline))
static int sensor_use_stale(void)
{
    struct ring_frame f;                   /* p 未初始化, 复用脏值 */
    void *victim = f.p;
    fprintf(stderr, "FAULT_ADDR=%p\n", victim);
    *(volatile char *)victim = 1;          /* 崩溃行: 解引用栈垃圾 */
    return 1;
}

__attribute__((noinline))
static int bus_scan_ring(void)
{
    int rc;
    bus_prime_garbage(3);                  /* 先污染更深栈区 */
    rc = sensor_use_stale();               /* 再踩进同一块栈 */
    return rc;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return bus_scan_ring() & 1;
}
EOF

# ---------- 38. off_by_one: 循环边界 <=n 差一写越界 ----------
cat > $CS/off_by_one.c <<'EOF'
/* BUG: for(i=0;i<=n;i++) 的差一错误——写 map[n] 越过缓冲 1 个元素。
   缓冲取"3 页 PROT_NONE 中间页"保证越界一步即触碰保护页 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static volatile int g_rows = 4096;

__attribute__((noinline))
static void sdr_write_row(unsigned char *map, int n)
{
    for (int i = 0; i <= n; i++)           /* BUG: 应为 i < n */
        map[i] = 0x5C;                     /* 崩溃行: map[n] 越界 */
}

__attribute__((noinline))
static int sdr_bulk_sync(unsigned char *map)
{
    sdr_write_row(map, g_rows);
    return map[0];
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    unsigned char *guard = mmap(NULL, 3 * 4096, PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED) return 1;
    unsigned char *map = guard + 4096;     /* 中间页 */
    if (mprotect(map, 4096, PROT_READ | PROT_WRITE) != 0) return 1;
    memset(map, 0, 4096);
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(map + 4096));
    volatile int rc = sdr_bulk_sync(map);
    return rc & 1;
}
EOF

# ---------- 39. int_overflow_alloc: 32 位乘法回绕 → malloc(0) 后海量写 ----------
cat > $CS/int_overflow_alloc.c <<'EOF'
/* BUG: count*size 用 32 位运算——0x10000*0x10000 回绕为 0, malloc(0)
   返回最小块, 随后按 count*elem 逐条初始化写穿整个堆 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static volatile uint32_t g_count = 0x10000u;   /* 65536 条 */
static volatile uint32_t g_elem = 0x10000u;    /* 每条 64KB */

__attribute__((noinline))
static void *net_alloc_table(uint32_t count, uint32_t elem)
{
    uint32_t total = count * elem;         /* BUG: 32 位乘法回绕为 0 */
    void *p = malloc(total);               /* malloc(0): 最小块 */
    size_t bytes = (size_t)count * 256u;   /* 真实条目 256B × count */
    fprintf(stderr, "FAULT_ADDR=%p\n", p);
    /* 逐字节写(绕开 fortify 对 memset 的堆对象尺寸检查), 一路写穿堆顶 */
    for (size_t i = 0; i < bytes; i++)
        ((volatile unsigned char *)p)[i] = 0x41;   /* 崩溃行: 越过堆末尾 */
    return p;
}

__attribute__((noinline))
static int net_cfg_load(void)
{
    void *t = net_alloc_table(g_count, g_elem);
    return t != 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return net_cfg_load() & 1;
}
EOF

# ---------- 40. sprintf_overflow: 小栈 buffer 格式化超长串 ----------
cat > $CS/sprintf_overflow.c <<'EOF'
/* BUG: sprintf 向 64B 栈缓冲写入 256B 描述串——-O1 下 glibc
   _FORTIFY_SOURCE 的 __sprintf_chk 运行期拦截 → abort */
#include <stdio.h>

static const char g_long_desc[256] =
    "board-desc::fm-rev-77:power-zone-A2:sensor-bus-3:fw-2.14.3-hotfix-9:"
    "vendor-string-very-long-payload-for-overflow-test-0123456789abcdef"
    "extended-manufacturing-data-paragraph-appended-by-mlb-fru-record-xyz";

__attribute__((noinline))
static void log_build_tag(char *out)       /* out 指向 64B 栈缓冲 */
{
    sprintf(out, "%s", g_long_desc);       /* 崩溃行: fortify abort */
}

__attribute__((noinline))
static int log_emit_banner(void)
{
    char tag[64];
    log_build_tag(tag);
    return tag[0];
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    volatile int rc = log_emit_banner();
    return rc & 1;
}
EOF

# ---------- 41. strlen_noterm: malloc 缓冲未清零无终止符, strlen 跑飞 ----------
cat > $CS/strlen_noterm.c <<'EOF'
/* BUG: malloc 的描述缓冲不清零、填满非零字节即交给 strlen——没有 NUL,
   strlen 一路读过 mmap 映射尾部 → SEGV */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

__attribute__((noinline))
static size_t sdr_desc_len(const char *desc)
{
    return strlen(desc);                   /* 崩溃行: 越过映射末尾 */
}

__attribute__((noinline))
static int sdr_inventory_scan(char *desc, size_t usable)
{
    memset(desc, 'R', usable);             /* 全部填非零, 无终止符 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(desc + usable));
    return (int)(sdr_desc_len(desc) & 1);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    char *desc = malloc(1u << 20);         /* 1MB: mmap 直供, 页精确 */
    if (!desc) return 1;
    return sdr_inventory_scan(desc, malloc_usable_size(desc)) & 1;
}
EOF

# ---------- 42. sizeof_pointer: 数组参数退化为指针, sizeof 只剩 8 ----------
cat > $CS/sizeof_pointer.c <<'EOF'
/* BUG: void f(char *msgs[64]) 内 sizeof(msgs)==8——memset 只清第一个
   指针, 后续槽位仍是毒化值, 调用方按已清零语义取 msgs[40] 使用 */
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
static void msg_clear(char *msgs[64])
{
    memset(msgs, 0, sizeof(msgs));         /* BUG: sizeof(参数)=8, 只清 8B */
}

__attribute__((noinline))
static int ui_dispatch(char *msgs[64])
{
    msg_clear(msgs);
    fprintf(stderr, "FAULT_ADDR=%p\n", msgs[40]);  /* 仍是 0x7777... 毒值 */
    *(volatile char *)msgs[40] = 1;        /* 崩溃行: 解引用毒化指针 */
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    static char *msgs[64];
    /* 播撒毒化指针(0x68000000 基址: 32/64 位上均落入未映射野地址) */
    for (volatile int i = 0; i < 64; i++)
        msgs[i] = (char *)(0x68000000UL + (unsigned long)i * 8);
    return ui_dispatch(msgs) & 1;
}
EOF

# ---------- 43. union_confusion: 小整数写进 union, 按指针读出解引用 ----------
cat > $CS/union_confusion.c <<'EOF'
/* BUG: union 先写 uint32_t 小值 42, 又按 void* 读出当指针用——
   高位是垃圾、低位 0x2a → 解引用 0x2a 附近 */
#include <stdio.h>
#include <stdint.h>

union bus_slot {
    uint32_t small;
    void *raw;
};

static volatile uint32_t g_slot_id = 42;

__attribute__((noinline))
static int bus_slot_fire(union bus_slot *s)
{
    void *victim = s->raw;                 /* 按指针读——值=42 */
    fprintf(stderr, "FAULT_ADDR=%p\n", victim);
    *(volatile int *)victim = 7;           /* 崩溃行: 解引用 0x2a */
    return 7;
}

__attribute__((noinline))
static int bus_slot_program(union bus_slot *s)
{
    s->small = g_slot_id;                  /* 按 uint32 写 42 */
    return bus_slot_fire(s);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    static union bus_slot s;
    return bus_slot_program(&s) & 1;
}
EOF

# ---------- 44. signed_unsigned: 负长度转无符号 → 巨大块索引 ----------
cat > $CS/signed_unsigned.c <<'EOF'
/* BUG: int len=-1 赋给 unsigned idx → 0xFFFFFFFF；buf[idx] 把负值
   当无符号块号用(每块 64KB), 偏移 4GB(64 位)/-64KB(32 位回绕) → 野地址 */
#include <stdio.h>
#include <stdlib.h>

static volatile int g_len = -1;            /* 解码失败的返回值 */

#define BLK 65536u

__attribute__((noinline))
static void pkt_write_at(char *buf, unsigned idx)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(buf + (size_t)idx * BLK));
    buf[(size_t)idx * BLK] = 0x2E;         /* 崩溃行: 巨大无符号块偏移 */
}

__attribute__((noinline))
static int pkt_dump_field(char *buf)
{
    unsigned idx = g_len;                  /* BUG: 负数隐式转巨大无符号 */
    pkt_write_at(buf, idx);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    char *buf = malloc(64);
    if (!buf) return 1;
    buf[0] = 1;
    return pkt_dump_field(buf) & 1;
}
EOF

# ---------- 45. const_rodata_write: 字符串字面量当可写缓冲改写 ----------
cat > $CS/const_rodata_write.c <<'EOF'
/* BUG: char *s = "board:serial:cfg" 后直接 s[0]='X'——字面量在
   .rodata 只读段, 写入 → SEGV ACCERR */
#include <stdio.h>

static char *volatile g_cfg_ro = "board_serial_config_v3";

__attribute__((noinline))
static void cfg_write_byte(char *s)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)s);
    s[0] = 'X';                            /* 崩溃行: 写 .rodata → ACCERR */
}

__attribute__((noinline))
static int cfg_override_serial(void)
{
    char *s = g_cfg_ro;                    /* 指向只读字面量 */
    cfg_write_byte(s);
    return s[0];
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return cfg_override_serial() & 1;
}
EOF

# ---------- 46. endianness_cast: 网络大端字节流直接 cast 成本机小端 ----------
cat > $CS/endianness_cast.c <<'EOF'
/* BUG: 收到的大端网络帧直接按 uint64_t* 解释——小端机器读出字节反转的
   巨值当偏移: 64 位上落入非规范地址段, 32 位上截断成 +256MB → 野地址 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

/* 大端编码的意图值 0x1000（页内偏移）; 小端直读 = 0x0080000010000000 */
static const uint8_t g_be_frame[8] =
    {0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x80, 0x00};

__attribute__((noinline))
static int net_frame_apply(uint8_t *raw, uint8_t *base)
{
    uint64_t aligned[1];
    uint64_t off;
    memcpy(aligned, raw, 8);               /* 对齐到局部再 cast */
    off = *(uint64_t *)aligned;            /* BUG: 字节序反了, 读出巨值 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(base + (size_t)off));
    *(volatile uint8_t *)(base + (size_t)off) = 1;   /* 崩溃行: 野偏移 */
    return 1;
}

__attribute__((noinline))
static int net_pkt_process(uint8_t *raw, uint8_t *base)
{
    return net_frame_apply(raw, base);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    uint8_t *base = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 1;
    return net_pkt_process((uint8_t *)g_be_frame, base) & 1;
}
EOF

# ---------- 47. timer_after_free: 定时器回调引用已 free 的大块 ctx ----------
cat > $CS/timer_after_free.c <<'EOF'
/* BUG: 周期定时器回调引用的 ctx 已被 free（mmap 大块 → munmap）。
   RT 信号 handler 只置标志（异步安全），主线程轮询标志后按回调语义
   访问 ctx —— 对象已解映射 → SEGV（qemu 对 handler 内崩溃会丢失寄存器
   上下文，故经标志位在普通线程上下文完成访问） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

struct sensor_ctx {
    long ticks;
    char pad[(1u << 20) - sizeof(long)];
};

static struct sensor_ctx *g_ctx;
static volatile sig_atomic_t g_fired;

static void sensor_timer_fire(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si; (void)uc;
    g_fired = 1;                           /* handler 内只做异步安全动作 */
}

__attribute__((noinline))
static int timer_poll_fire(void)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)g_ctx);
    g_ctx->ticks++;                        /* 崩溃行: ctx 已 munmap */
    return 1;
}

__attribute__((noinline))
static int sensor_poll_setup(void)
{
    timer_t tid;
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sensor_timer_fire;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGRTMIN, &sa, NULL);

    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    if (timer_create(CLOCK_MONOTONIC, &sev, &tid) != 0) return 1;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 10000000;    /* 10ms 周期 */
    its.it_value = its.it_interval;
    timer_settime(tid, 0, &its, NULL);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_ctx = calloc(1, sizeof *g_ctx);      /* 1MB: mmap 直供 */
    if (!g_ctx) return 1;
    if (sensor_poll_setup() != 0) return 1;
    free(g_ctx);                           /* BUG: 定时器还活着, ctx 先 munmap */
    while (!g_fired)
        pause();                           /* 等 RT 信号置标志 */
    return timer_poll_fire() & 1;          /* 回调语义访问悬垂 ctx */
}
EOF

# ---------- 48. atexit_stale: atexit 回调引用已 free 的全局会话 ----------
cat > $CS/atexit_stale.c <<'EOF'
/* BUG: atexit 注册的冲刷回调引用全局会话——exit 前会话已 free
   （mmap 大块 → munmap），退出路径上解引用悬垂指针 */
#include <stdio.h>
#include <stdlib.h>

struct bmc_session {
    long dirty;
    char pad[(2u << 20) - sizeof(long)];
};

static struct bmc_session *volatile g_sess;

static void bmc_session_flush(void)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)g_sess);
    g_sess->dirty = 0;                     /* 崩溃行: 会话已 munmap */
}

__attribute__((noinline))
static void bmc_service_stop(void)
{
    free((void *)g_sess);                  /* BUG: 退出钩子还挂在上面 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_sess = calloc(1, sizeof *g_sess);    /* 2MB: mmap 直供 */
    if (!g_sess) return 1;
    atexit(bmc_session_flush);
    bmc_service_stop();
    return 0;                              /* exit → 回调踩悬垂 */
}
EOF

# ---------- 49. shutdown_order: 共享 ctx 先 free, worker 线程还在用 ----------
cat > $CS/shutdown_order.c <<'EOF'
/* BUG: 关闭顺序颠倒——主线程 free 共享 ctx（mmap 大块 → munmap），
   worker 线程的读取循环下一拍就踩已解映射内存 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

struct sess_ctx {
    volatile long counter;
    char pad[(2u << 20) - sizeof(long)];
};

static struct sess_ctx *g_ctx;
static volatile long g_sink;

__attribute__((noinline))
static void *sess_worker_loop(void *arg)
{
    (void)arg;
    volatile struct sess_ctx *vc = g_ctx;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)g_ctx);
    for (;;) {
        g_sink += vc->counter;             /* 崩溃行: ctx 被 munmap 后 */
    }
    return NULL;
}

__attribute__((noinline))
static int sess_service_start(pthread_t *tid)
{
    g_ctx = calloc(1, sizeof *g_ctx);
    if (!g_ctx) return 1;
    return pthread_create(tid, NULL, sess_worker_loop, NULL);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    pthread_t tid;
    if (sess_service_start(&tid) != 0) return 1;
    usleep(200000);                        /* 等 worker 进入读取循环 */
    free(g_ctx);                           /* BUG: worker 还在读 */
    pthread_join(tid, NULL);
    return 0;
}
EOF

# ---------- 50. fd_exhaust: fd 耗尽返回 -1 未检查, 当无符号块索引用 ----------
cat > $CS/fd_exhaust.c <<'EOF'
/* BUG: 循环 open 直到 fd 耗尽（部署配额把 RLIMIT_NOFILE 压到 64）,
   返回 -1 不检查——赋给 unsigned 后变 0xFFFFFFFF, 当 64KB 槽区块号用
   → 4GB/-64KB 偏移野地址 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/resource.h>

#define SLOT_BLK 65536u
#define DEV_QUOTA 4                         /* 部署配额: 设备打开上限(仿真
                                              环境 gdb 对宿主 fd 数敏感) */

__attribute__((noinline))
static void dev_open_all(char *slot_map)
{
    int fd = 0;
    int n = 0;
    while (n < DEV_QUOTA) {                 /* 打满配额 */
        fd = open("/dev/null", O_RDONLY);
        if (fd < 0) break;                  /* 真实耗尽 */
        n++;
    }
    if (n >= DEV_QUOTA)
        fd = -1;                            /* BUG: 配额上限当 EMFILE 返回
                                                 -1, 调用方不检查 */
    {
        size_t idx = (size_t)(unsigned)fd * SLOT_BLK;   /* -1 → 0xFFFF0000 */
        fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(slot_map + idx));
        slot_map[idx] = 1;                 /* 崩溃行: 巨大块偏移 */
    }
}

__attribute__((noinline))
static int dev_enumerate(void)
{
    char *slot_map = malloc(64);
    if (!slot_map) return 1;
    slot_map[0] = 0;
    dev_open_all(slot_map);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return dev_enumerate() & 1;
}
EOF

# ---------- 51. malloc_null: 超大 malloc 返回 NULL 未判空 ----------
cat > $CS/malloc_null.c <<'EOF'
/* BUG: 预留池大小取自配置项，未初始化的配置读出 -1（SIZE_MAX），
   malloc 必然失败返回 NULL，未判空直接写成员 → 空指针+16 偏移 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static volatile size_t g_want = (size_t)-1;   /* 配置读出 -1 */

struct cap_blob {
    char pad[16];
    long magic;
};

__attribute__((noinline))
static struct cap_blob *cap_alloc_blob(size_t want)
{
    struct cap_blob *p = malloc(want);     /* NULL */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)&p->magic);
    p->magic = 0xC0DE;                     /* 崩溃行: NULL+16 写 */
    return p;
}

__attribute__((noinline))
static int cap_reserve_pool(void)
{
    struct cap_blob *b = cap_alloc_blob(g_want);
    return b != 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return cap_reserve_pool() & 1;
}
EOF

# ---------- 52. sigpipe_write: 写对端已关闭的管道 → SIGPIPE ----------
cat > $CS/sigpipe_write.c <<'EOF'
/* BUG: 日志冲刷线程向管道写入——采集端早已 close 读端, 写入即 SIGPIPE
   （默认终止）。
   注: qemu-user 的 gdbstub 不拦截宿主来源 SIGPIPE，生成环境以 block-write
   探测 EPIPE 后经 ipc_sigpipe_default 断点取核并注入 NT_SIGINFO(13) +
   pr_cursig 还原信号现场；真机上 ipc_pipe_write 的 write 本身即崩溃点 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <stdlib.h>

__attribute__((noinline))
static int ipc_pipe_write(int fd, const void *buf, size_t n)
{
    return (int)write(fd, buf, n);         /* 真机崩溃点: SIGPIPE */
}

__attribute__((noinline))
static void ipc_sigpipe_default(void)
{
    raise(SIGPIPE);                        /* 内核对无 handler 写者的默认动作 */
}

__attribute__((noinline))
static int ipc_flush_logs(int fds[2])
{
    static const char payload[4096] = "log";
    int rc;
    close(fds[0]);                         /* BUG: 读端先关, 写端不知情 */
    if (getenv("BMC_QEMU_EPIPE_PROBE")) {
        /* qemu 生成环境: 宿主 SIGPIPE 不可被 stub 拦截——以 poll 探测
           对端消失(POLLERR)代替真实写入 */
        struct pollfd pfd;
        pfd.fd = fds[1];
        pfd.events = POLLOUT;
        poll(&pfd, 1, 0);
        rc = (pfd.revents & POLLERR) ? -1 : 0;
    } else {
        rc = ipc_pipe_write(fds[1], payload, sizeof payload);
    }
    if (rc < 0)
        ipc_sigpipe_default();             /* EPIPE → SIGPIPE 终止 */
    return rc;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    int fds[2];
    if (pipe(fds) != 0) return 1;
    volatile int rc = ipc_flush_logs(fds);
    return rc & 1;
}
EOF

# ---------- 53. fpe_divzero: 传感器换算除零 → SIGFPE ----------
cat > $CS/fpe_divzero.c <<'EOF'
/* BUG: 转速换算 (a-b)/(c-c)——校准参数相同时分母为 0。
   arm64/riscv 的整数除法不产生陷阱(结果为 0), 换算层的除零检测
   按固件规约 raise(SIGFPE) 终止并触发转储 */
#include <stdio.h>
#include <signal.h>

static volatile int g_cal_a = 100;
static volatile int g_cal_b = 100;
static volatile int g_cal_c = 100;

__attribute__((noinline))
static int sensor_ratio(int a, int b, int c)
{
    int d = c - c;                         /* 分母恒 0 */
    if (d == 0)
        raise(SIGFPE);                     /* 崩溃行: 除零 → SIGFPE */
    return (a - b) / d;
}

__attribute__((noinline))
static int sensor_calc_rpm(int pulses)
{
    return sensor_ratio(g_cal_a, g_cal_b, g_cal_c) * pulses;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    volatile int rc = sensor_calc_rpm(36);
    return rc & 1;
}
EOF

# ---------- 54. nest_signal: SIGSEGV handler 内再次空指针 → 嵌套故障 ----------
cat > $CS/nest_signal.c <<'EOF'
/* BUG: SIGSEGV 处理函数内部又解引用空指针——同号信号被屏蔽时再次
   出错, 内核直接杀死, 崩在 handler 里 */
#include <stdio.h>
#include <signal.h>

static volatile int *g_probe;              /* NULL: 第一次故障点 */
static volatile int *g_log_hdr;            /* NULL: handler 内二次故障 */

static void nest_segv_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si; (void)uc;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)g_log_hdr);
    *g_log_hdr = 1;                        /* 崩溃行: handler 内再崩 */
}

__attribute__((noinline))
static int fault_probe(void)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)g_probe);
    *g_probe = 1;                          /* 第一次 SEGV → 进 handler */
    return 1;
}

__attribute__((noinline))
static int diag_service_run(void)
{
    struct sigaction sa;
    __builtin_memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = nest_segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    return fault_probe();
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return diag_service_run() & 1;
}
EOF

echo "batch1: $(ls $CS | grep -cE 'realloc_dangling|stack_local_return|free_nonheap|uninit_stack_ptr|off_by_one|int_overflow_alloc|sprintf_overflow|strlen_noterm|sizeof_pointer|union_confusion|signed_unsigned|const_rodata_write|endianness_cast|timer_after_free|atexit_stale|shutdown_order|fd_exhaust|malloc_null|sigpipe_write|fpe_divzero|nest_signal') cases"

#!/usr/bin/env bash
# 生成 12 个经典 coredump 案例的 C 源码（BMC 风格，多级调用链）
# 崩溃前向 stderr 打印 FAULT_ADDR=0x... 供 SIGINFO 注入使用
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 1. null_write (arm64): 空指针写 struct 成员 ----------
cat > $CS/null_write.c <<'EOF'
/* BMC 风格：设备驱动初始化顺序错误导致全局 dev 为 NULL 仍被写 */
#include <stdio.h>
#include <stdint.h>

struct fan_dev {
    int   idx;
    volatile unsigned int *ctrl_reg;   /* 偏移 8 */
    char  name[24];
    int   rpm;
};

static struct fan_dev *g_fan;          /* 板载风扇未注册时为 NULL */

static int hw_fan_set_pwm(struct fan_dev *dev, int duty)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)&dev->ctrl_reg);
    dev->ctrl_reg = (volatile unsigned int *)(uintptr_t)(0x1000u + duty); /* 崩溃行 */
    return 0;
}

static int thermal_apply_policy(int duty)
{ return hw_fan_set_pwm(g_fan, duty); }

static int thermal_loop(void)
{
    int duty = 128;
    for (int t = 0; t < 4; t++)
        duty += thermal_apply_policy(duty);
    return duty;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    /* 正常路径应当先 fan_register(&g_fan)，此处遗漏 */
    return thermal_loop() & 1;
}
EOF

# ---------- 2. wild_mmio (arm32, thumb): 基址表索引写坏 → 写未映射 ----------
cat > $CS/wild_mmio.c <<'EOF'
/* BMC 风格：多型号单板寄存器基址表索引被写坏，写出到未映射区域 */
#include <stdio.h>

typedef volatile unsigned int reg32_t;

struct plat_cfg { unsigned long gpio_base; unsigned long pwm_base; };
static const struct plat_cfg g_plats[] = {
    { 0x50000000UL, 0x50010000UL },
    { 0x51000000UL, 0x51010000UL },
    { 0x52000000UL, 0x52010000UL },
};

static unsigned long g_plat_idx = 2;   /* 意外被写坏 */

static int pwm_hw_init(unsigned long base)
{
    reg32_t *en = (reg32_t *)(base + 0x0c);
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)en);
    *en = 1;                            /* 崩溃行 */
    return 0;
}

static int pwm_init_for_model(const struct plat_cfg *cfg)
{ return pwm_hw_init(cfg->pwm_base); }

static int board_early_init(void)
{
    const struct plat_cfg *cfg = &g_plats[g_plat_idx];   /* 越界取基址 */
    return pwm_init_for_model(cfg);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_plat_idx = 0x25;                  /* 模拟配置解析把索引写坏 */
    return board_early_init();
}
EOF

# ---------- 3. stack_overflow (arm64): 递归栈溢出 ----------
cat > $CS/stack_overflow.c <<'EOF'
/* BMC 风格：SEL 事件树存在自引用环路，遍历递归爆栈 */
#include <string.h>

struct sel_node {
    char name[48];
    struct sel_node *child[4];
    int assert_bit;
};

static struct sel_node *g_root;

static int sel_assert_recursive(struct sel_node *n, int depth)
{
    char trail[768];
    memset(trail, depth & 0xff, sizeof trail);
    if (!n) return 0;
    int hit = 0;
    for (int i = 0; i < 4; i++)
        hit |= sel_assert_recursive(n->child[i], depth + 1);   /* 环路→无限递归 */
    return hit | n->assert_bit;
}

static int sel_walk_all(void)
{ return sel_assert_recursive(g_root, 0); }

static int sel_service_main(void)
{
    int r = sel_walk_all();
    return r ? 0 : 1;
}

int main(void)
{
    struct sel_node a, b;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.child[0] = &b; b.child[0] = &a;   /* 制造环路 */
    g_root = &a;
    return sel_service_main();
}
EOF

# ---------- 4. heap_overflow (arm64): 堆溢出写穿 chunk 头, free 暴雷 ----------
cat > $CS/heap_overflow.c <<'EOF'
/* BMC 风格：sensor 描述拷贝无长度检查，写穿相邻 chunk 头，释放时 glibc abort */
#include <stdlib.h>
#include <string.h>

struct sensor_slot {
    char name[0x100 - 8];
    int  seq;
};

static struct sensor_slot *g_slots[2];

static int sensor_fill_name(struct sensor_slot *s, const char *src)
{
    strcpy(s->name, src);               /* BUG: 无边界检查 */
    return 0;
}

static int sensor_load_fru(void)
{
    char fru_desc[0x140];
    memset(fru_desc, 'S', sizeof fru_desc - 1);
    fru_desc[sizeof fru_desc - 1] = 0;

    g_slots[0] = malloc(0x100);
    g_slots[1] = malloc(0x100);
    if (!g_slots[0] || !g_slots[1]) return -1;
    g_slots[0]->seq = 1; g_slots[1]->seq = 2;
    sensor_fill_name(g_slots[0], fru_desc);   /* 溢出写穿 slots[1] chunk 头 */
    return 0;
}

static int sensor_unload(void)
{
    free(g_slots[1]);                   /* 崩溃点: free 检测 next size 非法 → abort */
    free(g_slots[0]);
    g_slots[0] = g_slots[1] = NULL;
    return 0;
}

int main(void)
{
    if (sensor_load_fru() != 0) return 1;
    return sensor_unload();
}
EOF

# ---------- 5. double_free (riscv64): 错误路径+上层重试 双重清理 ----------
cat > $CS/double_free.c <<'EOF'
/* BMC 风格：底层错误路径已释放 audit 记录，上层不知道又清理一遍 */
#include <stdlib.h>
#include <string.h>

struct audit_rec {
    char tag[24];
    struct audit_rec *next;
};

static struct audit_rec *g_head;
static int g_count;

static int audit_append(const char *tag)
{
    struct audit_rec *r = calloc(1, sizeof *r);
    if (!r) return -1;
    strncpy(r->tag, tag, sizeof r->tag - 1);
    r->next = g_head;
    g_head = r;
    g_count++;
    return 0;
}

static void audit_cleanup(void)
{
    struct audit_rec *p = g_head;
    while (p) {
        struct audit_rec *nx = p->next;
        free(p);                        /* BUG: 不清 g_head/g_count */
        p = nx;
    }
}

static int audit_send(void)
{ return -1; }                          /* 模拟发送失败 */

static int audit_record_boot(void)
{
    audit_append("power-on");
    audit_append("bios-post");
    audit_append("bmc-handoff");
    if (audit_send() != 0) {
        audit_cleanup();                /* 错误路径清理 #1 */
        return -1;
    }
    return 0;
}

int main(void)
{
    if (audit_record_boot() != 0) {
        audit_cleanup();                /* BUG: 上层重试清理 → double free abort */
        return 1;
    }
    return 0;
}
EOF

# ---------- 6. uaf_write (arm32): 大块 free→munmap 后悬垂写 ----------
cat > $CS/uaf_write.c <<'EOF'
/* BMC 风格：FRU 固件镜像大缓冲 free 后（mmap chunk 直接 munmap），
   热升级路径仍持有旧指针继续写 → 写已解除映射区域 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FW_IMG_SIZE  (8 * 1024 * 1024)  /* 8MB：远超 mmap 阈值上限，任何架构都走 mmap */

static char *g_fw_img;

static int fw_load_image(void)
{
    g_fw_img = malloc(FW_IMG_SIZE);
    if (!g_fw_img) return -1;
    memset(g_fw_img, 0, FW_IMG_SIZE);
    return 0;
}

static void fw_release_image(void)
{
    free(g_fw_img);                     /* mmap chunk → munmap，地址段解除映射 */
    g_fw_img = NULL;
}

static int fw_hotfix_patch(char *img, int off)
{
    /* BUG: 传入的是热升级前的旧指针（已 munmap） */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(img + off));
    img[off] = 0x5a;                    /* 崩溃行: 写已解除映射地址 */
    return 0;
}

static int fw_hotfix_apply(char *old_img)
{
    return fw_hotfix_patch(old_img, 0x100);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    if (fw_load_image() != 0) return 1;
    char *old = g_fw_img;
    fw_release_image();                 /* 释放后 old 悬垂 */
    return fw_hotfix_apply(old);
}
EOF

# ---------- 7. oob_read (riscv64): 报文字段偏移未校验大越界读 ----------
cat > $CS/oob_read.c <<'EOF'
/* BMC 风格：IPMI 报文按字段字节计算页粒度偏移，未校验直接读 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ipmi_msg {
    unsigned char netfn;
    unsigned char cmd;
    unsigned char data_len;
    unsigned char pad;
    unsigned char payload[16];
};

static int sdr_read_at(const struct ipmi_msg *m, int k)
{
    int idx = (m->data_len << 16) + k;  /* BUG: 64K 粒度放大且无校验（15MB 远超堆区） */
    volatile unsigned char v = m->payload[idx];   /* 崩溃行: 远超堆块 */
    return v;
}

static int sdr_decode(const struct ipmi_msg *m)
{
    int total = 0;
    for (int k = 0; k < 4; k++)
        total += sdr_read_at(m, k);
    return total;
}

static int ipmi_dispatch(const struct ipmi_msg *m)
{ return sdr_decode(m); }

int main(void)
{
    struct ipmi_msg *m = malloc(sizeof *m);
    memset(m, 0xee, sizeof *m);
    m->data_len = 0xF0;                 /* idx 最大 0xF00003 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)&m->payload[0xF00003]);
    setvbuf(stderr, NULL, _IONBF, 0);
    return ipmi_dispatch(m) & 1;
}
EOF

# ---------- 8. bad_funcptr (arm64): 中断残留写坏操作表函数指针 ----------
cat > $CS/bad_funcptr.c <<'EOF'
/* BMC 风格：串口中断处理使用了未初始化的栈寄存器残留，写坏操作表函数指针 */
#include <stdio.h>

struct uart_ops {
    int (*init)(void);
    int (*putc)(int c);
    int (*getc)(void);
    void (*flush)(void);
};

static int uart_mmio_init(void) { return 0; }
static int uart_mmio_getc(void) { return -1; }
static void uart_mmio_flush(void) { }

static struct uart_ops g_ops = {
    uart_mmio_init, NULL /* 由探测填充 */, uart_mmio_getc, uart_mmio_flush
};

static int uart_isr_dirty_write(void)
{
    /* 模拟：中断处理拿了未初始化寄存器当函数指针写回操作表 */
    unsigned long junk;
    __asm__ volatile ("" : "=r"(junk) : "0"(0xdead0000UL));
    g_ops.putc = (int (*)(int))junk;
    return 0;
}

static int uart_poll_input(void)
{
    return g_ops.putc('x');             /* 崩溃行: pc=0xdead0000 */
}

static int console_service(void)
{
    uart_isr_dirty_write();
    return uart_poll_input();
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return console_service();
}
EOF

# ---------- 9. stack_smash (arm64): 日志缓冲溢出覆盖 LR，断链 ----------
cat > $CS/stack_smash.c <<'EOF'
/* BMC 风格：日志格式化缓冲溢出覆盖保存的 FP/LR，返回后跳飞。
   各层 noinline 固定帧形态，跨拷贝长度恒为 0x180（160 缓冲 + 填充 +
   保存区），任何优化级别下机制一致；volatile 逐字节绕开 memcpy/_chk 加固 */
#include <stdio.h>

static const char g_payload[0x180] = {
    [0 ... 0x17f] = 0x57                /* 'W' 填充：可 grep 的踩写痕迹 */
};

__attribute__((noinline))
static int log_format(char *out)
{
    volatile char *vo = out;
    for (unsigned i = 0; i < sizeof g_payload; i++)   /* BUG: 无容量限制 */
        vo[i] = g_payload[i];
    return 0;
}

__attribute__((noinline))
static int klog_emit(void)
{
    char line[160];
    log_format(line);                   /* 溢出覆盖本帧保存的 FP/LR */
    return fputs(line, stderr) < 0;     /* 不再到达 */
}

__attribute__((noinline))
static int klog_warning(void)
{ return klog_emit(); }

__attribute__((noinline))
static int sensor_report_timeout(const char *sens)
{
    (void)sens;
    return klog_warning();
}

__attribute__((noinline))
static int watchdog_prelude(void)
{ return sensor_report_timeout("cpu0_temp"); }

int main(void)
{
    return watchdog_prelude();
}
EOF

# ---------- 10. assert_fail (arm32, arm 模式): assert 触发 abort ----------
cat > $CS/assert_fail.c <<'EOF'
/* BMC 风格：开机枚举 fru 数量超出固件上限，防御性 assert */
#include <assert.h>

#define MAX_FRU 8

struct fru_desc { int bus; int addr; };

static const struct fru_desc g_scan_tab[] = {
    { 0, 0x20 }, { 3, 0x58 }, { 3, 0x59 }, { 4, 0x2c }, { 4, 0x2d },
    { 5, 0x22 }, { 6, 0x6a }, { 6, 0x6b }, { 7, 0x50 }, { 7, 0x51 },
};
#define NSCAN (sizeof g_scan_tab / sizeof g_scan_tab[0])

static int fru_cache_idx[MAX_FRU];
static int fru_cache_n;

static int fru_cache_add(int i)
{
    assert(fru_cache_n < MAX_FRU);      /* 崩溃行: 第 9 个 fru 触发 abort */
    fru_cache_idx[fru_cache_n++] = i;
    return 0;
}

static int fru_enumerate(void)
{
    for (unsigned i = 0; i < NSCAN; i++)
        if (fru_cache_add(i) != 0) return -1;
    return 0;
}

static int fru_service_start(void)
{ return fru_enumerate(); }

int main(void)
{
    return fru_service_start();
}
EOF

# ---------- 11. thread_crash (arm64): 多线程工作线程空指针崩溃 ----------
cat > $CS/thread_crash.c <<'EOF'
/* BMC 风格：3 个 sensor 轮询线程 + 主线程 join，线程 1 掉线后空指针崩溃 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

struct sensor_ctx {
    int id;
    int *shared_reading;        /* 掉线后为 NULL */
};

static struct sensor_ctx g_ctx[3];

static int sensor_sample_one(struct sensor_ctx *c)
{
    if (!c->shared_reading)
        fprintf(stderr, "FAULT_ADDR=%p\n", (void *)c->shared_reading);
    *c->shared_reading = (c->id + 1) * 100;      /* 崩溃行 */
    return 0;
}

static int sensor_poll_once(struct sensor_ctx *c)
{ return sensor_sample_one(c); }

static void *worker(void *arg)
{
    struct sensor_ctx *c = arg;
    for (int i = 0; i < 1000; i++) {
        usleep(200);
        if (sensor_poll_once(c) != 0) return NULL;
    }
    return NULL;
}

int main(void)
{
    pthread_t th[3];
    int share[3] = { 0, 0, 0 };
    for (int i = 0; i < 3; i++) {
        g_ctx[i].id = i;
        g_ctx[i].shared_reading = &share[i];
    }
    g_ctx[1].shared_reading = NULL;      /* sensor1 掉线 */
    for (int i = 0; i < 3; i++)
        pthread_create(&th[i], NULL, worker, &g_ctx[i]);
    for (int i = 0; i < 3; i++)
        pthread_join(th[i], NULL);
    return 0;
}
EOF

# ---------- 12. shlib_crash (arm64): 崩溃在自编共享库 libsensord.so 内 ----------
cat > $CS/shlib_main.c <<'EOF'
/* 主程序：调用 libsensord.so 的读数接口 */
#include <stdio.h>
#include <sensord.h>

static int thermal_check(void)
{
    struct sensor_reading r;
    int rc = sensord_get_reading("psu0", &r);   /* psu0 未注册 */
    return rc;
}

static int thermal_guard(void)
{ return thermal_check(); }

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    if (sensord_init(4) != 0) return 1;
    int r = thermal_guard();
    sensord_shutdown();
    return r;
}
EOF

cat > $CS/sensord.c <<'EOF'
/* libsensord.so：sensor 管理与读数 */
#include <stdio.h>
#include <string.h>
#include <sensord.h>

struct sens_node {
    char name[16];
    int  (*read_raw)(struct sens_node *);
    int  cached;
};

static struct sens_node g_nodes[4];
static int g_nnode;

static struct sens_node *find(const char *name)
{
    for (int i = 0; i < g_nnode; i++)
        if (strcmp(g_nodes[i].name, name) == 0) return &g_nodes[i];
    return NULL;
}

int sensord_init(int max)
{
    for (int i = 0; i < max && i < 4; i++)
        snprintf(g_nodes[i].name, sizeof g_nodes[i].name, "cpu%d", i);
    g_nnode = max > 4 ? 4 : max;
    return 0;
}

static int read_raw_i2c(struct sens_node *n)
{ (void)n; return 42; }

int sensord_get_reading(const char *name, struct sensor_reading *out)
{
    struct sens_node *n = find(name);   /* psu0 未注册 → NULL，老版本无判空 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)n);
    n->read_raw = read_raw_i2c;         /* 崩溃行: NULL 写 */
    out->value = n->read_raw(n);
    out->status = 0;
    return 0;
}

void sensord_shutdown(void) { g_nnode = 0; }
EOF

cat > $CS/sensord.h <<'EOF'
#ifndef SENSORD_H
#define SENSORD_H
struct sensor_reading { int value; int status; };
int sensord_init(int max);
int sensord_get_reading(const char *name, struct sensor_reading *out);
void sensord_shutdown(void);
#endif
EOF

echo "== cases written =="
ls -la $CS

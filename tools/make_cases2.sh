#!/usr/bin/env bash
# 新增 8 个更高难度维度的案例源码
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 13. ill_jump: 跳入垃圾指令 → SIGILL（新信号维度） ----------
cat > $CS/ill_jump.c <<'EOF'
/* BMC 风格：升级流程把"固件镜像字节"当作函数指针调用，跳入非法指令 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static const unsigned char g_img_code[16] = {
#if defined(__aarch64__)
    0x00, 0x00, 0x00, 0x00,        /* UDF #0 → SIGILL */
#elif defined(__riscv)
    0x00, 0x00, 0x00, 0x00,        /* opcode 0 非法 → SIGILL */
#elif defined(__arm__)
    0xf0, 0x01, 0xf0, 0xe7,        /* 0xE7F001F0 permanently undefined */
#else
    0xff, 0xff, 0xff, 0xff,
#endif
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

typedef int (*entry_fn)(void);

static int fw_stage_load(entry_fn *out)
{
    void *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -1;
    memcpy(p, g_img_code, sizeof g_img_code);
    __builtin___clear_cache((char *)p, (char *)p + 16);
    *out = (entry_fn)p;
    fprintf(stderr, "FAULT_ADDR=%p\n", p);
    return 0;
}

static volatile int g_boot_rc;

static int fw_verify_and_boot(entry_fn entry)
{
    /* BUG: 镜像校验缺省，非法指令字节被当入口直接执行 */
    int rc = entry();                     /* 崩溃行: SIGILL, pc=镜像页 */
    g_boot_rc = rc;                       /* volatile 后置动作：防 -O1 尾调用吞帧 */
    return rc;
}

static int fw_upgrade_main(void)
{
    entry_fn e = NULL;
    if (fw_stage_load(&e) != 0) return -1;
    return fw_verify_and_boot(e);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return fw_upgrade_main();
}
EOF

# ---------- 14. null_poison: 单字节 NUL 溢出堆投毒（更高难度堆维度） ----------
cat > $CS/null_poison.c <<'EOF'
/* BMC 风格：审计日志拷贝恰好多写一个 NUL，投毒下一 chunk 的 size 低位 */
#include <stdlib.h>
#include <string.h>

struct log_rec {
    char msg[0xf8 - 8];       /* usable 0xf8, chunk 0x100 */
    int  seq;
};

static struct log_rec *g_a, *g_b;

static int log_append(struct log_rec *r, const char *s)
{
    /* BUG: 目标按 0xf8 申请，拷贝长度按源串 0xf8+1（含结尾 NUL） */
    memcpy(r->msg, s, 0xf8);
    /* 越界清 9 字节：32 位布局 size LSB 在 +0xfc、64 位在 +0xf8，一并覆盖 */
    memset(&r->msg[0xf8], 0, 9);      /* 投毒 g_b chunk 头：size 0x111→0x100 等 */
    return 0;
}

static int log_boot(void)
{
    char long_msg[0x108];
    memset(long_msg, 'L', sizeof long_msg - 1);
    long_msg[sizeof long_msg - 1] = 0;

    /* 先占满 tcache[0x100]（7 个），让后续 free(g_b) 无法走 tcache 快速路径，
       必须进入合并/校验路径从而检测到被投毒的 size */
    static struct log_rec *filler[7];
    for (int i = 0; i < 7; i++) filler[i] = malloc(0xf8);

    g_a = malloc(0xf8);
    g_b = malloc(0x108);      /* chunk 0x110, size 字段 = 0x111 */
    if (!g_a || !g_b) return -1;
    for (int i = 0; i < 7; i++) free(filler[i]);   /* tcache 填满 */

    /* 模拟 g_b 曾被使用过、内部残留 0xff 数据（决定 free 走查读到的 next size） */
    memset(g_b, 0xff, 0x108);
    g_b->seq = 2;

    log_append(g_a, long_msg);       /* 投毒：g_b size 0x111→0x100 */
    return 0;
}

static int log_flush(void)
{
    free(g_b);               /* 崩溃点: size 已被投毒 → glibc 检测 abort */
    free(g_a);
    return 0;
}

int main(void)
{
    if (log_boot() != 0) return 1;
    return log_flush();
}
EOF

# ---------- 15. uaf_reuse: UAF + 堆复用类型混淆（悬垂写踩新对象回调） ----------
cat > $CS/uaf_reuse.c <<'EOF'
/* BMC 风格：会话对象释放后内存立即被复用为消息对象，
   旧路径的悬垂写踩掉新对象回调指针，调用时跳飞 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session {             /* 16 字节 */
    int (*on_event)(struct session *, int);
    int sess_id;
};

struct netmsg {              /* 16 字节，同 tcache bin */
    void (*volatile dispatch)(void);   /* volatile：-O1 前向传播会绕过悬垂写 */
    int len;
};

static struct session *g_sess;

static int session_on_event(struct session *s, int ev)
{ (void)s; return ev; }

static int session_open(int id)
{
    g_sess = malloc(sizeof *g_sess);
    g_sess->on_event = session_on_event;
    g_sess->sess_id = id;
    return 0;
}

static void session_close(void)
{
    free(g_sess);            /* 释放进入 tcache */
    /* BUG: 未置 NULL，旧指针仍将被使用 */
}

static struct netmsg *netmsg_alloc(int len)
{
    struct netmsg *m = malloc(sizeof *m);   /* 立即复用同一块内存 */
    m->dispatch = NULL;
    m->len = len;
    return m;
}

static int session_notify_legacy(int ev)
{
    /* 旧代码路径：拿着悬垂指针写回调 —— 踩掉 netmsg->dispatch。
       volatile 写：-O1 会据 malloc 不相交支配性把该越界写前向传播掉 */
    ((volatile struct session *)g_sess)->on_event =
        (int (*)(struct session *, int))0x52500000UL;
    return ev;
}

static int netmsg_pump(struct netmsg *m)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)m->dispatch);
    m->dispatch();           /* 崩溃行: pc=0x52500000 */
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    if (session_open(7) != 0) return 1;
    session_close();
    struct netmsg *m = netmsg_alloc(64);
    session_notify_legacy(1);   /* 悬垂写 */
    return netmsg_pump(m);
}
EOF

# ---------- 16. deep_chain: 12 层深调用链后空指针（深回溯维度） ----------
cat > $CS/deep_chain.c <<'EOF'
/* BMC 风格：Redfish 请求处理层层转发 12 层后落到未初始化的芯片句柄上 */
#include <stdio.h>

struct chip_ctx {
    int node_id;
    volatile unsigned int *doorbell;
};

static int svc_l0(struct chip_ctx *c)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)&c->doorbell);
    c->doorbell = (volatile unsigned int *)1;   /* 崩溃行 */
    return 0;
}
static int svc_l1(struct chip_ctx *c) { return svc_l0(c) + 1; }
static int svc_l2(struct chip_ctx *c) { return svc_l1(c) + 1; }
static int svc_l3(struct chip_ctx *c) { return svc_l2(c) + 1; }
static int svc_l4(struct chip_ctx *c) { return svc_l3(c) + 1; }
static int svc_l5(struct chip_ctx *c) { return svc_l4(c) + 1; }
static int svc_l6(struct chip_ctx *c) { return svc_l5(c) + 1; }
static int svc_l7(struct chip_ctx *c) { return svc_l6(c) + 1; }
static int svc_l8(struct chip_ctx *c) { return svc_l7(c) + 1; }
static int svc_l9(struct chip_ctx *c) { return svc_l8(c) + 1; }
static int svc_l10(struct chip_ctx *c) { return svc_l9(c) + 1; }
static int svc_l11(struct chip_ctx *c) { return svc_l10(c) + 1; }
static int svc_l12(struct chip_ctx *c) { return svc_l11(c) + 1; }

static int rest_dispatch(struct chip_ctx *c)
{ return svc_l12(c); }

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    struct chip_ctx *ctx = NULL;   /* 探测失败时句柄未初始化 */
    return rest_dispatch(ctx) & 1;
}
EOF

# ---------- 17. hugespan: 单帧巨栈一步跨过栈底（非递归栈溢出） ----------
cat > $CS/hugespan.c <<'EOF'
/* BMC 风格：一次性构造超大诊断帧（6MB+），一步把 SP 拉过栈底保护页 */
#include <string.h>

static int diag_collect_frame(void)
{
    char blob[12 * 1024 * 1024 + 32768];  /* 单帧 12MB，远超 8MB 栈上限 */
    /* volatile 逐字节触写：防止 -O1 死存储消除把 memset 缩成单字节 */
    volatile char *vb = blob;
    for (unsigned long i = 0; i < sizeof blob; i++)
        vb[i] = (char)0xA5;               /* 崩溃行: 首次触写即越保护页 */
    return blob[0];
}

static int diag_run_once(void)
{ return diag_collect_frame(); }

int main(void)
{
    return diag_run_once() & 1;
}
EOF

# ---------- 18. dlopen_crash: 运行时加载插件内崩溃（动态装载维度） ----------
cat > $CS/plug_main.c <<'EOF'
/* 主程序：dlopen 加载诊断插件，dlsym 取入口后调用（句柄未探测成功仍调用） */
#include <stdio.h>
#include <dlfcn.h>

typedef int (*plug_run_fn)(void *cfg);

static int diag_call_plugin(plug_run_fn fn, void *cfg)
{
    return fn(cfg);                       /* 崩溃发生在插件内 */
}

static int diag_try_plugin(const char *path)
{
    void *h = dlopen(path, 2 /*RTLD_NOW*/);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return -1;
    }
    plug_run_fn fn = (plug_run_fn)dlsym(h, "plug_run");
    if (!fn) return -1;
    /* BUG: 配置探测失败返回 NULL 却仍调用插件 */
    void *cfg = NULL;
    return diag_call_plugin(fn, cfg);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return diag_try_plugin("/tmp/coredump_work/build/libplug.so");
}
EOF

cat > $CS/plugin.c <<'EOF'
/* libplug.so：诊断插件 */
#include <stdio.h>

struct plug_cfg {
    int mode;
    int retries;
};

int plug_run(void *cfg)
{
    struct plug_cfg *c = (struct plug_cfg *)cfg;
    fprintf(stderr, "FAULT_ADDR=%p\n", c);
    c->mode = 3;                          /* 崩溃行: NULL 写（在 so 内） */
    return c->retries;
}
EOF

# ---------- 19. handler_crash: 信号处理函数内二次崩溃 ----------
cat > $CS/handler_crash.c <<'EOF'
/* BMC 风格：SIGSEGV 处理函数里打印现场时又踩空指针（嵌套故障） */
#include <stdio.h>
#include <signal.h>

static void crash_handler(int sig)
{
    (void)sig;
    volatile unsigned long *fault_ctx = (volatile unsigned long *)0;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)fault_ctx);
    *fault_ctx = 0xC0DE;      /* 崩溃行: 处理函数内再次空指针写 → 内核默认动作转储 */
}

static int board_probe_mmio(void)
{
    volatile unsigned int *status = (volatile unsigned int *)0x10;
    return *status;           /* 首次故障进入 handler */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGSEGV, crash_handler);
    return board_probe_mmio() & 1;
}
EOF

# ---------- 20. blame_thread: 肇事线程 ≠ 崩溃线程（多线程堆破坏取证） ----------
cat > $CS/blame_thread.c <<'EOF'
/* BMC 风格：worker0 越界写穿相邻 chunk 头，worker1 随后 free 暴雷
   —— 崩溃线程是受害者，肇事在另一个线程 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

struct bulk {
    char data[0xf8 - 8];
    int id;
};

static struct bulk *g_a, *g_b;
static volatile int g_poisoned;

static void *writer_thread(void *arg)
{
    (void)arg;
    usleep(1000);
    /* BUG: 拷贝长度超出本 chunk，写穿 g_b 的 chunk 头（'B' 填充） */
    memset(g_a->data, 'B', 0xf8 + 24);
    g_poisoned = 1;
    return NULL;
}

static void *reaper_thread(void *arg)
{
    (void)arg;
    while (!g_poisoned)
        usleep(200);
    free(g_b);                /* 崩溃点: 在本线程检测到堆损坏 abort */
    return NULL;
}

static int storage_service_start(void)
{
    g_a = malloc(0xf8);
    g_b = malloc(0xf8);
    if (!g_a || !g_b) return -1;
    g_a->id = 1; g_b->id = 2;

    pthread_t tw, tr;
    pthread_create(&tw, NULL, writer_thread, NULL);
    pthread_create(&tr, NULL, reaper_thread, NULL);
    pthread_join(tw, NULL);
    pthread_join(tr, NULL);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return storage_service_start();
}
EOF

echo "== new cases written =="
ls -la $CS | tail -12

#!/usr/bin/env bash
# 批次 3：BMC/OpenBMC 特定维度 9 例（#65~#73）
# IPMI 报文越界/FRU 损坏/sensor 热插拔/I2C 超时旧缓存/D-Bus 属性 UAF/
# 电源切换上下文/SEL 写满/shm_unlink 后访问/FIFO 对端退出 SIGPIPE
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 65. ipmi_parse_overflow: crafted 报文长度字段越界 ----------
cat > $CS/ipmi_parse_overflow.c <<'EOF'
/* BUG: IPMI 解析器信任报文自带的数据长度字段——crafted 报文声明
   0x400 字段数, 跨步 4 的字段扫描冲出缓冲页 → SEGV */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

static volatile uint32_t g_req_len = 0x420u;   /* crafted: 字段数 */

__attribute__((noinline))
static long ipmi_parse_cmd(const uint8_t *req, uint32_t nfields)
{
    long sum = 0;
    uint32_t off = 3;                      /* netfn+cmd+seq 头 */
    for (uint32_t f = 0; f < nfields; f++) {
        sum += req[off + f * 4];           /* 崩溃行: 跨步扫出缓冲 */
        sum &= 0xffffff;
    }
    return sum;
}

__attribute__((noinline))
static int ipmi_recv(const uint8_t *req)
{
    return (int)(ipmi_parse_cmd(req, g_req_len) & 1);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    /* 3 页保护区: [NONE][数据 RW][NONE]——越界一步即触碰保护页 */
    uint8_t *guard = mmap(NULL, 3 * 4096, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED) return 1;
    uint8_t *req = guard + 4096;
    if (mprotect(req, 4096, PROT_READ | PROT_WRITE) != 0) return 1;
    memset(req, 0x11, 4096);
    req[0] = 0x06; req[1] = 0x01; req[2] = 0x00;   /* 假 IPMI 头 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(req + 0x1003));
    volatile int rc = ipmi_recv(req);
    return rc & 1;
}
EOF

# ---------- 66. fru_corrupt_parse: FRU 区域长度字段损坏 0xFFFF ----------
cat > $CS/fru_corrupt_parse.c <<'EOF'
/* BUG: FRU 二进制的 area 长度字段损坏为 0xFFFF——解析器累加步进
   直接跳出映射 → SEGV */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

__attribute__((noinline))
static long fru_walk_area(const uint8_t *fru)
{
    long sum = 0;
    uint32_t off = 0;
    for (int a = 0; a < 6; a++) {
        uint8_t type = fru[off];
        uint16_t alen = (uint16_t)(fru[off + 1] | (fru[off + 2] << 8));
        sum += type;
        off += 3u + alen;                  /* 损坏值: 一次跳出 64KB */
    }
    /* 逐页走查(首探即越过映射的架构直接踩空; 相邻有映射的布局
       继续上行, 直到第一个未映射页) */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(fru + off));
    for (;;)
        sum += *(const volatile uint8_t *)(fru + off), off += 4096u;   /* 崩溃行 */
}

__attribute__((noinline))
static int fru_inventory_load(const uint8_t *fru)
{
    return (int)(fru_walk_area(fru) & 1);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    uint8_t *fru = mmap(NULL, 3 * 4096, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fru == MAP_FAILED) return 1;
    if (mprotect(fru + 4096, 4096, PROT_READ | PROT_WRITE) != 0) return 1;
    fru += 4096;
    memset((void *)fru, 0, 4096);
    fru[0] = 0x01; fru[1] = 0xFF; fru[2] = 0xFF;   /* 损坏: len=0xFFFF */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(fru + 0x10002));
    volatile int rc = fru_inventory_load(fru);
    return rc & 1;
}
EOF

# ---------- 67. sensor_hotplug: 拔出后 re-activate 用悬垂句柄 ----------
cat > $CS/sensor_hotplug.c <<'EOF'
/* BUG: sensor 拔出时释放设备对象, 热插拔缓存里的活跃句柄没有失效
   ——re-activate 拿悬垂句柄递增计数（对象为 mmap 大块, free 即 munmap） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sensor_dev {
    volatile long id;
    char pad[(1u << 20) - sizeof(long)];
};

static struct sensor_dev *g_active;        /* 热插拔缓存句柄 */

__attribute__((noinline))
static void sensor_hotplug_remove(struct sensor_dev **slot)
{
    free(*slot);                           /* 拔出: 大块 free → munmap */
    *slot = NULL;
}

__attribute__((noinline))
static int sensor_reactivate(struct sensor_dev *cached)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)cached);
    cached->id++;                          /* 崩溃行: 悬垂句柄解引用 */
    return 1;
}

__attribute__((noinline))
static int sensor_mgr_replug(struct sensor_dev *dev)
{
    sensor_hotplug_remove(&dev);
    return sensor_reactivate(g_active);    /* BUG: 缓存未随拔出失效 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    struct sensor_dev *dev = calloc(1, sizeof *dev);
    if (!dev) return 1;
    dev->id = 7;
    g_active = dev;
    return sensor_mgr_replug(dev) & 1;
}
EOF

# ---------- 68. i2c_timeout_stale: I2C 超时返回旧缓存悬垂指针 ----------
cat > $CS/i2c_timeout.c <<'EOF'
/* BUG: I2C 总线故障恢复路径释放了读取缓存, 但超时的 i2c_read_regs
   仍返回旧缓存指针——调用方按 8 寄存器批量读取踩 munmap 内存 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint8_t *g_cache;                   /* I2C 读取缓存 */

__attribute__((noinline))
static int i2c_read_regs(uint8_t *out, int n)
{
    /* 模拟: 传输超时, 返回缓存的旧数据指针内容 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)g_cache);
    for (int i = 0; i < n; i++)
        out[i] = g_cache[i];               /* 崩溃行: 缓存已 munmap */
    return n;
}

__attribute__((noinline))
static void i2c_bus_recover(void)
{
    free(g_cache);                         /* BUG: 超时恢复释放缓存,
                                              读路径还在用它 */
}

__attribute__((noinline))
static int thermal_update(void)
{
    uint8_t regs[8];
    return i2c_read_regs(regs, 8);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_cache = malloc(1u << 20);            /* 1MB: mmap 直供 */
    if (!g_cache) return 1;
    memset(g_cache, 0x22, 1u << 20);
    i2c_bus_recover();
    volatile int rc = thermal_update();
    return rc & 1;
}
EOF

# ---------- 69. dbus_prop_crash: D-Bus 属性 setter 内 UAF ----------
cat > $CS/dbus_prop_crash.c <<'EOF'
/* BUG: D-Bus 连接断开时释放属性对象, 但已在队列中的属性设置请求
   照常派发——setter 写已 free 的大块对象（munmap）→ SEGV */
#include <stdio.h>
#include <stdlib.h>

struct prop_obj {
    volatile long refcount;
    char pad[(1u << 20) - sizeof(long)];
};

static struct prop_obj *g_obj;

__attribute__((noinline))
static void dbus_prop_set(struct prop_obj *o, long v)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)o);
    o->refcount = v;                       /* 崩溃行: 对象已 munmap */
}

__attribute__((noinline))
static int dbus_method_dispatch(struct prop_obj *o)
{
    dbus_prop_set(o, 2);
    return 0;
}

__attribute__((noinline))
static void dbus_conn_drop(void)
{
    free(g_obj);                           /* BUG: 在途请求未排空 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_obj = calloc(1, sizeof *g_obj);      /* 1MB: mmap 直供 */
    if (!g_obj) return 1;
    dbus_conn_drop();
    volatile int rc = dbus_method_dispatch(g_obj);
    return rc & 1;
}
EOF

# ---------- 70. power_transition: 电源切换释放 ctx, 在途命令仍引用 ----------
cat > $CS/power_transition.c <<'EOF'
/* BUG: S0→S5 切换立即释放电源上下文（mmap 大块）, 而 S0 时代已接收
   的命令还在处理队列——命令执行路径读 ctx->state 踩 munmap 内存 */
#include <stdio.h>
#include <stdlib.h>

struct power_ctx {
    volatile int state;
    char pad[(1u << 20) - sizeof(int)];
};

static struct power_ctx *g_pctx;

__attribute__((noinline))
static int power_cmd_execute(struct power_ctx *ctx, int op)
{
    (void)op;
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)ctx);
    return ctx->state;                     /* 崩溃行: ctx 已 munmap */
}

__attribute__((noinline))
static int power_service_serve(struct power_ctx *ctx)
{
    return power_cmd_execute(ctx, 0x71);
}

__attribute__((noinline))
static void power_transition_off(void)
{
    free(g_pctx);                          /* BUG: 在途命令未排空 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_pctx = calloc(1, sizeof *g_pctx);
    if (!g_pctx) return 1;
    g_pctx->state = 0;                     /* S0 */
    power_transition_off();                /* 切 S5: ctx 释放 */
    volatile int rc = power_service_serve(g_pctx);
    return rc & 1;
}
EOF

# ---------- 71. sel_full_error: SEL 写满错误路径返回 NULL 未判空 ----------
cat > $CS/sel_full_error.c <<'EOF'
/* BUG: SEL 存储写满时分配函数返回 NULL, 提交路径不查错直接写
   记录字段 → NULL+偏移 写 */
#include <stdio.h>

struct sel_entry {
    long ts;
    int type;
};

static volatile int g_sel_full = 1;        /* 存储已写满 */

__attribute__((noinline))
static struct sel_entry *sel_alloc(void)
{
    if (g_sel_full)
        return NULL;                       /* 写满: 分配失败 */
    static struct sel_entry e;
    return &e;
}

__attribute__((noinline))
static int sel_commit_record(long ts)
{
    struct sel_entry *e = sel_alloc();
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)e);
    e->ts = ts;                            /* 崩溃行: NULL->ts 写 */
    e->type = 1;
    return 0;
}

__attribute__((noinline))
static int sel_log_event(long ts)
{
    return sel_commit_record(ts);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return sel_log_event(1770000000L) & 1;
}
EOF

# ---------- 72. shm_unlink_alive: shm_unlink+截断后已 attach 进程访问 → SIGBUS ----------
cat > $CS/shm_unlink_alive.c <<'EOF'
/* BUG: 共享内存对象被"部署脚本"进程 unlink 并收缩, 仍 attach 的采集进程
   继续按原大小远端读取 → 落到截断空洞上 SIGBUS
   （生成环境用 /tmp 常规文件承载共享对象语义：qemu 对 /dev/shm 截断区的
   gcore 读取会拖死仿真器） */
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

static const char *SHM_PATH = "/tmp/bmc_sel_shm.bin";
static const char *SHM_ARCHIVED = "/tmp/bmc_sel_shm.archived";
static const char *FLAG_PARENT = "/tmp/bmc_shmflag_parent.flag";
static const char *FLAG_CHILD = "/tmp/bmc_shmflag_child.flag";

__attribute__((noinline))
static int shm_far_read(volatile uint8_t *m, size_t off)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(m + off));
    return m[off];                         /* 崩溃行: 文件已收缩 → SIGBUS */
}

__attribute__((noinline))
static int shm_archive_sweep(volatile uint8_t *m)
{
    return shm_far_read(m, 0x3800);        /* 旧布局的末条记录 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    int fd;
    uint8_t *m;
    pid_t pid;

    unlink(SHM_PATH);
    unlink(FLAG_PARENT);
    unlink(FLAG_CHILD);

    fd = open(SHM_PATH, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) return 1;
    if (ftruncate(fd, 0x4000) != 0) return 1;
    m = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) return 1;
    memset(m, 0x33, 0x4000);               /* 旧版完整布局 */

    pid = fork();
    if (pid == 0) {                        /* 子进程模拟部署脚本 */
        int cfd;
        for (;;) {
            cfd = open(SHM_PATH, O_RDWR);
            if (cfd >= 0) break;
            usleep(10000);
        }
        unlink(SHM_ARCHIVED);
        if (getenv("BMC_QEMU_EPIPE_PROBE")) {
            /* qemu 生成环境: unlink 会使 gcore 读取孤儿 inode 截断区时
               击杀仿真器——以 rename 移除对象名等价实现 */
            rename(SHM_PATH, SHM_ARCHIVED);
        } else {
            unlink(SHM_PATH);              /* 真机: 直接移除对象名 */
        }
        ftruncate(cfd, 0x100);             /* 内容收缩(精简版) */
        close(cfd);
        creat(FLAG_CHILD, 0600);
        _exit(0);
    }
    creat(FLAG_PARENT, 0600);
    for (;;)
        if (access(FLAG_CHILD, F_OK) == 0) break;
    usleep(50000);
    { volatile int rc = shm_archive_sweep(m); (void)rc; }
    waitpid(pid, NULL, 0);
    return 0;
}
EOF

# ---------- 73. fifo_sigpipe: FIFO 读端退出后写端写入 → SIGPIPE ----------
cat > $CS/fifo_sigpipe.c <<'EOF'
/* BUG: 采集端(reader)崩溃退出后, 日志端(writer)仍向 FIFO 写——写入即
   SIGPIPE（默认终止）。
   注: qemu-user 下宿主 SIGPIPE 不可被 stub 拦截，生成环境经
   ipc_sigpipe_default 断点取核并注入信号现场；真机上 write 即崩溃点 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/wait.h>

static const char *FIFO_PATH = "/tmp/bmc_vlog.fifo";
static const char *FLAG_R = "/tmp/bmc_fifo_r.flag";
static const char *FLAG_W = "/tmp/bmc_fifo_w.flag";

__attribute__((noinline))
static void ipc_sigpipe_default(void)
{
    raise(SIGPIPE);                        /* 内核对无 handler 写者的默认动作 */
}

__attribute__((noinline))
static int log_tail_flush(int fd)
{
    static const char payload[4096] = "vlog";
    int rc;
    if (getenv("BMC_QEMU_EPIPE_PROBE")) {
        /* qemu 生成环境: 宿主 SIGPIPE 不可被 stub 拦截——poll 探测对端消失 */
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        poll(&pfd, 1, 0);
        rc = (pfd.revents & POLLERR) ? -1 : 0;
    } else {
        rc = (int)write(fd, payload, sizeof payload);   /* 真机崩溃点: SIGPIPE */
    }
    if (rc < 0)
        ipc_sigpipe_default();             /* EPIPE → SIGPIPE 终止 */
    return rc;
}

__attribute__((noinline))
static int log_flush_cycle(int fd)
{
    return log_tail_flush(fd);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    pid_t pid;

    unlink(FIFO_PATH);
    unlink(FLAG_R);
    unlink(FLAG_W);
    if (mkfifo(FIFO_PATH, 0600) != 0) return 1;

    pid = fork();
    if (pid == 0) {                        /* 采集端: 开读后立即退出 */
        int rfd;
        for (;;) {
            rfd = open(FIFO_PATH, O_RDONLY);
            if (rfd >= 0) break;
            usleep(10000);
        }
        creat(FLAG_R, 0600);
        for (;;)
            if (access(FLAG_W, F_OK) == 0) break;
        close(rfd);                        /* 采集端退出, 读端消失 */
        _exit(0);
    }
    {   /* 日志端: 等 reader 就位再开写端(阻塞语义) */
        int wfd;
        for (;;) {
            wfd = open(FIFO_PATH, O_WRONLY);
            if (wfd >= 0) break;
            usleep(10000);
        }
        creat(FLAG_W, 0600);
        usleep(300000);                    /* 确保 reader 已退出 */
        { volatile int rc = log_flush_cycle(wfd); (void)rc; }
    }
    waitpid(pid, NULL, 0);
    return 0;
}
EOF

echo "batch3: 9 cases written"

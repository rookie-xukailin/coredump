#!/usr/bin/env bash
# 批次 4：消息队列维度 5 例（#74~#78）
# POSIX mqueue×3（异步通知UAF/接收截断/反序列化越界）+ System V×1
# （IPC_RMID 后返回值误用）+ 自研环形队列×1（满判断缺失）
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 74. mq_consumer_uaf: 队列消费者线程阻塞接收, 停止路径先 free ctx ----------
cat > $CS/mq_consumer_uaf.c <<'EOF'
/* BUG: 消费者线程阻塞在 mq_receive 上等消息；服务停止路径先 free 了
   队列处理上下文（mmap 大块 → munmap）再投递唤醒消息——消费者醒来后
   按事件处理路径访问悬垂 ctx。
   注: qemu-user 未实现 mq_notify(ENOSYS)，通知语义以阻塞消费者实现 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mqueue.h>
#include <pthread.h>
#include <unistd.h>

struct mq_ctx {
    volatile long seq;
    char pad[(1u << 20) - sizeof(long)];
};

static struct mq_ctx *g_ctx;
static mqd_t g_mq;

__attribute__((noinline))
static void mq_event_process(struct mq_ctx *ctx)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)ctx);
    ctx->seq++;                            /* 崩溃行: ctx 已 munmap */
}

__attribute__((noinline))
static void *mq_consumer(void *arg)
{
    char buf[64];
    (void)arg;
    for (;;) {
        ssize_t n = mq_receive(g_mq, buf, sizeof buf, NULL);
        if (n < 0)
            break;                         /* 队列出错/关闭 */
        mq_event_process(g_ctx);           /* 消息事件处理 */
    }
    return NULL;
}

__attribute__((noinline))
static int mq_svc_start(mqd_t mq)
{
    pthread_t tid;
    g_mq = mq;
    g_ctx = calloc(1, sizeof *g_ctx);      /* 1MB: mmap 直供 */
    if (!g_ctx) return -1;
    if (pthread_create(&tid, NULL, mq_consumer, NULL) != 0) return -1;
    usleep(200000);                        /* 等消费者进入阻塞接收 */
    return 0;
}

__attribute__((noinline))
static void mq_svc_stop(void)
{
    free(g_ctx);                           /* BUG: 消费者还挂在队列上 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    struct mq_attr attr;
    mqd_t mq;

    mq_unlink("/bmc_mq_uaf");
    attr.mq_flags = 0;
    attr.mq_maxmsg = 8;
    attr.mq_msgsize = 64;                  /* 与接收缓冲同尺寸 */
    attr.mq_curmsgs = 0;
    mq = mq_open("/bmc_mq_uaf", O_CREAT | O_RDWR, 0600, &attr);
    if (mq == (mqd_t)-1) return 1;
    if (mq_svc_start(mq) != 0) return 1;
    mq_svc_stop();                         /* 先释放处理上下文 */
    mq_send(mq, "W", 1, 0);                /* 唤醒消费者 → 踩悬垂 ctx */
    sleep(5);                              /* 等消费者线程崩溃 */
    return 0;
}
EOF

# ---------- 75. mq_recv_truncate: 接收缓冲过小 EMSGSIZE 未检查 → 残留旧消息被解析 ----------
cat > $CS/mq_recv_truncate.c <<'EOF'
/* BUG: 接收缓冲按旧版消息尺寸(8B)分配，对端升级后发送 64B 大消息——
   mq_receive 以 EMSGSIZE 拒收返回 -1，错误未检查，缓冲里残留的上一版
   消息被当作新消息解析，其长度字段指向野地址 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mqueue.h>
#include <sys/mman.h>

struct msg_hdr {
    uint32_t type;
    uint32_t len;
};

__attribute__((noinline))
static long mq_recv_parse(uint8_t *buf)
{
    uint32_t len = *(volatile uint32_t *)(buf + 4);   /* 残留的旧长度字段 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(buf + len));
    return *(volatile uint8_t *)(buf + len);          /* 崩溃行: 野偏移读取 */
}

__attribute__((noinline))
static int mq_consumer_poll(mqd_t mq, uint8_t *buf)
{
    char big[64];
    memset(big, 0x42, sizeof big);
    mq_send(mq, big, sizeof big, 1);       /* 对端: 64B 新版消息 */
    /* 接收侧按旧版 8B 缓冲收 → EMSGSIZE/-1, BUG: 不检查返回值 */
    (void)mq_receive(mq, (char *)buf, 8, NULL);
    return (int)(mq_recv_parse(buf) & 1);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    struct mq_attr attr;
    mqd_t mq;
    uint8_t *guard, *buf;

    mq_unlink("/bmc_mq_trunc");
    attr.mq_flags = 0;
    attr.mq_maxmsg = 8;
    attr.mq_msgsize = 4096;
    attr.mq_curmsgs = 0;
    mq = mq_open("/bmc_mq_trunc", O_CREAT | O_RDWR, 0600, &attr);
    if (mq == (mqd_t)-1) return 1;

    guard = mmap(NULL, 3 * 4096, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED) return 1;
    buf = guard + 4096;
    if (mprotect(buf, 4096, PROT_READ | PROT_WRITE) != 0) return 1;

    /* 播撒"上一版残留消息": type=3, len=0x77000000(过期的旧字段) */
    *(volatile uint32_t *)(buf + 0) = 3;
    *(volatile uint32_t *)(buf + 4) = 0x77000000u;
    memset(buf + 8, 0x33, 2000);

    volatile int rc = mq_consumer_poll(mq, buf);
    return rc & 1;
}
EOF

# ---------- 76. mq_deser_overflow: 消息长度字段未校验 → 反序列化拷贝越界 ----------
cat > $CS/mq_deser_overflow.c <<'EOF'
/* BUG: 消息载荷的长度字段由对端控制且未校验上限——反序列化按该长度
   向精确页缓冲拷贝，越过页边界触保护页 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mqueue.h>
#include <sys/mman.h>

struct mq_msg {
    uint32_t len;                          /* 对端控制的长度 */
    char payload[12];
};

__attribute__((noinline))
static int mq_deser_copy(uint8_t *dst, const struct mq_msg *msg)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(dst + 0x1000));
    for (uint32_t i = 0; i < msg->len; i++)           /* BUG: 无上限校验 */
        ((volatile uint8_t *)dst)[i] = (uint8_t)msg->payload[i & 11];
    return 0;                               /* 崩溃行: 越过页边界 */
}

__attribute__((noinline))
static int mq_dispatch_one(mqd_t mq, uint8_t *dst)
{
    struct mq_msg msg;
    if (mq_receive(mq, (char *)&msg, sizeof msg + 16, NULL) < 0)
        return -1;
    return mq_deser_copy(dst, &msg);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    struct mq_attr attr;
    struct mq_msg crafted;
    mqd_t mq;
    uint8_t *guard, *dst;

    mq_unlink("/bmc_mq_deser");
    attr.mq_flags = 0;
    attr.mq_maxmsg = 8;
    attr.mq_msgsize = sizeof(struct mq_msg);   /* 队列消息定长 16B */
    attr.mq_curmsgs = 0;
    mq = mq_open("/bmc_mq_deser", O_CREAT | O_RDWR, 0600, &attr);
    if (mq == (mqd_t)-1) return 1;

    memset(&crafted, 0x5A, sizeof crafted);
    crafted.len = 0x7770u;                  /* crafted: 远超一页 */
    mq_send(mq, (const char *)&crafted, sizeof crafted, 1);

    guard = mmap(NULL, 3 * 4096, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED) return 1;
    dst = guard + 4096;
    if (mprotect(dst, 4096, PROT_READ | PROT_WRITE) != 0) return 1;

    volatile int rc = mq_dispatch_one(mq, dst);
    return rc & 1;
}
EOF

# ---------- 77. msgq_rmid_race: SysV 队列被 IPC_RMID → msgrcv -1 当长度用 ----------
cat > $CS/msgq_rmid_race.c <<'EOF'
/* BUG: 管理进程 IPC_RMID 移除 System V 队列，阻塞中的 msgrcv 以 EIDRM
   返回 -1——返回值未检查被当作消息长度，负数转无符号成巨大块偏移 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLK 65536u

struct rx_msg {
    long mtype;
    char mtext[64];
};

__attribute__((noinline))
static void mq_rx_dispatch(char *base, long rc)
{
    size_t idx = (size_t)(unsigned)rc * BLK;   /* BUG: -1 → 0xFFFF0000 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(base + idx));
    base[idx] = 1;                             /* 崩溃行: 巨大块偏移 */
}

__attribute__((noinline))
static int mq_admin_wait(int qid, char *base)
{
    struct rx_msg msg;
    long rc = msgrcv(qid, &msg, sizeof msg.mtext, 0, 0);   /* 阻塞等消息 */
    mq_rx_dispatch(base, rc);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    pid_t pid;
    char *base;

    if (qid < 0) return 1;
    base = malloc(64);
    if (!base) return 1;
    base[0] = 0;

    pid = fork();
    if (pid == 0) {                        /* 管理进程: 移除整个队列 */
        usleep(200000);
        msgctl(qid, IPC_RMID, NULL);
        _exit(0);
    }
    { volatile int rc = mq_admin_wait(qid, base); (void)rc; }
    waitpid(pid, NULL, 0);
    return 0;
}
EOF

# ---------- 78. queue_ring_overrun: 自研环形队列满判断缺失 → 越界写 ----------
cat > $CS/queue_ring_overrun.c <<'EOF'
/* BUG: 自研环形队列的"满判断"在批量入队路径被绕过——生产者连续写入
   冲过数据页末尾，越过页边界触保护页
   布局: [元数据页 RW][数据页 RW][保护页 NONE] */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

struct ring_meta {
    volatile uint64_t head;
    volatile uint64_t tail;
    volatile uint64_t drops;
};

#define MSG_BYTES 64
#define DATA_SIZE 4096

__attribute__((noinline))
static void mq_ring_push(struct ring_meta *meta, uint8_t *data,
                         const void *msg)
{
    /* BUG: 高性能路径省略了满判断(应回绕或丢弃) */
    memcpy(data + meta->head, msg, MSG_BYTES);   /* 崩溃行: 越过数据页 */
    meta->head += MSG_BYTES;
}

__attribute__((noinline))
static int mq_ring_feed(struct ring_meta *meta, uint8_t *data)
{
    uint8_t msg[MSG_BYTES];
    memset(msg, 0x71, sizeof msg);
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(data + DATA_SIZE));
    for (int i = 0; i < 100; i++)                /* 64B×100 >> 4096B */
        mq_ring_push(meta, data, msg);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    uint8_t *base = mmap(NULL, 3 * 4096, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 1;
    if (mprotect(base, 2 * 4096, PROT_READ | PROT_WRITE) != 0) return 1;
    {
        struct ring_meta *meta = (struct ring_meta *)base;
        uint8_t *data = base + 4096;
        volatile int rc = mq_ring_feed(meta, data);
        (void)rc;
    }
    return 0;
}
EOF

echo "batch4: 5 message-queue cases written"

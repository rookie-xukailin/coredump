#!/usr/bin/env bash
# 第 22-27 维度：并发（线程间/进程间）资源移动/删除/修改竞态
set -e
CS=/tmp/coredump_work/cases
mkdir -p $CS

# ---------- 22. db_reload_race: 线程间 数据库热更新整表替换 ----------
cat > $CS/db_reload_race.c <<'EOF'
/* BMC 风格：sensor 数据库热更新（下载新库→换指针→清旧表→延迟回收）。
   读者线程已缓存旧表条目指针，重载完成即调用——回调已被清零 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

struct sdr_ent {
    int (*handler)(struct sdr_ent *);
    char name[12];
    int val;
};

static struct sdr_ent *g_table;
static volatile int g_reloaded;

static int sdr_default(struct sdr_ent *e)
{ return e->val; }

static void *reloader_thread(void *arg)
{
    (void)arg;
    usleep(3000);
    struct sdr_ent *fresh = calloc(8, sizeof *fresh);
    for (int i = 0; i < 8; i++) {
        strcpy(fresh[i].name, "new");
        fresh[i].handler = sdr_default;
    }
    struct sdr_ent *old = g_table;
    g_table = fresh;                        /* 换表 */
    memset(old, 0, 8 * sizeof *old);        /* 旧表清零（回调归零） */
    g_reloaded = 1;                         /* 通知读者：可以用了 */
    usleep(20000);                          /* 回收延迟（读者恰在此窗口用旧条目） */
    free(old);
    return NULL;
}

static int sdr_feed_one(struct sdr_ent *e)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(uintptr_t)e->handler);
    return e->handler(e);                   /* 崩溃行：旧条目回调已清零 */
}

static void *reader_thread(void *arg)
{
    (void)arg;
    struct sdr_ent *ent = &g_table[3];      /* 缓存条目指针 */
    while (!g_reloaded)
        usleep(300);
    return (void *)(long)sdr_feed_one(ent);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_table = calloc(8, sizeof *g_table);
    for (int i = 0; i < 8; i++) {
        strcpy(g_table[i].name, "old");
        g_table[i].handler = sdr_default;
        g_table[i].val = i;
    }
    pthread_t tr, tw;
    pthread_create(&tr, NULL, reader_thread, NULL);
    pthread_create(&tw, NULL, reloader_thread, NULL);
    pthread_join(tr, NULL);
    pthread_join(tw, NULL);
    return 0;
}
EOF

# ---------- 23. rec_delete_race: 线程间 删除单条记录 + 堆复用 ----------
cat > $CS/rec_delete_race.c <<'EOF'
/* BMC 风格：配置中心删除一条记录并释放节点；该块立即被日志缓冲复用
   （'G' 填充）。持有旧指针的读者随后调用其回调 → 跳到 0x4747… */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

struct cfg_node {
    char key[12];
    int (*on_change)(struct cfg_node *);
    int v;
};

static struct cfg_node *g_nodes[8];
static volatile int g_removed;
static volatile long g_reader_rc;

static int cfg_on_change(struct cfg_node *n)
{ return n->v; }

static void *deleter_thread(void *arg)
{
    (void)arg;
    usleep(3000);
    struct cfg_node *n = g_nodes[5];
    g_nodes[5] = NULL;
    free(n);                                /* 删除记录 */
    char *logbuf = malloc(sizeof(struct cfg_node));   /* 同尺寸复用该块 */
    /* volatile 逐字节投毒：-O1 会把 memset+读回折叠成常量、把纯 memset
       当死存储删除——volatile 存储不可消除 */
    volatile char *vl = logbuf;
    for (unsigned i = 0; i < sizeof(struct cfg_node); i++)
        vl[i] = 0x47;                       /* 'G' 填充：踩写痕迹可 grep */
    g_removed = 1;
    return NULL;
}

static int cfg_reader_commit(struct cfg_node *n)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(uintptr_t)n->on_change);
    return n->on_change(n);                 /* 崩溃行：pc=0x4747474747474747 */
}

static void *reader_thread(void *arg)
{
    (void)arg;
    struct cfg_node *ent = g_nodes[5];      /* 缓存记录指针 */
    while (!g_removed)
        usleep(300);
    /* 编译屏障：阻止 -O1 把 on_change 的载入作为循环不变量外提到
       自旋之前（那会读到删除/复用发生前的旧值，案例被合法拆弹） */
    __asm__ volatile ("" ::: "memory");
    long rc = cfg_reader_commit(ent);      /* 崩溃链：悬垂回调在此跳飞 */
    g_reader_rc = rc;                      /* volatile 后置：防 -O1 尾调用吞帧 */
    return (void *)rc;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    for (int i = 0; i < 8; i++) {
        g_nodes[i] = calloc(1, sizeof **g_nodes);
        snprintf(g_nodes[i]->key, sizeof g_nodes[i]->key, "k%d", i);
        g_nodes[i]->on_change = cfg_on_change;
        g_nodes[i]->v = i;
    }
    pthread_t tr, td;
    pthread_create(&tr, NULL, reader_thread, NULL);
    pthread_create(&td, NULL, deleter_thread, NULL);
    pthread_join(tr, NULL);
    pthread_join(td, NULL);
    return 0;
}
EOF

# ---------- 24. shm_truncate_bus: 进程间 部署进程收缩库文件 → SIGBUS ----------
cat > $CS/shm_truncate_bus.c <<'EOF'
/* BMC 风格：FRU 数据库以 mmap 方式常驻；部署子进程把库文件替换为精简版
   （ftruncate 收缩）。父进程仍按旧布局读远端记录 → 越过新 EOF → SIGBUS */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

static const char *DB_PATH = "/tmp/bmc_fru_db.bin";
static const char *FLAG_PATH = "/tmp/bmc_fru_db.flag";

static int db_far_record_read(volatile unsigned char *db)
{
    volatile unsigned char *rec = db + 0x3800;      /* 旧布局的最后一条记录 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)rec);
    return *rec;                                    /* 崩溃行: SIGBUS（越过收缩后 EOF） */
}

static int fru_service_boot(void)
{
    int fd = open(DB_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ftruncate(fd, 0x4000);
    unsigned char *db = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                             MAP_SHARED, fd, 0);
    if (db == MAP_FAILED) return -1;
    memset(db, 'D', 0x4000);                        /* 旧版完整布局 */

    unlink(FLAG_PATH);
    pid_t pid = fork();
    if (pid == 0) {
        /* 部署子进程：库文件被"替换"为精简版（收缩同一 inode） */
        int cfd = open(DB_PATH, O_RDWR);
        ftruncate(cfd, 0x100);
        close(cfd);
        int f = open(FLAG_PATH, O_CREAT | O_WRONLY, 0644);
        close(f);
        _exit(0);
    }
    /* 父进程：看到部署完成标志后继续按旧布局访问 */
    while (access(FLAG_PATH, F_OK) != 0)
        usleep(300);
    return db_far_record_read((volatile unsigned char *)db);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return fru_service_boot() & 1;
}
EOF

# ---------- 25. db_index_corrupt: 进程间 无锁并发修改共享库索引 ----------
cat > $CS/db_index_corrupt.c <<'EOF'
/* BMC 风格：Sensor 共享库（mmap MAP_SHARED）被两个进程同时使用但没加锁。
   统计子进程把垃圾写进索引字段（0x47474747），查询进程按垃圾索引取记录
   → 远超库区的大越界读 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

static const char *DB_PATH = "/tmp/bmc_sens_idx.bin";
static const char *FLAG_PATH = "/tmp/bmc_sens_idx.flag";

static int db_query_run(volatile unsigned char *db)
{
    volatile uint32_t idx = *(volatile uint32_t *)(db + 0x10);  /* 索引字段 */
    volatile unsigned char *rec = db + (unsigned long)idx * 4;  /* BUG: 未校验 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)rec);
    return *rec;                                    /* 崩溃行: 垃圾索引→大越界读 */
}

static int sens_query_service(void)
{
    int fd = open(DB_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ftruncate(fd, 0x4000);
    unsigned char *db = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                             MAP_SHARED, fd, 0);
    if (db == MAP_FAILED) return -1;
    memset(db, 'S', 0x4000);
    *(uint32_t *)(db + 0x10) = 3;                   /* 正常索引 */

    unlink(FLAG_PATH);
    pid_t pid = fork();
    if (pid == 0) {
        /* 统计子进程：无锁并发修改共享库索引（写坏） */
        int cfd = open(DB_PATH, O_RDWR);
        unsigned char *cdb = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, cfd, 0);
        *(volatile uint32_t *)(cdb + 0x10) = 0x47474747u;
        munmap(cdb, 0x4000);
        close(cfd);
        int f = open(FLAG_PATH, O_CREAT | O_WRONLY, 0644);
        close(f);
        _exit(0);
    }
    while (access(FLAG_PATH, F_OK) != 0)
        usleep(300);
    return db_query_run((volatile unsigned char *)db);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return sens_query_service() & 1;
}
EOF

# ---------- 26. dblfree_concurrent: 线程间 会话并发双重释放 ----------
cat > $CS/dblfree_concurrent.c <<'EOF'
/* BMC 风格：会话资源由"超时看护"与"IO 完成上报"两条路径同时收尾，
   都认为归自己释放 → 双重 free，第二下在完成线程里暴雷 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

struct ipmi_sess {
    char id[24];
    int refs;
};

static struct ipmi_sess *g_sess;
static volatile int g_timeout_freed;
static volatile int g_io_done;

static void *timeout_watcher(void *arg)
{
    (void)arg;
    usleep(3000);
    /* 超时路径：会话超时回收 */
    free(g_sess);
    g_timeout_freed = 1;
    usleep(5000);
    return NULL;
}

static int io_completer_release(struct ipmi_sess *s)
{
    free(s);                                /* 崩溃点：第二次 free → abort */
    g_io_done = 1;                          /* free 后仍有动作：阻止尾调用折叠 */
    return 0;
}

static void *io_completer(void *arg)
{
    (void)arg;
    /* 完成路径：等超时回收标志后仍按自己的账本释放（竞态双收尾） */
    while (!g_timeout_freed)
        usleep(200);
    free(g_sess);                           /* 崩溃点：第二次 free → abort */
    g_io_done = 1;
    usleep(2000);                           /* 释放后仍有动作 */
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_sess = calloc(1, sizeof *g_sess);
    strcpy(g_sess->id, "ipmi-sess-1");
    pthread_t tw, tc;
    pthread_create(&tw, NULL, timeout_watcher, NULL);
    pthread_create(&tc, NULL, io_completer, NULL);
    pthread_join(tw, NULL);
    pthread_join(tc, NULL);
    return 0;
}
EOF

# ---------- 27. db_compact_race: 线程间 碎片整理移动记录 ----------
cat > $CS/db_compact_race.c <<'EOF'
/* BMC 风格：事件库碎片整理线程把记录前移（memmove 挪动记录）；读者线程
   缓存的最后一条记录指针如今指向被 'C' 填充的空位——len 字段读出
   0x43434343，按它索引辅助表 → 大越界读 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

struct evt_rec {
    char key[8];
    unsigned int len;
    char pad[4];
};

static struct evt_rec g_recs[8];           /* 内存事件库 */
static unsigned char g_aux[0x40];          /* 辅助载荷表 */
static volatile int g_compacted;

static void *compactor_thread(void *arg)
{
    (void)arg;
    usleep(3000);
    /* 整理：删掉第 3 条，后面记录整体前移一条的位置（移动记录） */
    memmove(&g_recs[2], &g_recs[3], 5 * sizeof(struct evt_rec));
    memset(&g_recs[7], 0x43, sizeof(struct evt_rec));   /* 尾洞 'C' 填充 */
    g_compacted = 1;
    return NULL;
}

static int db_report_scan(struct evt_rec *r)
{
    unsigned int len = r->len;             /* 读到 0x43434343 */
    volatile unsigned char *p = g_aux + len;   /* BUG: 未校验 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)p);
    return *p;                             /* 崩溃行: 大越界读 */
}

static void *reader_thread(void *arg)
{
    (void)arg;
    struct evt_rec *ent = &g_recs[7];      /* 缓存最后一条记录 */
    while (!g_compacted)
        usleep(300);
    return (void *)(long)db_report_scan(ent);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    for (int i = 0; i < 8; i++) {
        snprintf(g_recs[i].key, sizeof g_recs[i].key, "e%d", i);
        g_recs[i].len = i;
    }
    memset(g_aux, 'A', sizeof g_aux);
    pthread_t tr, tc;
    pthread_create(&tr, NULL, reader_thread, NULL);
    pthread_create(&tc, NULL, compactor_thread, NULL);
    pthread_join(tr, NULL);
    pthread_join(tc, NULL);
    return 0;
}
EOF

echo "== concurrency cases written =="
ls -la $CS | tail -8

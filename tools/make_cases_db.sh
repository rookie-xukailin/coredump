#!/usr/bin/env bash
# 第 28-33 维度：SQLite/LMDB/动态库 并发与损坏场景
set -e
CS=/tmp/coredump_work/cases

# ---------- 28. sqlite_close_race: 线程间 巡检关闭与查询并发（UAF） ----------
cat > $CS/sqlite_close_race.c <<'EOF'
/* BMC 风格：巡检线程认为配置库空闲，跨线程 finalize 活动语句并 close 连接；
   正在步进的读线程继续 sqlite3_step —— 释放后的 Vdbe 被复用投毒，崩在
   sqlite3VdbeExec 内部 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sqlite3.h>

static sqlite3 *g_db;
static sqlite3_stmt *g_stmt;
static volatile int g_positioned, g_reclaimed;

static void *admin_thread(void *arg)
{
    (void)arg;
    while (!g_positioned) usleep(200);
    usleep(3000);
    sqlite3_finalize(g_stmt);          /* 误用：跨线程回收活动语句 */
    sqlite3_close(g_db);               /* 连接关闭，句柄内存释放 */
    char *junk = malloc(0x200);        /* 立即复用投毒 */
    memset(junk, 0x5a, 0x200);
    g_reclaimed = 1;
    return NULL;
}

static void *reader_thread(void *arg)
{
    (void)arg;
    sqlite3_step(g_stmt);              /* 第一行正常，定位游标 */
    g_positioned = 1;
    while (!g_reclaimed) usleep(200);
    sqlite3_step(g_stmt);              /* 崩溃行：UAF 步进已释放的 Vdbe */
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    remove("/tmp/bmc_cfg.db");
    if (sqlite3_open("/tmp/bmc_cfg.db", &g_db) != SQLITE_OK) return 1;
    sqlite3_exec(g_db, "PRAGMA journal_mode=OFF;", 0, 0, 0);
    sqlite3_exec(g_db, "CREATE TABLE sensor(id INTEGER PRIMARY KEY, val TEXT);",
                 0, 0, 0);
    sqlite3_exec(g_db, "BEGIN;", 0, 0, 0);
    for (int i = 0; i < 300; i++)
        sqlite3_exec(g_db, "INSERT INTO sensor(val) VALUES('aaaaaaaa');", 0, 0, 0);
    sqlite3_exec(g_db, "COMMIT;", 0, 0, 0);
    sqlite3_prepare_v2(g_db, "SELECT id, val FROM sensor;", -1, &g_stmt, 0);

    pthread_t ta, tr;
    pthread_create(&ta, NULL, admin_thread, NULL);
    pthread_create(&tr, NULL, reader_thread, NULL);
    pthread_join(ta, NULL);
    pthread_join(tr, NULL);
    return 0;
}
EOF

# ---------- 29. sqlite_corrupt_bus: 进程间 部署截断 mmap 的 db 文件 → SIGBUS ----------
cat > $CS/sqlite_corrupt_bus.c <<'EOF'
/* BMC 风格：事件库开启 mmap 访问；全表扫描进行中，部署子进程把库文件
   替换为精简版（truncate 同一 inode），后续页越过新 EOF → SIGBUS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sqlite3.h>

static const char *DB = "/tmp/bmc_evt.db";
static const char *FLG = "/tmp/bmc_evt.flag";

static int evt_scan_all(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db, "SELECT id, payload FROM evt;", -1, &st, 0);
    if (!st) return -1;
    long total = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {     /* 扫描中逐页触碰 mmap */
        total += sqlite3_column_int(st, 0);
        g_positioned_hint();
        if (total > 0 && g_flag_seen()) {
            /* 部署完成后继续扫 —— 后续页已越过收缩后的 EOF */
            continue;
        }
    }
    sqlite3_finalize(st);
    return 0;
}
EOF
# 上面占位写法不对——重写为自洽版本
cat > $CS/sqlite_corrupt_bus.c <<'EOF'
/* BMC 风格：事件库开启 mmap 访问；全表扫描进行中，部署子进程把库文件
   替换为精简版（truncate 同一 inode），后续页越过新 EOF → SIGBUS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sqlite3.h>

static const char *DB_PATH = "/tmp/bmc_evt.db";
static const char *POS_FLAG = "/tmp/bmc_evt.pos";
static const char *DONE_FLAG = "/tmp/bmc_evt.done";
static sqlite3 *g_db;

static int evt_scan_all(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id, payload FROM evt;", -1, &st, 0) != SQLITE_OK)
        return -1;
    long total = 0;
    int n = 0;
    /* 先扫 5 行：读事务按"旧文件大小"打开，mmap/页缓存定位 */
    while (n < 5 && sqlite3_step(st) == SQLITE_ROW) {
        total += sqlite3_column_int(st, 0);
        n++;
    }
    /* 通知部署进程可以替换文件了 */
    int f = open(POS_FLAG, O_CREAT | O_WRONLY, 0644);
    close(f);
    while (access(DONE_FLAG, F_OK) != 0)
        usleep(300);
    /* 部署完成后继续步进同一语句 —— 越过收缩后的 EOF → SIGBUS */
    while (sqlite3_step(st) == SQLITE_ROW) {
        total += sqlite3_column_int(st, 0);
        n++;
    }
    sqlite3_finalize(st);
    return (int)(total ^ n);
}

static int evt_fill(sqlite3 *db)
{
    char sql[256];
    sqlite3_exec(db, "PRAGMA journal_mode=OFF;", 0, 0, 0);
    sqlite3_exec(db, "CREATE TABLE evt(id INTEGER PRIMARY KEY, payload TEXT);",
                 0, 0, 0);
    sqlite3_exec(db, "BEGIN;", 0, 0, 0);
    for (int i = 0; i < 3000; i++) {
        snprintf(sql, sizeof sql,
                 "INSERT INTO evt(payload) VALUES('%064dabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789');", i);
        sqlite3_exec(db, sql, 0, 0, 0);
    }
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    return 0;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    remove(DB_PATH);
    remove(POS_FLAG);
    remove(DONE_FLAG);
    if (sqlite3_open(DB_PATH, &g_db) != SQLITE_OK) return 1;
    evt_fill(g_db);
    sqlite3_close(g_db);               /* 关闭写连接：清空 page cache */

    /* 新开连接：冷缓存 + mmap 访问，逐页从文件走 */
    if (sqlite3_open(DB_PATH, &g_db) != SQLITE_OK) return 1;
    sqlite3_exec(g_db, "PRAGMA mmap_size=67108864;", 0, 0, 0);

    pid_t pid = fork();
    if (pid == 0) {
        /* 部署子进程：等扫描定位后把库文件替换为空壳 */
        while (access(POS_FLAG, F_OK) != 0)
            usleep(300);
        int fd = open(DB_PATH, O_RDWR);
        ftruncate(fd, 4096);
        close(fd);
        int f = open(DONE_FLAG, O_CREAT | O_WRONLY, 0644);
        close(f);
        _exit(0);
    }
    evt_scan_all(g_db);        /* 扫描中途越过收缩后的 EOF → SIGBUS in sqlite */
    sqlite3_close(g_db);
    return 0;
}
EOF

# ---------- 30. sqlite_finalize_uaf: 线程间 对账双收尾（双重 finalize） ----------
cat > $CS/sqlite_finalize_uaf.c <<'EOF'
/* BMC 风格：升级对账线程与补数线程各自持有语句句柄副本，先后 finalize
   同一 stmt —— 第二次 finalize 走已释放的 Vdbe，db 指针被复用投毒 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sqlite3.h>

static sqlite3 *g_db;
static sqlite3_stmt *g_stmt;
static volatile int g_stepped, g_freed;

static void *reclaimer_thread(void *arg)
{
    (void)arg;
    while (!g_stepped) usleep(200);
    usleep(2000);
    sqlite3_finalize(g_stmt);           /* 第一次 finalize（正常） */
    char *junk = malloc(0x200);         /* 复用投毒 0x5a */
    memset(junk, 0x5a, 0x200);
    g_freed = 1;
    return NULL;
}

static void *reconcile_thread(void *arg)
{
    (void)arg;
    sqlite3_step(g_stmt);               /* 执行一次 */
    g_stepped = 1;
    while (!g_freed) usleep(200);
    sqlite3_finalize(g_stmt);           /* 崩溃行：第二次 finalize → UAF */
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    remove("/tmp/bmc_rctl.db");
    if (sqlite3_open("/tmp/bmc_rctl.db", &g_db) != SQLITE_OK) return 1;
    sqlite3_exec(g_db, "PRAGMA journal_mode=OFF;", 0, 0, 0);
    sqlite3_exec(g_db, "CREATE TABLE fru(id INTEGER PRIMARY KEY, sn TEXT);", 0, 0, 0);
    for (int i = 0; i < 100; i++)
        sqlite3_exec(g_db, "INSERT INTO fru(sn) VALUES('SN0000');", 0, 0, 0);
    sqlite3_prepare_v2(g_db, "SELECT id FROM fru;", -1, &g_stmt, 0);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, reclaimer_thread, NULL);
    pthread_create(&t2, NULL, reconcile_thread, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    sqlite3_close(g_db);
    return 0;
}
EOF

# ---------- 31. lmdb_close_race: 线程间 env 关闭与活动读者并发 ----------
cat > $CS/lmdb_close_race.c <<'EOF'
/* BMC 风格：维护线程认为库空闲执行 mdb_env_close（解映射+释放 env），
   已定位游标的读线程继续 mdb_cursor_get —— 崩在 liblmdb 内部 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "lmdb.h"

static MDB_env *g_env;
static MDB_dbi g_dbi;
static volatile int g_cursor_ready, g_env_closed;

static void *maint_thread(void *arg)
{
    (void)arg;
    while (!g_cursor_ready) usleep(200);
    usleep(3000);
    mdb_env_close(g_env);               /* 误用：读者事务仍活动 */
    char *junk = malloc(0x200);
    memset(junk, 0x5a, 0x200);
    g_env_closed = 1;
    return NULL;
}

static void *reader_thread(void *arg)
{
    (void)arg;
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    mdb_txn_begin(g_env, NULL, MDB_RDONLY, &txn);
    mdb_cursor_open(txn, g_dbi, &cur);
    mdb_cursor_get(cur, &k, &v, MDB_FIRST);     /* 定位 */
    g_cursor_ready = 1;
    while (!g_env_closed) usleep(200);
    mdb_cursor_get(cur, &k, &v, MDB_NEXT);      /* 崩溃行：UAF+已解映射 */
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    return NULL;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    system("rm -rf /tmp/bmc_lmdb1 && mkdir -p /tmp/bmc_lmdb1");
    if (mdb_env_create(&g_env) != 0) return 1;
    mdb_env_set_mapsize(g_env, 1048576 * 4);
    if (mdb_env_open(g_env, "/tmp/bmc_lmdb1", 0, 0644) != 0) return 1;

    MDB_txn *txn = NULL;
    mdb_txn_begin(g_env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, MDB_CREATE, &g_dbi);
    char keybuf[16], valbuf[64];
    for (int i = 0; i < 300; i++) {
        MDB_val k, v;
        snprintf(keybuf, sizeof keybuf, "k%06d", i);
        memset(valbuf, 'V', sizeof valbuf - 1); valbuf[sizeof valbuf - 1] = 0;
        k.mv_data = keybuf; k.mv_size = strlen(keybuf) + 1;
        v.mv_data = valbuf; v.mv_size = sizeof valbuf;
        mdb_put(txn, g_dbi, &k, &v, 0);
    }
    mdb_txn_commit(txn);

    pthread_t tm, tr;
    pthread_create(&tm, NULL, maint_thread, NULL);
    pthread_create(&tr, NULL, reader_thread, NULL);
    pthread_join(tm, NULL);
    pthread_join(tr, NULL);
    return 0;
}
EOF

# ---------- 32. lmdb_truncate_bus: 进程间 部署截断 data.mdb → SIGBUS ----------
cat > $CS/lmdb_truncate_bus.c <<'EOF'
/* BMC 风格：LMDB 全 mmap 特性下，部署子进程把 data.mdb 截断为空壳，
   遍历线程继续走 B+树页 → 越过新 EOF → SIGBUS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "lmdb.h"

static const char *FLAG_PATH = "/tmp/bmc_lmdb2.flag";

static int walk_all(MDB_env *env, MDB_dbi dbi)
{
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    mdb_cursor_open(txn, dbi, &cur);
    int n = 0;
    if (mdb_cursor_get(cur, &k, &v, MDB_FIRST) == 0)
        n++;
    while (mdb_cursor_get(cur, &k, &v, MDB_NEXT) == 0)  /* 崩溃点：越过 EOF 页 */
        n++;
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    return n;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    system("rm -rf /tmp/bmc_lmdb2 && mkdir -p /tmp/bmc_lmdb2");
    remove(FLAG_PATH);
    MDB_env *env = NULL;
    MDB_dbi dbi;
    mdb_env_create(&env);
    mdb_env_set_mapsize(env, 1048576 * 4);
    if (mdb_env_open(env, "/tmp/bmc_lmdb2", 0, 0644) != 0) return 1;
    MDB_txn *txn = NULL;
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
    char kb[16], vb[128];
    for (int i = 0; i < 2000; i++) {
        MDB_val k, v;
        snprintf(kb, sizeof kb, "k%06d", i);
        memset(vb, 'W', sizeof vb - 1); vb[sizeof vb - 1] = 0;
        k.mv_data = kb; k.mv_size = strlen(kb) + 1;
        v.mv_data = vb; v.mv_size = sizeof vb;
        mdb_put(txn, dbi, &k, &v, 0);
    }
    mdb_txn_commit(txn);

    pid_t pid = fork();
    if (pid == 0) {
        /* 部署子进程：data.mdb 截断为空壳 */
        int fd = open("/tmp/bmc_lmdb2/data.mdb", O_RDWR);
        ftruncate(fd, 4096);
        close(fd);
        int f = open(FLAG_PATH, O_CREAT | O_WRONLY, 0644);
        close(f);
        _exit(0);
    }
    while (access(FLAG_PATH, F_OK) != 0)
        usleep(300);
    walk_all(env, dbi);         /* 遍历 → SIGBUS */
    mdb_env_close(env);
    return 0;
}
EOF

# ---------- 33. dlclose_race: 多线程加载/卸载动态库 ----------
cat > $CS/libdlplug.c <<'EOF'
/* 被加载/卸载的插件库 */
int plug_run(void)
{
    return 7;
}
EOF

cat > $CS/dlclose_race.c <<'EOF'
/* BMC 风格：插件管理线程加载诊断插件取入口后卸载（认为没人在用）；
   工作线程拿到函数指针正要调用 —— 代码页已被 dlclose 解映射 */
#include <stdio.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

typedef int (*plug_fn)(void);

static plug_fn g_fn;
static void *g_handle;
static volatile int g_bound, g_unloaded;
static volatile long g_worker_rc;

static int plug_worker_call(plug_fn f)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)f);
    return f();                     /* 崩溃行：pc=已卸载插件地址 */
}

static void *plugin_worker(void *arg)
{
    (void)arg;
    while (!g_bound) usleep(200);
    while (!g_unloaded) usleep(200);
    long rc = plug_worker_call(g_fn);     /* 崩溃链：已卸载代码页在此调用 */
    g_worker_rc = rc;                     /* volatile 后置：防 -O1 尾调用吞帧 */
    return (void *)rc;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_handle = dlopen("/tmp/coredump_work/build/libdlplug.so", 2 /*RTLD_NOW*/);
    if (!g_handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    g_fn = (plug_fn)dlsym(g_handle, "plug_run");
    g_bound = 1;

    pthread_t tw;
    pthread_create(&tw, NULL, plugin_worker, NULL);
    usleep(5000);
    dlclose(g_handle);              /* 卸载：插件代码页解映射 */
    g_unloaded = 1;
    pthread_join(tw, NULL);
    return 0;
}
EOF

echo "== db/dl cases written =="
ls -la $CS | tail -10

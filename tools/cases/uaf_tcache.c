/* BMC 风格：定时器事件释放后仍被 arm 写，污染 tcache 链表 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct timer_evt {
    void (*cb)(void *);                 /* 偏移 0，与 tcache next 重合 */
    void *arg;
    int  period_ms;
};

typedef void (*tmr_cb_t)(void *);

static struct timer_evt *tmr_alloc(int ms)
{
    struct timer_evt *e = malloc(sizeof *e);
    if (e) { e->cb = NULL; e->arg = NULL; e->period_ms = ms; }
    return e;
}

static void tmr_arm(struct timer_evt *e, tmr_cb_t cb)
{
    e->cb = cb;                         /* UAF 写 */
}

static int scheduler_pump(void)
{
    struct timer_evt *e1 = tmr_alloc(100);
    struct timer_evt *e2 = tmr_alloc(200);
    struct timer_evt *e3 = tmr_alloc(300);
    free(e2);
    free(e3);                           /* tcache: head=e3 -> e2, count=2 */
    tmr_arm(e3, (tmr_cb_t)0x51500000);  /* BUG: 写已 free 的 head chunk → next 被污染 */
    struct timer_evt *a = malloc(sizeof *a);   /* 返回 e3, head=野指针 */
    struct timer_evt *b = malloc(sizeof *b);   /* 返回野指针 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)b);
    memset(b, 0, sizeof *b);            /* 崩溃行 */
    (void)a; (void)e1;
    return 0;
}

static int scheduler_main(void)
{ return scheduler_pump(); }

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return scheduler_main();
}

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

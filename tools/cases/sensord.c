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

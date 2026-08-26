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

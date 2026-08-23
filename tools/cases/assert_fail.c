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

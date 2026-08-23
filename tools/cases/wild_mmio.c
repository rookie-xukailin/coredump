/* BMC 风格：多型号单板寄存器基址表索引被写坏，写出到未映射区域 */
#include <stdio.h>

typedef volatile unsigned int reg32_t;

struct plat_cfg { unsigned long gpio_base; unsigned long pwm_base; };
static const struct plat_cfg g_plats[] = {
    { 0x50000000UL, 0x50010000UL },
    { 0x51000000UL, 0x51010000UL },
    { 0x52000000UL, 0x52010000UL },
};

static unsigned long g_plat_idx = 2;   /* 意外被写坏 */

static int pwm_hw_init(unsigned long base)
{
    reg32_t *en = (reg32_t *)(base + 0x0c);
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)en);
    *en = 1;                            /* 崩溃行 */
    return 0;
}

static int pwm_init_for_model(const struct plat_cfg *cfg)
{ return pwm_hw_init(cfg->pwm_base); }

static int board_early_init(void)
{
    const struct plat_cfg *cfg = &g_plats[g_plat_idx];   /* 越界取基址 */
    return pwm_init_for_model(cfg);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_plat_idx = 0x25;                  /* 模拟配置解析把索引写坏 */
    return board_early_init();
}

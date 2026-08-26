/* BMC 风格：设备驱动初始化顺序错误导致全局 dev 为 NULL 仍被写 */
#include <stdio.h>
#include <stdint.h>

struct fan_dev {
    int   idx;
    volatile unsigned int *ctrl_reg;   /* 偏移 8 */
    char  name[24];
    int   rpm;
};

static struct fan_dev *g_fan;          /* 板载风扇未注册时为 NULL */

static int hw_fan_set_pwm(struct fan_dev *dev, int duty)
{
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)&dev->ctrl_reg);
    dev->ctrl_reg = (volatile unsigned int *)(uintptr_t)(0x1000u + duty); /* 崩溃行 */
    return 0;
}

static int thermal_apply_policy(int duty)
{ return hw_fan_set_pwm(g_fan, duty); }

static int thermal_loop(void)
{
    int duty = 128;
    for (int t = 0; t < 4; t++)
        duty += thermal_apply_policy(duty);
    return duty;
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    /* 正常路径应当先 fan_register(&g_fan)，此处遗漏 */
    return thermal_loop() & 1;
}

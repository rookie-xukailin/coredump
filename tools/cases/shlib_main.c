/* 主程序：调用 libsensord.so 的读数接口 */
#include <stdio.h>
#include <sensord.h>

static int thermal_check(void)
{
    struct sensor_reading r;
    int rc = sensord_get_reading("psu0", &r);   /* psu0 未注册 */
    return rc;
}

static int thermal_guard(void)
{ return thermal_check(); }

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    if (sensord_init(4) != 0) return 1;
    int r = thermal_guard();
    sensord_shutdown();
    return r;
}

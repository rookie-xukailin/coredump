/* BMC 风格：日志格式化缓冲溢出覆盖保存的 FP/LR，返回后跳飞 */
#include <stdio.h>
#include <string.h>

static int log_format(char *out, const char *src)
{
    memcpy(out, src, strlen(src));      /* BUG: 未用容量限制 */
    return 0;
}

static int klog_emit(const char *tag, const char *body)
{
    char line[160];
    (void)tag;
    log_format(line, body);             /* 溢出覆盖本帧 FP/LR */
    return fputs(line, stderr) < 0;
}

static int klog_warning(const char *body)
{ return klog_emit("WARN", body); }

static int sensor_report_timeout(const char *sens)
{
    char body[600];
    int n = snprintf(body, sizeof body, "sensor %s report timeout ", sens);
    memset(body + n, 'W', sizeof body - n - 1);
    body[sizeof body - 1] = 0;
    return klog_warning(body);
}

static int watchdog_prelude(void)
{ return sensor_report_timeout("cpu0_temp"); }

int main(void)
{
    return watchdog_prelude();
}

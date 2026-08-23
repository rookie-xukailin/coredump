/* BMC 风格：IPMI 报文按字段字节计算页粒度偏移，未校验直接读 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ipmi_msg {
    unsigned char netfn;
    unsigned char cmd;
    unsigned char data_len;
    unsigned char pad;
    unsigned char payload[16];
};

static int sdr_read_at(const struct ipmi_msg *m, int k)
{
    int idx = (m->data_len << 12) + k;  /* BUG: 页粒度放大且无校验 */
    volatile unsigned char v = m->payload[idx];   /* 崩溃行: 远超堆块 */
    return v;
}

static int sdr_decode(const struct ipmi_msg *m)
{
    int total = 0;
    for (int k = 0; k < 4; k++)
        total += sdr_read_at(m, k);
    return total;
}

static int ipmi_dispatch(const struct ipmi_msg *m)
{ return sdr_decode(m); }

int main(void)
{
    struct ipmi_msg *m = malloc(sizeof *m);
    memset(m, 0xee, sizeof *m);
    m->data_len = 0xF0;                 /* idx 最大 0xF0003 */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)&m->payload[0xF0003]);
    setvbuf(stderr, NULL, _IONBF, 0);
    return ipmi_dispatch(m) & 1;
}

/* BMC 风格：底层错误路径已释放 audit 记录，上层不知道又清理一遍 */
#include <stdlib.h>
#include <string.h>

struct audit_rec {
    char tag[24];
    struct audit_rec *next;
};

static struct audit_rec *g_head;
static int g_count;

static int audit_append(const char *tag)
{
    struct audit_rec *r = calloc(1, sizeof *r);
    if (!r) return -1;
    strncpy(r->tag, tag, sizeof r->tag - 1);
    r->next = g_head;
    g_head = r;
    g_count++;
    return 0;
}

static void audit_cleanup(void)
{
    struct audit_rec *p = g_head;
    while (p) {
        struct audit_rec *nx = p->next;
        free(p);                        /* BUG: 不清 g_head/g_count */
        p = nx;
    }
}

static int audit_send(void)
{ return -1; }                          /* 模拟发送失败 */

static int audit_record_boot(void)
{
    audit_append("power-on");
    audit_append("bios-post");
    audit_append("bmc-handoff");
    if (audit_send() != 0) {
        audit_cleanup();                /* 错误路径清理 #1 */
        return -1;
    }
    return 0;
}

int main(void)
{
    if (audit_record_boot() != 0) {
        audit_cleanup();                /* BUG: 上层重试清理 → double free abort */
        return 1;
    }
    return 0;
}

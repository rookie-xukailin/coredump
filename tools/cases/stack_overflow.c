/* BMC 风格：SEL 事件树存在自引用环路，遍历递归爆栈 */
#include <string.h>

struct sel_node {
    char name[48];
    struct sel_node *child[4];
    int assert_bit;
};

static struct sel_node *g_root;

static int sel_assert_recursive(struct sel_node *n, int depth)
{
    char trail[768];
    memset(trail, depth & 0xff, sizeof trail);
    if (!n) return 0;
    int hit = 0;
    for (int i = 0; i < 4; i++)
        hit |= sel_assert_recursive(n->child[i], depth + 1);   /* 环路→无限递归 */
    return hit | n->assert_bit;
}

static int sel_walk_all(void)
{ return sel_assert_recursive(g_root, 0); }

static int sel_service_main(void)
{
    int r = sel_walk_all();
    return r ? 0 : 1;
}

int main(void)
{
    struct sel_node a, b;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.child[0] = &b; b.child[0] = &a;   /* 制造环路 */
    g_root = &a;
    return sel_service_main();
}

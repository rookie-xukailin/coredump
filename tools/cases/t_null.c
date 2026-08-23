#include <stdlib.h>
struct dev { int id; char name[32]; };
static struct dev *g_dev;  /* NULL */
int main(void) { g_dev->id = 42; return 0; }

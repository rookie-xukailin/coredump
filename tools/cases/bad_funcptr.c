/* BMC 风格：串口中断处理使用了未初始化的栈寄存器残留，写坏操作表函数指针 */
#include <stdio.h>

struct uart_ops {
    int (*init)(void);
    int (*putc)(int c);
    int (*getc)(void);
    void (*flush)(void);
};

static int uart_mmio_init(void) { return 0; }
static int uart_mmio_getc(void) { return -1; }
static void uart_mmio_flush(void) { }

static struct uart_ops g_ops = {
    uart_mmio_init, NULL /* 由探测填充 */, uart_mmio_getc, uart_mmio_flush
};

static int uart_isr_dirty_write(void)
{
    /* 模拟：中断处理拿了未初始化寄存器当函数指针写回操作表 */
    unsigned long junk;
    __asm__ volatile ("" : "=r"(junk) : "0"(0xdead0000UL));
    g_ops.putc = (int (*)(int))junk;
    return 0;
}

static int uart_poll_input(void)
{
    return g_ops.putc('x');             /* 崩溃行: pc=0xdead0000 */
}

static int console_service(void)
{
    uart_isr_dirty_write();
    return uart_poll_input();
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    return console_service();
}

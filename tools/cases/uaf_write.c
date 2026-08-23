/* BMC 风格：FRU 固件镜像大缓冲 free 后（mmap chunk 直接 munmap），
   热升级路径仍持有旧指针继续写 → 写已解除映射区域 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FW_IMG_SIZE  (160 * 1024)       /* >128KB → malloc 走 mmap */

static char *g_fw_img;

static int fw_load_image(void)
{
    g_fw_img = malloc(FW_IMG_SIZE);
    if (!g_fw_img) return -1;
    memset(g_fw_img, 0, FW_IMG_SIZE);
    return 0;
}

static void fw_release_image(void)
{
    free(g_fw_img);                     /* mmap chunk → munmap，地址段解除映射 */
    g_fw_img = NULL;
}

static int fw_hotfix_patch(char *img, int off)
{
    /* BUG: 传入的是热升级前的旧指针（已 munmap） */
    fprintf(stderr, "FAULT_ADDR=%p\n", (void *)(img + off));
    img[off] = 0x5a;                    /* 崩溃行: 写已解除映射地址 */
    return 0;
}

static int fw_hotfix_apply(char *old_img)
{
    return fw_hotfix_patch(old_img, 0x100);
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    if (fw_load_image() != 0) return 1;
    char *old = g_fw_img;
    fw_release_image();                 /* 释放后 old 悬垂 */
    return fw_hotfix_apply(old);
}

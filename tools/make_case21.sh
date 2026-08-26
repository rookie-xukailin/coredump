#!/usr/bin/env bash
# 第 21 个维度：内存被踩（静默、堆头完好、延迟引爆）
set -e
CS=/tmp/coredump_work/cases

cat > $CS/stomped_late.c <<'EOF'
/* BMC 风格：LED 呼吸灯效果表 memcpy 目标指针少减 0x20，恰好踩进
   前一个 chunk（风扇控制块）尾部的回调指针——写区恰止于本块 chunk 头
   之前，堆头完好无损，glibc 全程无感；LED 动画正常跑完，若干无关业务
   之后风扇服务才调用被踩的回调 → 在远离肇事的代码处延迟引爆 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fan_ctrl {
    char name[16];
    int  pwm;
    int  (*set_pwm)(struct fan_ctrl *, int);   /* 位于块尾部：被踩目标 */
};

struct led_fx {
    unsigned char curve[0x40];    /* 呼吸曲线 */
};

static struct fan_ctrl *g_fan;
static struct led_fx  *g_led;

static int fan_default_pwm(struct fan_ctrl *f, int duty)
{ (void)f; return duty; }

/* 偏移量经 volatile 全局传递：真实缺陷里偏移来自配置/寄存器，
   编译器不可见 —— 否则 -O1 会据 malloc 不相交支配性把越界写当 UB 消除 */
static volatile int g_curve_off;

static int led_play_breath(void)
{
    unsigned char pat[16];
    memset(pat, 0x58, sizeof pat);            /* 'X' 填充：可 grep 的指纹 */
    unsigned char *dst = g_led->curve;
    /* BUG: 目标指针算错 —— 写到前一 chunk 尾部 16 字节（pwm+回调指针），
       且恰好停在本块 chunk 头之前，堆头完好。偏移随位宽（chunk 头 8/16 字节） */
#if defined(__LP64__)
    g_curve_off = -0x20;
#else
    g_curve_off = -0x18;
#endif
    memcpy(dst + g_curve_off, pat, sizeof pat);
    for (int i = 0; i < 0x40; i++)            /* 本块随后正常使用 */
        g_led->curve[i] = (unsigned char)(0x40 + i);
    return 0;
}

static int fan_pwm_apply(struct fan_ctrl *f, int duty)
{
    return f->set_pwm(f, duty);               /* 崩溃行：回调已被踩成 0x58585858… */
}

static volatile int g_tick_rc;

static int fan_tick(void)
{
    int rc = fan_pwm_apply(g_fan, 128);   /* 崩溃链：被踩回调在此跳飞 */
    g_tick_rc = rc;                       /* volatile 后置：防 -O1 尾调用吞帧 */
    return rc;
}

static void housekeeping_heartbeat(void)
{
    volatile int seq = 0;
    for (int i = 0; i < 3; i++) seq += i * 7; /* 无关业务：延迟引爆 */
}

int main(void)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    g_fan = malloc(sizeof *g_fan);   /* 先分配：受害块 */
    g_led = malloc(sizeof *g_led);   /* 后分配：紧随其后，肇事块 */
    if (!g_fan || !g_led) return 1;
    strcpy(g_fan->name, "fan0");
    g_fan->pwm = 0;
    g_fan->set_pwm = fan_default_pwm;

    if (led_play_breath() != 0) return 1;     /* 肇事：静默踩内存 */
    housekeeping_heartbeat();
    return fan_tick() & 1;                    /* 延迟引爆 */
}
EOF
echo written

/* startup_stm32u585.c
 *
 * Minimal Cortex-M33 startup for STM32U585 under stm32-sim. The CPU
 * has TrustZone but we boot in non-secure-only / no-secure mode;
 * the simulator's chip config maps memory at the non-secure peripheral
 * aliases so this works fine.
 */

#include <stdint.h>
#include <stddef.h>

extern int main(int argc, char **argv);

void Default_Handler(void);
void Reset_Handler(void);

extern unsigned long _estack;
extern unsigned long __data_start__;
extern unsigned long __data_end__;
extern unsigned long __bss_start__;
extern unsigned long __bss_end__;
extern unsigned long _sidata;

extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

static void call_init_array(void)
{
    size_t count, i;
    count = __preinit_array_end - __preinit_array_start;
    for (i = 0; i < count; i++)
        __preinit_array_start[i]();
    count = __init_array_end - __init_array_start;
    for (i = 0; i < count; i++)
        __init_array_start[i]();
}

void Reset_Handler(void)
{
    unsigned long *src, *dst;
    src = &_sidata;
    for (dst = &__data_start__; dst < &__data_end__;)
        *dst++ = *src++;
    for (dst = &__bss_start__; dst < &__bss_end__;)
        *dst++ = 0;
    call_init_array();
    (void)main(0, (char**)0);
    while (1) {
        __asm__ volatile ("wfi");
    }
}

void Default_Handler(void)
{
    while (1) {
        __asm__ volatile ("wfi");
    }
}

void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SecureFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

__attribute__ ((section(".isr_vector"), used))
void (* const g_pfnVectors[])(void) = {
    (void (*)(void))(&_estack),
    Reset_Handler,
    NMI_Handler,
    HardFault_Handler,
    MemManage_Handler,
    BusFault_Handler,
    UsageFault_Handler,
    SecureFault_Handler,
    0,
    0,
    0,
    SVC_Handler,
    DebugMon_Handler,
    0,
    PendSV_Handler,
    SysTick_Handler,
};

/* vectors.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Minimal Cortex-M vector table for the smoke-test firmware. Only the
 * initial SP and reset handler matter for the simulator; everything
 * else points at Default_Handler so unexpected exceptions are caught.
 */

#include <stdint.h>

extern uint32_t __stack_top__;
void Reset_Handler(void);
void Default_Handler(void);

__attribute__((section(".isr_vector"), used))
const void *vectors[] = {
    (const void *)&__stack_top__,
    (const void *)Reset_Handler,
    (const void *)Default_Handler, /* NMI */
    (const void *)Default_Handler, /* HardFault */
    (const void *)Default_Handler, /* MemManage */
    (const void *)Default_Handler, /* BusFault */
    (const void *)Default_Handler, /* UsageFault */
    (const void *)0, (const void *)0, (const void *)0, (const void *)0,
    (const void *)Default_Handler, /* SVCall */
    (const void *)Default_Handler, /* DebugMonitor */
    (const void *)0,
    (const void *)Default_Handler, /* PendSV */
    (const void *)Default_Handler, /* SysTick */
};

/* vectors.c - Cortex-M33 vector table for the U5 smoke firmware.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#include <stdint.h>

extern uint32_t __stack_top__;
void Reset_Handler(void);
void Default_Handler(void);

__attribute__((section(".isr_vector"), used))
const void *vectors[] = {
    (const void *)&__stack_top__,
    (const void *)Reset_Handler,
    (const void *)Default_Handler,
    (const void *)Default_Handler,
    (const void *)Default_Handler,
    (const void *)Default_Handler,
    (const void *)Default_Handler,
    (const void *)0, (const void *)0, (const void *)0, (const void *)0,
    (const void *)Default_Handler,
    (const void *)Default_Handler,
    (const void *)0,
    (const void *)Default_Handler,
    (const void *)Default_Handler,
};

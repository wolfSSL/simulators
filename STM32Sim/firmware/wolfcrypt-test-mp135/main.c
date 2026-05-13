/* main.c - Entry point for wolfCrypt test on STM32MP135 under
 * stm32-sim. Mirrors the H7/U5 wolfcrypt firmwares: bring up the
 * MMU, configure UART4 via direct register pokes (no HAL_Init in
 * sight), then call wolfcrypt_test() from wolfSSL's test suite. The
 * simulator polls test_complete / test_result via ELF symbol
 * lookup. */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern int wolfcrypt_test(void *args);
void mmu_enable(void);

/* UART4 on MP135 is at APB1 + 0x10000 = 0x40010000. The H7/U5 USART
 * register layout (CR1/BRR/ISR/TDR) is shared with all modern STM32
 * USARTs, so we drive it directly without going through HAL. */
#define UART4_BASE     0x40010000UL
#define UART4_CR1      (*(volatile uint32_t *)(UART4_BASE + 0x00))
#define UART4_BRR      (*(volatile uint32_t *)(UART4_BASE + 0x0C))
#define UART4_ISR      (*(volatile uint32_t *)(UART4_BASE + 0x1C))
#define UART4_TDR      (*(volatile uint32_t *)(UART4_BASE + 0x28))

#define USART_CR1_UE    (1 << 0)
#define USART_CR1_TE    (1 << 3)
#define USART_ISR_TXE   (1 << 7)

static void uart_init(void)
{
    UART4_BRR = 64000000UL / 115200UL;
    UART4_CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void uart_putc(char c)
{
    while (!(UART4_ISR & USART_ISR_TXE))
        ;
    UART4_TDR = (uint32_t)c;
}

int _write(int fd, const char *buf, int len)
{
    (void)fd;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            uart_putc('\r');
        uart_putc(buf[i]);
    }
    return len;
}

extern char __heap_start__;
extern char __heap_end__;

void *_sbrk(ptrdiff_t incr)
{
    static char *heap_ptr = NULL;
    char *prev;

    if (heap_ptr == NULL) {
        heap_ptr = &__heap_start__;
    }
    prev = heap_ptr;
    if (heap_ptr + incr > &__heap_end__) {
        return (void *)-1;
    }
    heap_ptr += incr;
    return prev;
}

/* A monotonically increasing tick counter. The MP13 HAL declares
 * HAL_GetTick as __weak so we override it here and avoid having to
 * configure a hardware timer. */
static volatile uint32_t tick_counter;

uint32_t HAL_GetTick(void)
{
    return ++tick_counter;
}

/* newlib's __libc_init_array calls _init() / _fini() between the
 * preinit_array and init_array walks. Without a real definition the
 * linker falls back to `PROVIDE(_init = 0)` in stm32mp135.ld and the
 * call lands at PC=0x00000000, which is unmapped on the simulator
 * and the firmware silently spins until the wall-clock timeout. */
void _init(void) { }
void _fini(void) { }

/* HAL_Init / SystemInit / SystemCoreClock - the MP13 HAL expects all
 * three to exist. We replace them with the minimum stubs the crypto
 * drivers rely on. */
uint32_t SystemCoreClock = 64000000UL;

void SystemInit(void) { }

/* HAL_Init calls (among other things) HAL_InitTick. Provide a
 * trivial override so the HAL does not try to start a timer. */
int HAL_InitTick(uint32_t TickPriority)
{
    (void)TickPriority;
    return 0;
}

/* wolfSSL GENSEED_FORTEST fallback - returns the tick counter so we
 * are not stuck on a constant seed. */
#include <time.h>
time_t time(time_t *t)
{
    tick_counter += 12345;
    time_t val = (time_t)tick_counter;
    if (t) {
        *t = val;
    }
    return val;
}

volatile int test_result   __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    mmu_enable();

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    uart_init();
#define PUTS(s) _write(0, (s), sizeof(s) - 1)
    PUTS("\n\n=== Starting wolfCrypt test ===\n\n");

    test_result = wolfcrypt_test(NULL);

    if (test_result == 0) {
        PUTS("\n\n=== wolfCrypt test passed! ===\n");
    } else {
        PUTS("\n\n=== wolfCrypt test FAILED ===\n");
    }
#undef PUTS

    test_complete = 1;

    /* Plain branch-to-self spin: wfe/wfi decode as invalid on
     * Unicorn's Cortex-A7 model. */
    for (;;) {
        __asm__ volatile ("");
    }
}

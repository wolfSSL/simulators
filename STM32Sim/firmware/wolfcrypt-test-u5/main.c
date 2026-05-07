/* main.c - Entry point for wolfCrypt test on STM32U585 under
 * stm32-sim. Mirrors the H7 wolfcrypt firmware: a minimal Cortex-M33
 * boot, USART1 register init, then `wolfcrypt_test()` from
 * wolfSSL's test suite. The simulator polls test_complete /
 * test_result via ELF symbol lookup. */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern int wolfcrypt_test(void *args);

/* USART1 on U5 is at APB2 + 0x3800 = 0x40013800. The HAL register
 * layout (CR1/BRR/ISR/TDR offsets) is shared with the H7 USART3 we
 * use in the H7 firmware. */
#define USART1_BASE     0x40013800UL
#define USART1_CR1      (*(volatile uint32_t *)(USART1_BASE + 0x00))
#define USART1_BRR      (*(volatile uint32_t *)(USART1_BASE + 0x0C))
#define USART1_ISR      (*(volatile uint32_t *)(USART1_BASE + 0x1C))
#define USART1_TDR      (*(volatile uint32_t *)(USART1_BASE + 0x28))

#define USART_CR1_UE    (1 << 0)
#define USART_CR1_TE    (1 << 3)
#define USART_ISR_TXE   (1 << 7)

static void uart_init(void)
{
    /* Configure USART1: 115200 baud at 16 MHz HSI. The simulator
     * does not actually clock the UART; this is just to satisfy
     * the firmware's expectation of a real configuration. */
    USART1_BRR = 16000000 / 115200;
    USART1_CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void uart_putc(char c)
{
    while (!(USART1_ISR & USART_ISR_TXE))
        ;
    USART1_TDR = c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
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
    char *prev_heap_ptr;

    if (heap_ptr == NULL) {
        heap_ptr = &__heap_start__;
    }

    prev_heap_ptr = heap_ptr;

    if (heap_ptr + incr > &__heap_end__) {
        return (void *)-1;
    }

    heap_ptr += incr;
    return prev_heap_ptr;
}

static volatile uint32_t tick_counter = 0;

#include <time.h>
time_t time(time_t *t)
{
    tick_counter += 12345;
    time_t val = (time_t)tick_counter;
    if (t)
        *t = val;
    return val;
}

volatile int test_result __attribute__((section(".data")))   = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    uart_init();
    uart_puts("\n\n=== Starting wolfCrypt test ===\n\n");

    test_result = wolfcrypt_test(NULL);

    if (test_result == 0) {
        uart_puts("\n\n=== wolfCrypt test passed! ===\n");
    } else {
        uart_puts("\n\n=== wolfCrypt test FAILED ===\n");
    }

    /* Set test_complete last: the simulator polls this between
     * instruction slices and exits as soon as it goes nonzero,
     * which would race with any output emitted afterwards. */
    test_complete = 1;

    while (1) {
        __asm__ volatile ("wfi");
    }

    return test_result;
}

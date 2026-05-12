/* syscalls.c - newlib-nano backend for PIC32MZSim firmware
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Newlib is configured with `--disable-newlib-supplied-syscalls`, so
 * we have to supply the small set of POSIX syscalls newlib references:
 * `_write` (stdio output), `_sbrk` (heap), `_exit` (program halt), and
 * a handful of inert stubs newlib link-references but does not need
 * to actually work for the wolfCrypt test surface.
 *
 * Output from printf / fprintf(stdout, ...) lands on PIC32MZ's UART2
 * (the same TX register the simulator's `Uart` peripheral observes
 * and forwards to the runner's stdout).
 *
 * Also defines `min` / `max`: wolfSSL's settings.h:1201 predefines
 * WOLFSSL_HAVE_MIN/MAX when WOLFSSL_MICROCHIP_PIC32MZ is set (it
 * assumes XC32 supplies them), so misc.c does not emit them and the
 * link would otherwise fail. The bodies are tiny; matching STM32Sim's
 * approach.
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/times.h>

#include "pic32mz_stubs.h"

/* Test-result signalling - the simulator runner polls these symbols. */
extern volatile int test_result;
extern volatile int test_complete;

/* ---- stdout via UART2 ---- */

static void uart_putc(unsigned char c)
{
    if (c == '\n') U2TXREG = (uint32_t)'\r';
    U2TXREG = (uint32_t)c;
}

int _write(int fd, const char *buf, int len)
{
    (void)fd;
    for (int i = 0; i < len; i++) {
        uart_putc((unsigned char)buf[i]);
    }
    return len;
}
int write(int fd, const char *buf, int len) __attribute__((alias("_write")));

/* ---- Heap (newlib's nano malloc layers on top of _sbrk) ---- */

extern char _heap_start;
extern char _heap_end;
static char *heap_ptr = NULL;

void *_sbrk(ptrdiff_t incr)
{
    if (heap_ptr == NULL) {
        heap_ptr = &_heap_start;
    }
    char *prev = heap_ptr;
    if (heap_ptr + incr > &_heap_end) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_ptr += incr;
    return prev;
}
void *sbrk(ptrdiff_t incr) __attribute__((alias("_sbrk")));

/* ---- Program exit ---- */

void _exit(int code)
{
    test_result = code;
    test_complete = 1;
    for (;;) {
        __asm__ volatile ("nop");
    }
}

/* ---- Inert stubs newlib references at link time ---- */

int _close(int fd) { (void)fd; errno = ENOSYS; return -1; }
int close(int fd) __attribute__((alias("_close")));

int _isatty(int fd) { (void)fd; return 1; }
int isatty(int fd) __attribute__((alias("_isatty")));

int _lseek(int fd, int off, int whence) {
    (void)fd; (void)off; (void)whence;
    errno = ENOSYS; return -1;
}
int lseek(int fd, int off, int whence) __attribute__((alias("_lseek")));

int _read(int fd, char *buf, int len) {
    (void)fd; (void)buf; (void)len;
    return 0;
}
int read(int fd, char *buf, int len) __attribute__((alias("_read")));

int _fstat(int fd, struct stat *st)
{
    (void)fd;
    if (st) {
        st->st_mode = S_IFCHR;
    }
    return 0;
}
int fstat(int fd, struct stat *st) __attribute__((alias("_fstat")));

int _kill(int pid, int sig) {
    (void)pid; (void)sig;
    errno = EINVAL; return -1;
}
int kill(int pid, int sig) __attribute__((alias("_kill")));

int _getpid(void) { return 1; }
int getpid(void) __attribute__((alias("_getpid")));

/* time(): use CP0 Count as a tick source. wolfSSL's RNG seeding path
 * pulls in time() when USER_TIME is defined; CP0 Count is fine as a
 * non-cryptographic tick. */
#include <time.h>
time_t time(time_t *t)
{
    time_t v = (time_t)_CP0_GET_COUNT();
    if (t) *t = v;
    return v;
}

/* ---- wolfSSL `min` / `max` ----
 *
 * settings.h pre-defines WOLFSSL_HAVE_MIN / WOLFSSL_HAVE_MAX for
 * WOLFSSL_MICROCHIP_PIC32MZ, so misc.c does not emit these; supply
 * them here so external references resolve at link time. */
uint32_t min(uint32_t a, uint32_t b) { return a < b ? a : b; }
uint32_t max(uint32_t a, uint32_t b) { return a > b ? a : b; }

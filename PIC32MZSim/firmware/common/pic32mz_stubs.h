/* pic32mz_stubs.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Replaces Microchip XC32's <xc.h> / <sys/kmem.h> / <sys/endian.h>
 * just enough that wolfSSL's PIC32MZ port and the bare-metal test
 * firmware can be cross-compiled with gcc-mipsel-linux-gnu. Only the
 * SFRs and intrinsics that pic32mz-crypt.c, random.c, and our own
 * smoke/test firmware touch are exposed - this is not a complete
 * Microchip header replacement.
 */

#ifndef PIC32MZ_SIM_STUBS_H
#define PIC32MZ_SIM_STUBS_H

/* The wolfcrypt-test firmware Makefiles -include this header for both
 * C and assembly TUs (startup.S). Guard the C declarations so the
 * assembler does not try to parse `typedef union { ... }`. */
#ifndef __ASSEMBLER__

#include <stdint.h>

/* Family identification for the EC-vs-EF byte-swap check. Builds
 * select the variant on the command line; shell quoting strips C
 * character literals, so the Makefiles / run scripts pass the ASCII
 * codes directly:
 *   EF: -D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x46
 *   EC: -D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x43
 * The defaults below pick EF when neither is supplied.
 */
#ifndef __PIC32_FEATURE_SET0
#define __PIC32_FEATURE_SET0 'E'
#endif
#ifndef __PIC32_FEATURE_SET1
#define __PIC32_FEATURE_SET1 'F'
#endif

/* KSEG translation: in our simulator everything lives in KSEG1, so the
 * KVA <-> PA mapping is just masking off the segment selector. */
#define KVA_TO_PA(x)    ((uintptr_t)(x) & 0x1FFFFFFFu)
#define PA_TO_KVA0(x)   ((void *)(((uintptr_t)(x) & 0x1FFFFFFFu) | 0x80000000u))
#define PA_TO_KVA1(x)   ((void *)(((uintptr_t)(x) & 0x1FFFFFFFu) | 0xA0000000u))
#define KVA0_TO_KVA1(x) ((void *)((uintptr_t)(x) | 0x20000000u))

/* CP0 Count read. wolfSSL random.c calls this to seed its fallback
 * entropy path on EC silicon, and the bare-metal firmware uses it
 * for very rough delay loops. Unicorn does not auto-increment CP0
 * Count, but for our purposes a non-zero value is sufficient. */
static inline uint32_t _CP0_GET_COUNT(void)
{
    uint32_t v;
    __asm__ volatile("mfc0 %0, $9" : "=r"(v));
    return v;
}

#define SFR_REG(addr) (*(volatile uint32_t *)(addr))

/* Crypto Engine SFRs at phys 0x1F8E_0000, KSEG1 alias 0xBF8E_0000.
 * Each SFR has the standard PIC32 atomic SET/CLR/INV aliases at
 * base+4/+8/+0xC. */
#define CECON       SFR_REG(0xBF8E0000u)
#define CECONSET    SFR_REG(0xBF8E0004u)
#define CECONCLR    SFR_REG(0xBF8E0008u)
#define CECONINV    SFR_REG(0xBF8E000Cu)
#define CESTAT      SFR_REG(0xBF8E0010u)
#define CESTATSET   SFR_REG(0xBF8E0014u)
#define CESTATCLR   SFR_REG(0xBF8E0018u)
#define CESTATINV   SFR_REG(0xBF8E001Cu)
#define CEINTSRC    SFR_REG(0xBF8E0020u)
#define CEINTSRCSET SFR_REG(0xBF8E0024u)
#define CEINTSRCCLR SFR_REG(0xBF8E0028u)
#define CEINTSRCINV SFR_REG(0xBF8E002Cu)
#define CEINTEN     SFR_REG(0xBF8E0030u)
#define CEINTENSET  SFR_REG(0xBF8E0034u)
#define CEINTENCLR  SFR_REG(0xBF8E0038u)
#define CEINTENINV  SFR_REG(0xBF8E003Cu)
#define CEBDPADDR   SFR_REG(0xBF8E0040u)
#define CEBDPADDRSET SFR_REG(0xBF8E0044u)
#define CEBDPADDRCLR SFR_REG(0xBF8E0048u)
#define CEBDPADDRINV SFR_REG(0xBF8E004Cu)
#define CEPOLLCON   SFR_REG(0xBF8E0050u)

/* Bit-field overlays for the registers wolfSSL's pic32mz-crypt.c
 * touches via the `CESTATbits.x` / `CEINTSRCbits.x` syntax. */
typedef union {
    struct {
        unsigned ERROP : 4;
        unsigned ERRPHASE : 4;
        unsigned : 24;
    };
    uint32_t w;
} __CESTATbits_t;
#define CESTATbits (*(volatile __CESTATbits_t *)(0xBF8E0010u))

typedef union {
    struct {
        unsigned : 1;
        unsigned PKTIF : 1;
        unsigned : 30;
    };
    uint32_t w;
} __CEINTSRCbits_t;
#define CEINTSRCbits (*(volatile __CEINTSRCbits_t *)(0xBF8E0020u))

/* RNG SFRs at phys 0x1F88_6000, KSEG1 alias 0xBF88_6000. */
#define RNGCON      SFR_REG(0xBF886000u)
#define RNGCONSET   SFR_REG(0xBF886004u)
#define RNGCONCLR   SFR_REG(0xBF886008u)
#define RNGCONINV   SFR_REG(0xBF88600Cu)
#define RNGPOLY1    SFR_REG(0xBF886010u)
#define RNGPOLY2    SFR_REG(0xBF886020u)
#define RNGNUMGEN1  SFR_REG(0xBF886030u)
#define RNGNUMGEN2  SFR_REG(0xBF886040u)
#define RNGSEED1    SFR_REG(0xBF886050u)
#define RNGSEED2    SFR_REG(0xBF886060u)
#define RNGCNT      SFR_REG(0xBF886070u)

typedef union {
    struct {
        unsigned : 8;
        unsigned TRNGMODE : 1;
        unsigned TRNGEN : 1;
        unsigned PRNGEN : 1;
        unsigned LOAD : 1;
        unsigned : 2;
        unsigned PLEN : 7;
        unsigned : 11;
    };
    uint32_t w;
} __RNGCONbits_t;
#define RNGCONbits (*(volatile __RNGCONbits_t *)(0xBF886000u))

/* UART2 SFRs at phys 0x1F82_2000, KSEG1 alias 0xBF82_2000. */
#define U2MODE      SFR_REG(0xBF822000u)
#define U2MODESET   SFR_REG(0xBF822004u)
#define U2STA       SFR_REG(0xBF822010u)
#define U2STASET    SFR_REG(0xBF822014u)
#define U2BRG       SFR_REG(0xBF822020u)
#define U2TXREG     SFR_REG(0xBF822030u)
#define U2RXREG     SFR_REG(0xBF822040u)

#endif /* __ASSEMBLER__ */

#endif /* PIC32MZ_SIM_STUBS_H */

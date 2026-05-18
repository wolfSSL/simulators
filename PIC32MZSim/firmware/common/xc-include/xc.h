/* xc.h - stub for Microchip XC32 compiler header
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * The real Microchip XC32 toolchain ships <xc.h> as the umbrella
 * processor header. We replace it with our SFR-stub header so
 * wolfSSL's pic32 port (wolfcrypt/port/pic32/pic32mz-crypt.h) can
 * `#include <xc.h>` without the proprietary toolchain present.
 */

#ifndef PIC32MZ_SIM_XC_H
#define PIC32MZ_SIM_XC_H

#include "pic32mz_stubs.h"

#endif

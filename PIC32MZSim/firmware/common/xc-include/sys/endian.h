/* sys/endian.h - stub
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * XC32 ships a BSD-style <sys/endian.h>; wolfSSL's pic32 port
 * (pic32mz-crypt.h:56) blindly includes it. Linux glibc lacks this
 * header (it has <endian.h> with different macro names), so we
 * supply a minimal replacement that provides what the wolfSSL port
 * actually uses - which is nothing, after the include: the byte
 * swaps are open-coded via ByteReverseWord32. This stub just keeps
 * the preprocessor happy.
 */

#ifndef PIC32MZ_SIM_SYS_ENDIAN_H
#define PIC32MZ_SIM_SYS_ENDIAN_H

#endif

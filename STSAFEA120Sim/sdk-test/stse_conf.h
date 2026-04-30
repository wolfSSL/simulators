/* stse_conf.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * STSELib feature configuration for the STSAFE-A120 simulator build.
 *
 * Notes:
 *  - STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS skips the
 *    `stsafea_perso_info_update` query path during stse_init. The
 *    simulator does not implement Query(COMMAND_AUTHORIZATION_CONFIG),
 *    and we operate in plain mode where all access conditions are FREE
 *    and no encryption flags are honoured -- so a static (zeroed)
 *    perso_info is correct and matches the simulator's behaviour.
 *  - STSE_USE_RSP_POLLING avoids the per-command inter-frame delays in
 *    stsafea_frame_transfer; the simulator answers synchronously, so we
 *    don't need to sleep STSAFEA_EXEC_TIME_xxx ms between transmit and
 *    receive.
 *  - Only NIST P-256 is enabled (STSE_CONF_ECC_NIST_P_256). Brainpool,
 *    P-384, P-521, and 25519 are deliberately omitted to keep the
 *    simulator's command handlers narrow.
 */

#ifndef STSE_CONF_H
#define STSE_CONF_H

#define STSE_CONF_STSAFE_A_SUPPORT
#define STSE_CONF_USE_I2C
#define STSE_CONF_DEVICE_DEFAULT_ADDRESS 0x20

#define STSE_CONF_ECC_NIST_P_256
#define STSE_CONF_HASH_SHA_256

#define STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS
#define STSE_USE_RSP_POLLING

/*
 * Polling-retry constants -- borrowed from STSELib's documented defaults
 * (doc/resources/Markdown/03_LIBRARY_CONFIGURATION/03_LIBRARY_CONFIGURATION.md).
 * The simulator answers synchronously so retries should never trigger,
 * but the symbols must exist for stsafea_frame_transfer.c to compile.
 */
#define STSE_MAX_POLLING_RETRY 100
#define STSE_FIRST_POLLING_INTERVAL 10
#define STSE_POLLING_RETRY_INTERVAL 10

#endif /* STSE_CONF_H */

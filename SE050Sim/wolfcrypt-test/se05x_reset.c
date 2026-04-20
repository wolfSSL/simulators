/*
 * No-op SE050 reset stub for simulator testing.
 * Replaces platform/rsp/se05x_reset.c which uses GPIO (not available in Docker).
 */

#include <stdint.h>
#include "sm_timer.h"

void axReset_HostConfigure(void) {}
void axReset_HostUnconfigure(void) {}
void axReset_ResetPulseDUT(int reset_logic) { (void)reset_logic; }
void axReset_PowerDown(int reset_logic) { (void)reset_logic; }
void axReset_PowerUp(int reset_logic) { (void)reset_logic; }
void se05x_ic_reset(uint32_t applet_version) { (void)applet_version; }

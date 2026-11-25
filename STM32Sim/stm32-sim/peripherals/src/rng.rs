/* rng.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STM32Sim.
 *
 * STM32Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STM32Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

use std::fmt;
use std::str::FromStr;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use stm32_sim_core::peripheral::Peripheral;

const CR: u32 = 0x00;
const SR: u32 = 0x04;
const DR: u32 = 0x08;

const CR_RNGEN: u32 = 1 << 2;

const SR_DRDY: u32 = 1 << 0;
const SR_CECS: u32 = 1 << 1;
const SR_SECS: u32 = 1 << 2;
const SR_CEIS: u32 = 1 << 5;
const SR_SEIS: u32 = 1 << 6;

/// Number of SR reads a non-sticky clock error stays asserted for before
/// the (modelled) kernel clock comes back.
const CLOCK_GLITCH_SR_READS: u32 = 64;

/// Which RNG error condition to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngFaultKind {
    /// Seed error: the entropy source failed its health checks. SECS and
    /// SEIS latch and generation stops until software runs the recovery
    /// sequence (clear SEIS, then cycle RNGEN).
    Seed,
    /// Clock error: the RNG kernel clock is too slow (or gone). CECS and
    /// CEIS latch and DRDY stops until the clock comes back.
    Clock,
}

/// An RNG fault to inject after a set number of DR reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngFault {
    pub kind: RngFaultKind,
    /// DR reads served normally before the fault latches. With 0 the
    /// error is already present when the fault is armed, before the
    /// firmware's first status check.
    pub after_reads: u64,
    /// A sticky fault never clears: a dead entropy source or a kernel
    /// clock that never returns. Otherwise a seed error clears once
    /// software runs the recovery sequence and a clock error clears on
    /// its own after a short glitch.
    pub sticky: bool,
}

impl FromStr for RngFault {
    type Err = String;

    /// Parses `<seed|clock>:<after_reads>[:sticky]`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!(
                "expected <seed|clock>:<after_reads>[:sticky], got `{s}`"
            ));
        }
        let kind = match parts[0] {
            "seed" => RngFaultKind::Seed,
            "clock" => RngFaultKind::Clock,
            other => return Err(format!("unknown RNG fault kind `{other}`")),
        };
        let after_reads = parts[1]
            .parse::<u64>()
            .map_err(|e| format!("bad DR read count `{}`: {e}", parts[1]))?;
        let sticky = match parts.get(2) {
            None => false,
            Some(&"sticky") => true,
            Some(other) => return Err(format!("unknown RNG fault flag `{other}`")),
        };
        Ok(Self {
            kind,
            after_reads,
            sticky,
        })
    }
}

impl fmt::Display for RngFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            RngFaultKind::Seed => "seed",
            RngFaultKind::Clock => "clock",
        };
        write!(f, "{kind}:{}", self.after_reads)?;
        if self.sticky {
            write!(f, ":sticky")?;
        }
        Ok(())
    }
}

/// STM32 RNG peripheral. Register layout is identical across F2/F4/H7/U5/L4:
///   0x00 CR   0x04 SR   0x08 DR
///
/// A healthy RNG always has data ready (DRDY=1) and never reports
/// SECS/CECS. An optional injected fault (see [`RngFault`]) models the
/// error management described in the F2/F4 reference manuals (RM0033 /
/// RM0090 "Error management"): while a seed or clock error is current,
/// DRDY stays low and DR holds no fresh data. Optional fixed seeding makes
/// tests deterministic.
pub struct Rng {
    rng: ChaCha20Rng,
    cr: u32,
    /// Software-visible SR bits other than DRDY / CECS / SECS, i.e. the
    /// CEIS / SEIS interrupt flags (write 0 to clear).
    sr: u32,
    fault: Option<RngFault>,
    dr_reads: u64,
    /// The fault has latched (it only latches once per run).
    fault_fired: bool,
    /// A seed or clock error is current (SECS / CECS set, DRDY held low).
    error_current: bool,
    /// Seed-error recovery progress: RNGEN observed low after the fault.
    rngen_dropped: bool,
    /// Clock-error recovery progress: SR reads since the fault latched.
    glitch_reads: u32,
}

impl Rng {
    /// Deterministic seed - good for KAT-style integration tests where
    /// the firmware has to reproduce exact byte streams.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            cr: 0,
            sr: 0,
            fault: None,
            dr_reads: 0,
            fault_fired: false,
            error_current: false,
            rngen_dropped: false,
            glitch_reads: 0,
        }
    }

    pub fn new() -> Self {
        Self::with_seed(0xDEAD_BEEF_CAFE_BABE)
    }

    /// Arm a fault that latches after `fault.after_reads` DR reads (at
    /// once for 0).
    pub fn with_fault(mut self, fault: Option<RngFault>) -> Self {
        self.fault = fault;
        self.maybe_latch_fault();
        self
    }

    fn maybe_latch_fault(&mut self) {
        let Some(fault) = self.fault else { return };
        if self.fault_fired || self.dr_reads < fault.after_reads {
            return;
        }
        self.fault_fired = true;
        self.error_current = true;
        self.rngen_dropped = false;
        self.glitch_reads = 0;
        self.sr |= match fault.kind {
            RngFaultKind::Seed => SR_SEIS,
            RngFaultKind::Clock => SR_CEIS,
        };
        log::info!("rng: injected {fault} fault after {} DR reads", self.dr_reads);
    }

    fn current_error_bits(&self) -> u32 {
        match (self.error_current, self.fault.map(|f| f.kind)) {
            (true, Some(RngFaultKind::Seed)) => SR_SECS,
            (true, Some(RngFaultKind::Clock)) => SR_CECS,
            _ => 0,
        }
    }

    fn clear_error(&mut self) {
        if self.error_current {
            self.error_current = false;
            log::info!("rng: injected fault cleared");
        }
    }

    fn read_sr(&mut self) -> u32 {
        if self.error_current {
            if let Some(f) = self.fault {
                if f.kind == RngFaultKind::Clock && !f.sticky {
                    self.glitch_reads += 1;
                    if self.glitch_reads >= CLOCK_GLITCH_SR_READS {
                        self.clear_error();
                    }
                }
            }
        }
        let drdy = if self.error_current { 0 } else { SR_DRDY };
        self.sr | self.current_error_bits() | drdy
    }

    fn read_dr(&mut self) -> u32 {
        if self.error_current {
            return 0;
        }
        let v = self.rng.next_u32();
        self.dr_reads += 1;
        self.maybe_latch_fault();
        v
    }

    fn write_cr(&mut self, value: u32) {
        let was_enabled = self.cr & CR_RNGEN != 0;
        let now_enabled = value & CR_RNGEN != 0;
        self.cr = value;

        let Some(f) = self.fault else { return };
        if !self.error_current || f.kind != RngFaultKind::Seed || f.sticky {
            return;
        }
        if was_enabled && !now_enabled {
            self.rngen_dropped = true;
        } else if !was_enabled && now_enabled && self.rngen_dropped && self.sr & SR_SEIS == 0 {
            // RM0090 seed-error recovery: SEIS cleared, then RNGEN cycled.
            self.clear_error();
        }
    }

    fn write_sr(&mut self, value: u32) {
        // Only CEIS / SEIS are writable, and only to 0 (rc_w0).
        let clear = !value & (SR_CEIS | SR_SEIS);
        self.sr &= !clear;
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Peripheral for Rng {
    fn name(&self) -> &str {
        "rng"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            CR => self.cr,
            SR => self.read_sr(),
            DR => self.read_dr(),
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            CR => self.write_cr(value),
            SR => self.write_sr(value),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault(s: &str) -> Option<RngFault> {
        Some(s.parse().unwrap())
    }

    fn drain(r: &mut Rng, n: u64) {
        for _ in 0..n {
            assert_ne!(r.read(SR, 4) & SR_DRDY, 0);
            r.read(DR, 4);
        }
    }

    #[test]
    fn parses_fault_specs() {
        assert_eq!(
            "seed:10".parse::<RngFault>().unwrap(),
            RngFault {
                kind: RngFaultKind::Seed,
                after_reads: 10,
                sticky: false
            }
        );
        assert_eq!(
            "clock:0:sticky".parse::<RngFault>().unwrap(),
            RngFault {
                kind: RngFaultKind::Clock,
                after_reads: 0,
                sticky: true
            }
        );
        assert!("seed".parse::<RngFault>().is_err());
        assert!("noise:1".parse::<RngFault>().is_err());
        assert!("seed:x".parse::<RngFault>().is_err());
        assert!("seed:1:forever".parse::<RngFault>().is_err());
        assert_eq!(
            "clock:7:sticky".parse::<RngFault>().unwrap().to_string(),
            "clock:7:sticky"
        );
    }

    #[test]
    fn healthy_rng_always_ready() {
        let mut r = Rng::new();
        r.write(CR, 4, CR_RNGEN);
        drain(&mut r, 1000);
        assert_eq!(r.read(SR, 4), SR_DRDY);
    }

    #[test]
    fn seed_error_latches_and_recovers_per_rm() {
        let mut r = Rng::new().with_fault(fault("seed:4"));
        r.write(CR, 4, CR_RNGEN);
        drain(&mut r, 4);

        assert_eq!(r.read(SR, 4), SR_SECS | SR_SEIS);
        assert_eq!(r.read(DR, 4), 0);

        // Cycling RNGEN without clearing SEIS first does not recover.
        r.write(CR, 4, 0);
        r.write(CR, 4, CR_RNGEN);
        assert_eq!(r.read(SR, 4) & SR_DRDY, 0);

        // Clear SEIS, then cycle RNGEN.
        r.write(SR, 4, 0);
        assert_eq!(r.read(SR, 4), SR_SECS);
        r.write(CR, 4, 0);
        r.write(CR, 4, CR_RNGEN);
        assert_eq!(r.read(SR, 4), SR_DRDY);
        // The fault only fires once.
        drain(&mut r, 100);
    }

    /// A zero-read fault is there from the start: the first SR read already
    /// shows it and no fresh data is served.
    #[test]
    fn zero_read_fault_is_present_before_first_read() {
        let mut r = Rng::new().with_fault(fault("seed:0"));
        assert_eq!(r.read(SR, 4), SR_SECS | SR_SEIS);
        assert_eq!(r.read(DR, 4), 0);

        let mut r = Rng::new().with_fault(fault("clock:0:sticky"));
        r.write(CR, 4, CR_RNGEN);
        assert_eq!(r.read(SR, 4), SR_CECS | SR_CEIS);

        // One read later is a different fault from zero reads.
        let mut r = Rng::new().with_fault(fault("seed:1:sticky"));
        r.write(CR, 4, CR_RNGEN);
        assert_eq!(r.read(SR, 4), SR_DRDY);
        r.read(DR, 4);
        assert_eq!(r.read(SR, 4), SR_SECS | SR_SEIS);
    }

    #[test]
    fn sticky_seed_error_never_recovers() {
        let mut r = Rng::new().with_fault(fault("seed:0:sticky"));
        r.write(CR, 4, CR_RNGEN);
        r.read(DR, 4);
        for _ in 0..4 {
            r.write(SR, 4, 0);
            r.write(CR, 4, 0);
            r.write(CR, 4, CR_RNGEN);
            assert_eq!(r.read(SR, 4), SR_SECS);
        }
    }

    #[test]
    fn clock_glitch_clears_by_itself() {
        let mut r = Rng::new().with_fault(fault("clock:2"));
        r.write(CR, 4, CR_RNGEN);
        drain(&mut r, 2);
        assert_eq!(r.read(SR, 4), SR_CECS | SR_CEIS);
        let mut polls = 1;
        while r.read(SR, 4) & SR_DRDY == 0 {
            polls += 1;
            assert!(polls <= CLOCK_GLITCH_SR_READS, "clock glitch never cleared");
        }
        // CEIS stays latched until software clears it.
        assert_eq!(r.read(SR, 4), SR_DRDY | SR_CEIS);
        r.write(SR, 4, !SR_CEIS);
        assert_eq!(r.read(SR, 4), SR_DRDY);
    }

    #[test]
    fn sticky_clock_error_holds_drdy_low() {
        let mut r = Rng::new().with_fault(fault("clock:1:sticky"));
        r.write(CR, 4, CR_RNGEN);
        drain(&mut r, 1);
        for _ in 0..(CLOCK_GLITCH_SR_READS * 4) {
            assert_eq!(r.read(SR, 4), SR_CECS | SR_CEIS);
        }
    }
}

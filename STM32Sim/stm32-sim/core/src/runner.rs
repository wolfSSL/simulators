/* runner.rs
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

use anyhow::Result;
use std::time::{Duration, Instant};

use crate::cpu::{Cpu, CpuStop};

#[derive(Debug, Clone)]
pub struct ExitCondition {
    /// Address of a u32 the firmware sets nonzero when the test is done.
    pub flag_address: Option<u64>,
    /// Address of a u32 holding the wolfCrypt return value (0 = pass).
    pub result_address: Option<u64>,
    /// Wall-clock deadline.
    pub timeout: Duration,
    /// Instructions per emu_start slice. Smaller = more responsive
    /// flag/timeout polling, more overhead.
    pub slice_instructions: u64,
}

impl Default for ExitCondition {
    fn default() -> Self {
        Self {
            flag_address: None,
            result_address: None,
            timeout: Duration::from_secs(300),
            slice_instructions: 5_000_000,
        }
    }
}

#[derive(Debug)]
pub enum RunOutcome {
    Pass {
        result: u32,
        elapsed: Duration,
    },
    Fail {
        result: u32,
        elapsed: Duration,
    },
    Timeout {
        elapsed: Duration,
    },
    Fault {
        pc: u64,
        elapsed: Duration,
    },
}

pub struct Runner {
    cpu: Cpu,
    exit: ExitCondition,
}

impl Runner {
    pub fn new(cpu: Cpu, exit: ExitCondition) -> Self {
        Self { cpu, exit }
    }

    pub fn run(mut self) -> Result<RunOutcome> {
        let start = Instant::now();
        loop {
            let stop = self.cpu.run(self.exit.slice_instructions)?;

            if let Some(flag_addr) = self.exit.flag_address {
                if self.cpu.read_u32(flag_addr)? != 0 {
                    let result = match self.exit.result_address {
                        Some(a) => self.cpu.read_u32(a)?,
                        None => 0,
                    };
                    let elapsed = start.elapsed();
                    return Ok(if result == 0 {
                        RunOutcome::Pass { result, elapsed }
                    } else {
                        RunOutcome::Fail { result, elapsed }
                    });
                }
            }

            if matches!(stop, CpuStop::Fault) {
                let pc = self.cpu.read_pc().unwrap_or(0);
                return Ok(RunOutcome::Fault {
                    pc,
                    elapsed: start.elapsed(),
                });
            }

            if start.elapsed() > self.exit.timeout {
                return Ok(RunOutcome::Timeout {
                    elapsed: start.elapsed(),
                });
            }
        }
    }
}

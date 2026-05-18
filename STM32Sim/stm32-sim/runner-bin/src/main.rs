/* main.rs
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

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use stm32_sim_core::{Cpu, ElfImage, ExitCondition, RunOutcome, Runner};

#[derive(Parser, Debug)]
#[command(version, about = "wolfSSL STM32 simulator runner")]
struct Args {
    /// Chip target (e.g. stm32h753, stm32u575, stm32u585; pass
    /// --list-chips for the full list).
    #[arg(long, default_value = "stm32h753")]
    chip: String,

    /// Wall-clock timeout in seconds.
    #[arg(long, default_value_t = 300)]
    timeout: u64,

    /// Symbol name of a u32 the firmware sets to nonzero when finished.
    #[arg(long, default_value = "test_complete")]
    exit_on: String,

    /// Symbol name of the wolfCrypt result u32 (0 = pass).
    #[arg(long, default_value = "test_result")]
    result_symbol: String,

    /// List supported chips and exit.
    #[arg(long)]
    list_chips: bool,

    /// ELF file to load.
    elf: Option<PathBuf>,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if args.list_chips {
        for c in stm32_sim_chips::list() {
            println!("{c}");
        }
        return ExitCode::SUCCESS;
    }

    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Args) -> Result<ExitCode> {
    let elf_path = args
        .elf
        .clone()
        .ok_or_else(|| anyhow!("ELF path required (or pass --list-chips)"))?;

    let chip = stm32_sim_chips::build(&args.chip)?;

    let image = ElfImage::from_path_with_kind(&elf_path, chip.cpu_kind)
        .with_context(|| format!("loading {}", elf_path.display()))?;

    let mut cpu = Cpu::new_with_kind(&chip.memory_regions, chip.cpu_kind)?;
    cpu.ensure_segments_fit(&image, &chip.memory_regions)?;
    cpu.install_bus(chip.bus)?;
    cpu.load_elf(&image)?;

    let exit = ExitCondition {
        flag_address: image.symbol(&args.exit_on),
        result_address: image.symbol(&args.result_symbol),
        timeout: Duration::from_secs(args.timeout),
        ..Default::default()
    };

    if exit.flag_address.is_none() {
        log::warn!(
            "exit-on symbol `{}` not found in ELF; runner will only stop on timeout/fault",
            args.exit_on
        );
    }
    if exit.result_address.is_none() {
        log::warn!(
            "result symbol `{}` not found in ELF; result will be reported as 0 (PASS) regardless of the firmware's actual outcome",
            args.result_symbol
        );
    }

    let outcome = Runner::new(cpu, exit).run()?;

    match outcome {
        RunOutcome::Pass { result, elapsed } => {
            log::info!("PASS (result={result}, elapsed={:?})", elapsed);
            Ok(ExitCode::SUCCESS)
        }
        RunOutcome::Fail { result, elapsed } => {
            log::error!("FAIL (result={result}, elapsed={:?})", elapsed);
            Ok(ExitCode::FAILURE)
        }
        RunOutcome::Timeout { elapsed } => {
            log::error!("TIMEOUT after {:?}", elapsed);
            Ok(ExitCode::from(3))
        }
        RunOutcome::Fault { pc, elapsed } => {
            log::error!("FAULT at PC=0x{pc:08x} after {:?}", elapsed);
            Ok(ExitCode::from(4))
        }
    }
}

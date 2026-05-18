/* main.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of PIC32MZSim.
 *
 * PIC32MZSim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * PIC32MZSim is distributed in the hope that it will be useful,
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

use pic32mz_sim_core::{Cpu, ElfImage, ExitCondition, RunOutcome, Runner};

#[derive(Parser, Debug)]
#[command(version, about = "wolfSSL PIC32MZ simulator runner")]
struct Args {
    /// Chip target: pic32mz2048ech144 (alias `ec`) or
    /// pic32mz2048efh144 (alias `ef`).
    #[arg(long, default_value = "pic32mz2048efh144")]
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

    /// Instructions per emu_start slice. Lower values poll the exit
    /// flag more often; higher values reduce overhead. 100k strikes a
    /// reasonable balance for a CE driven by tight polling loops.
    #[arg(long, default_value_t = 100_000)]
    slice: u64,

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
        for c in pic32mz_sim_chips::list() {
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
    let image = ElfImage::from_path(&elf_path)
        .with_context(|| format!("loading {}", elf_path.display()))?;

    let chip = pic32mz_sim_chips::build(&args.chip)?;
    log::info!("chip built");

    let mut cpu = Cpu::new(&chip.memory_regions)?;
    log::info!("cpu created");
    cpu.ensure_segments_fit(&image, &chip.memory_regions)?;
    log::info!("segments fit");
    cpu.install_bus(chip.bus)?;
    log::info!("bus installed");
    cpu.load_elf(&image)?;
    log::info!("elf loaded; entry=0x{:x}", image.entry_point);

    let exit = ExitCondition {
        flag_address: image.symbol(&args.exit_on),
        result_address: image.symbol(&args.result_symbol),
        timeout: Duration::from_secs(args.timeout),
        slice_instructions: args.slice,
    };

    if exit.flag_address.is_none() {
        log::warn!(
            "exit-on symbol `{}` not found in ELF; runner will only stop on timeout/fault",
            args.exit_on
        );
    }
    if exit.result_address.is_none() {
        log::warn!(
            "result symbol `{}` not found in ELF; result will be reported as 0 regardless of the firmware's actual outcome",
            args.result_symbol
        );
    }

    let outcome = Runner::new(cpu, exit).run()?;

    log::info!(
        "block-hook polling ticks: {}",
        pic32mz_sim_core::tick_count()
    );

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
            let last_block_pc = pic32mz_sim_core::last_pc();
            let last_code = pic32mz_sim_core::last_code_pc();
            let mem_fault = pic32mz_sim_core::last_mem_fault()
                .unwrap_or_else(|| "<none>".to_string());
            log::error!(
                "FAULT at PC=0x{pc:08x} (last instr=0x{last_code:08x}, last block start=0x{last_block_pc:08x}, mem={mem_fault}) after {:?}",
                elapsed
            );
            Ok(ExitCode::from(4))
        }
    }
}

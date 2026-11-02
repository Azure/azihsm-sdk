// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::env;
use std::fs;
use std::path::PathBuf;

use azihsm_fw_uno_reg_soc::io_gsram;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let code_start = io_gsram::IO_GSRAM_BASE + io_gsram::HSM_CODE_OFFSET;
    let io_end = io_gsram::IO_GSRAM_BASE
        + io_gsram::SRAM_IO_BUF_OFFSET
        + io_gsram::SRAM_IO_BUF_COUNT * io_gsram::SRAM_IO_BUF_STRIDE;
    assert!(io_end <= code_start, "SRAM_IO_BUF overlaps HSM_CODE");
    fs::write(
        out.join("gsram-memory.x"),
        format!(
            "MEMORY {{ GSRAM_CODE : ORIGIN = {code_start:#x}, LENGTH = {:#x} }}\n",
            io_gsram::HSM_CODE_SIZE,
        ),
    )
    .unwrap();

    // Copy memory.x to OUT_DIR so the linker can find it.
    // memory.x lives at the platform workspace root (one level up from app/).
    let memory_x = manifest.join("../memory.x");
    fs::copy(&memory_x, out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", memory_x.display());

    let gsram_x = manifest.join("../gsram.x");
    fs::copy(&gsram_x, out.join("gsram.x")).unwrap();
    println!("cargo:rerun-if-changed={}", gsram_x.display());

    // Force the linker to keep Embassy trace hook symbols
    // even under LTO, so profiling works correctly.
    println!("cargo:rustc-link-arg=--undefined=_embassy_trace_task_exec_begin");
    println!("cargo:rustc-link-arg=--undefined=_embassy_trace_task_exec_end");
    println!("cargo:rustc-link-arg=--undefined=_embassy_trace_executor_idle");
}

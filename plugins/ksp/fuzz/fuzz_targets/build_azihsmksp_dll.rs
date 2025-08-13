// Copyright (C) Microsoft Corporation. All rights reserved.

/// This program is not a real fuzzing target. Instead, it provides a way to
/// invoke cargo-fuzz's build routine to build the AZIHSM KSP DLL
/// (`azihsmksp.dll`) for fuzzing.
///
/// When cargo-fuzz builds fuzzing targets on Windows, it adds the
/// `/include:main` linker argument, which is passed to the MSVC linker. The
/// goal of adding this argument is to force fuzzing targets, once compiled, to
/// be able to find LibFuzzer's `main` function during the linking stage.
///
/// The problem this introduces with our use-case of cargo-fuzz is the fact that
/// we're trying to build a DLL (`azihsmksp.dll`) for fuzzing. DLLs should *not*
/// have the `main` symbol included in them; rather, they should be loaded in by
/// another program which has access to a `main` function. So, when cargo-fuzz
/// builds the AZIHSM KSP in this way, it fails with this linker error:
///
/// ```
/// LINK : error LNK2001: unresolved external symbol main
/// C:\....\azihsmksp.dll : fatal error LNK1120: 1 unresolved externals
/// ```
///
/// If we force cargo-fuzz to *not* add `/include:main` to its `cargo build`
/// arguments, then the DLL will build just fine, but then, any valid fuzzing
/// targets will fail to build, due to not actually having access to a `main`
/// symbol (i.e. we are defeating the purpose of `/include:main`. We're solving
/// one problem but creating another.)
///
/// To get around this issue, this program is a "dummy" fuzzing target, which
/// provides its own `main` function. We can run:
///
/// ```powershell
/// cargo fuzz run THIS_FUZZING_TARGET
/// ```
///
/// Along with forcing cargo-fuzz to *not* use the `/include:main` linker
/// argument, to build all dependencies (including `azihsmksp.dll`) for fuzzing,
/// while also building a valid program with a `main` function.
// Imports
use std::env;
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

// Globals
const DLL_NAME: &str = "azihsmksp.dll";

/// Searches for the AZIHSM KSP DLL within the fuzzing project directory.
fn find_dll(target_dir: &PathBuf) -> Result<PathBuf, String> {
    for result in WalkDir::new(target_dir.to_str().unwrap()) {
        if let Err(err) = result {
            return Err(String::from(format!(
                "failed to retrieve directory entry: {:?}",
                err
            )));
        }
        let entry = result.unwrap();

        // skip any entries that aren't files
        if !entry.file_type().is_file() {
            continue;
        }

        // does the file name match the expected DLL name?
        if entry.file_name().eq(DLL_NAME) {
            return Ok(PathBuf::from(entry.path()));
        }
    }

    Err(String::from(format!(
        "failed to find DLL within `{}`",
        target_dir.to_str().unwrap()
    )))
}

/// Installs the DLL at the given path to System32.
fn install_dll(dll_src: &PathBuf, dll_dst: &PathBuf) -> Result<(), String> {
    let result = fs::copy(dll_src.as_path(), dll_dst.as_path());
    if result.is_err() {
        return Err(String::from(format!(
            "failed to copy DLL to `{}`",
            dll_dst.to_str().unwrap()
        )));
    }
    Ok(())
}

// Main function.
pub fn main() {
    println!("    _    _______ _  _ ___ __  __    _  _____ ___    ___ _   _ ________");
    println!("   /_\\  |_  /_ _| || / __|  \\/  |  | |/ / __| _ \\  | __| | | |_  /_  /");
    println!("  / _ \\  / / | || __ \\__ \\ |\\/| |  | ' <\\__ \\  _/  | _|| |_| |/ / / / ");
    println!(" /_/ \\_\\/___|___|_||_|___/_|  |_|  |_|\\_\\___/_|    |_|  \\___//___/___|");
    println!("");
    println!("Successfully built the KSP DLL for fuzzing.");

    // build a path to which the DLL should be installed
    let mut dll_destination = PathBuf::from("C:\\Windows\\System32");
    dll_destination.push(DLL_NAME);

    // look for the `CARGO_TARGET_DIR` environment variable to determine where
    // to look for the DLL that was just built
    let mut target_dir = PathBuf::new();
    if let Ok(target_path) = env::var("CARGO_TARGET_DIR") {
        target_dir.push(target_path);
    } else {
        panic!("Couldn't find `CARGO_TARGET_DIR` (the environment variable was not set).");
    }
    
    // search for the DLL within the target directory
    let result = find_dll(&target_dir);
    if let Err(msg) = result {
        panic!(
            "Couldn't find DLL: {}. \
             Please manually find the KSP DLL (`{}`) and install it to `{}`.",
            msg,
            DLL_NAME,
            dll_destination.to_str().unwrap()
        );
    }
    let dll_path = result.unwrap();
    println!(
        "Found the instrumented DLL: `{}`.",
        dll_path.to_str().unwrap()
    );

    // install the DLL to System32
    let result = install_dll(&dll_path, &dll_destination);
    if let Err(msg) = result {
        panic!(
            "Couldn't install DLL: {}. \
             Please manually find the KSP DLL (`{}`) and install it to `{}`.",
            msg,
            DLL_NAME,
            dll_destination.to_str().unwrap()
        );
    }
    println!(
        "Installed the DLL to: `{}`.",
        dll_destination.to_str().unwrap()
    );

    println!("");
    println!("Done! The DLL has been built and installed.");
    println!("If you haven't done so yet, run the following one-time-setup command:");
    println!("\n    regsvr32 {}\n", dll_destination.to_str().unwrap());
    println!("After that, you're ready to fuzz.");
    println!(" 1. Run `cargo fuzz list` to view all possible fuzz targets");
    println!(" 2. Run `cargo fuzz run FUZZ_TARGET_NAME` to run a target.");
}

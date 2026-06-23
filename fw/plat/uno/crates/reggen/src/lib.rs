// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::collapsible_if, clippy::collapsible_match)]

//! Register code generator.
//!
//! Takes a SystemRDL AST (from [`azihsm_systemrdl`]) and generates:
//! - **Firmware registers**: tock-style `register_bitfields!` definitions
//! - **Peripheral devices**: `BusDevice` implementations (for host emulator)

pub mod devs;
pub mod regs;
pub mod schema;
pub mod translate;

/// Sanitize a description string for use in Rust comments/doc attributes.
/// Replaces newlines with spaces and strips stray quotes.
pub(crate) fn sanitize_desc(s: &str) -> String {
    s.replace('\n', " ")
        .replace('\r', "")
        .replace('"', "'")
        .trim()
        .to_string()
}

/// Run `rustfmt` on a source string, returning the formatted result.
/// Falls back to the original string if `rustfmt` is unavailable or fails.
/// Uses nightly rustfmt with `imports_granularity = "Crate"` to match the
/// project's `rustfmt.toml` settings.
pub(crate) fn run_rustfmt(code: &str) -> String {
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;

    let mut child = match Command::new("rustup")
        .args([
            "run",
            "nightly",
            "rustfmt",
            "--edition",
            "2021",
            "--config",
            "imports_granularity=Item,group_imports=StdExternalCrate",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return code.to_string(),
    };

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(code.as_bytes())
        .unwrap();

    match child.wait_with_output() {
        Ok(output) if output.status.success() => {
            String::from_utf8(output.stdout).unwrap_or_else(|_| code.to_string())
        }
        _ => code.to_string(),
    }
}

/// Clean up extra spacing introduced by `quote!`'s `TokenStream::to_string()`.
pub(crate) fn fixup_quote_spacing(s: &str) -> String {
    s.replace(" ::", "::")
        .replace(":: ", "::")
        .replace("OFFSET (", "OFFSET(")
        .replace("NUMBITS (", "NUMBITS(")
        .replace(" ;", ";")
        .replace(" ,", ",")
}

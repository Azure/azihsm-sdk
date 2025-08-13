// Copyright (C) Microsoft Corporation. All rights reserved.

use clap::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct CliArgs {
    /// Converting from format
    #[arg(long, default_value_t = From::Hex, value_enum)]
    pub(crate) from: From,

    /// Converting to format
    #[arg(long, default_value_t = To::Debug, value_enum)]
    pub(crate) to: To,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
pub(crate) enum From {
    /// Hex-encoded bytes: 0x01, 0x02, 0x03 ... or 01, 02, 03... or 01 02 03... (ignore spaces, commas, and 0x, separator needed: either comma or space or both)
    Hex,

    /// Bytes: 1, 122, 253... or 1 122 253... (ignore spaces, commas etc, separator needed: either comma or space or both)
    Bytes,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
pub(crate) enum To {
    /// MBOR Debug format
    Debug,
}

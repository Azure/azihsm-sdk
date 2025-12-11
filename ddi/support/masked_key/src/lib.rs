// Copyright (C) Microsoft Corporation. All rights reserved.

mod decode;
mod encode;
mod helpers;

#[cfg(test)]
mod test_utils;

// Re-export the main functions to make them accessible from the crate root.
pub use decode::*;
pub use encode::*;
pub use helpers::*;
#[cfg(test)]
pub(crate) use test_utils::*;

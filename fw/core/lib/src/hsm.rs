// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level HSM application struct.
//!
//! [`Hsm`] owns the platform abstraction layer and drives the
//! application lifecycle. The concrete PAL type is supplied by the
//! platform crate (e.g. `fw/plat/std/lib`), which also provides the
//! Embassy task wiring and global static.

use super::*;

/// The top-level HSM application, generic over the platform abstraction
/// layer.
///
/// A single `Hsm<P>` lives in a platform-owned `OnceLock`. All Embassy
/// tasks access it through that global rather than receiving a reference,
/// because Embassy task functions cannot capture borrows.
pub struct Hsm<P: HsmPal> {
    /// The platform abstraction layer.
    pal: P,
}

impl<P: HsmPal> Hsm<P> {
    /// Creates a new `Hsm` wrapping the given PAL.
    pub fn new(pal: P) -> Self {
        Self { pal }
    }

    /// Returns a reference to the PAL.
    pub fn pal(&self) -> &P {
        &self.pal
    }
}

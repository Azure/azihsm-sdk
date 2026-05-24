// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test binary for `azihsm_ddi_tbor_types`.
//!
//! Placeholder — real tests will land alongside the first TBOR-migrated
//! DDI command (`GetApiRev`).

#[test]
fn crate_compiles() {
    // Sanity check — exercise the crate's re-exports so they don't
    // bit-rot before the first real TBOR command lands.
    let _ = core::any::type_name::<azihsm_ddi_tbor_types::codec::RequestEncoder<'_>>();
}

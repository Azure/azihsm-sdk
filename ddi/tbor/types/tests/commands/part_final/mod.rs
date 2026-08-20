// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `PartFinal` command.
//!
//! `PartFinal` runs after `PartInit` and finalizes the partition: it
//! validates the supplied PTA certificate chain (POTA-anchored, terminal
//! cert == partition PTA key), derives the partition-local masking keys,
//! and returns the current `local_mk` backup.
//!
//! Submodules are split by whether the test needs the **out-of-band**
//! certificate transport, because that is what decides where it can run:
//!
//! * [`fw_rejects`] — handler gates that fire *before* the cert-chain
//!   walk, so they pass an empty `certs` slice and reference no
//!   out-of-band page.
//! * [`chain_path`] — everything that supplies a real chain, carried
//!   out of band. Both transports implement this (`ddi/emu` writes the
//!   Metadata Page itself; `ddi/nix` goes through the driver's
//!   data-transfer ioctl), so these run on emu and hardware alike.
//!
//! Cross-test isolation comes from [`TestCtx::new`] (factory-reset +
//! process-global lock held for the ctx's lifetime), so each test starts
//! from a pristine `Enabled` partition with the canonical default PSKs.
//!
//! Bootstrap helpers and the wire-correct policy/seed/thumbprint
//! fixtures are shared with `PartInit` and re-exported here via
//! `use super::part_init::*`-style imports so each submodule can reach
//! them through `super::*`.

pub(super) use crate::commands::part_init::bootstrap_rotated_co;
pub(super) use crate::commands::part_init::known_good_part_policy;
pub(super) use crate::commands::part_init::mach_seed;
pub(super) use crate::commands::part_init::pota_thumbprint;
pub(super) use crate::commands::part_init::ROTATED_CO_PSK;
pub(super) use crate::harness::TestCtx;

mod chain_path;
mod fw_rejects;

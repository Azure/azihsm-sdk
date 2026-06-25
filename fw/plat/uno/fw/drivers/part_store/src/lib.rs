// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GSRAM-backed partition persistent store for the Uno platform.
//!
//! This driver owns the SoC-specific knowledge of where each partition's
//! persistent store lives in GSRAM and how its fields are laid out, so the
//! PAL's partition implementation can stay free of `reg_soc` dependencies.
//!
//! The on-storage [`Storage`] layout mirrors the reference firmware's
//! `HsmPartPersistentStore` byte-for-byte for the fields it shares (version,
//! flags, session table, lockout policy, VM-launch GUID, partition identity,
//! certificate, masked boot key, sealed BK3, nonce, BK3 session key); the
//! two Uno-specific fields (`policy_hash`, `pota_thumbprint`) are appended
//! flat into the reference layout's trailing reserved region, so no shared
//! field offset moves.
//!
//! GSRAM is plain shared SRAM (not a peripheral), so the accessors use
//! ordinary non-volatile reads/writes. The platform-agnostic partition logic
//! lives in the PAL; this driver only provides the storage substrate. Byte
//! buffers are handed out as [`DmaBuf`](azihsm_fw_hsm_pal_traits::DmaBuf) so
//! the PAL can feed them straight to the crypto / DMA engines.

#![no_std]
#![allow(unsafe_code)]

mod part_store;

pub use part_store::PartStore;
pub use part_store::Partition;
pub use part_store::PinPolicy;
pub use part_store::PinPolicyState;
pub use part_store::NUM_PARTITIONS;
pub use part_store::STORE_VERSION;

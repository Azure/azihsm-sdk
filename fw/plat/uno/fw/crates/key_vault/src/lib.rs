// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno HSM key vault — core storage logic.
//!
//! A `no_std` implementation of the per-partition key store backing the
//! Uno PAL's [`HsmVault`] trait. Keys are held in GSRAM using the
//! reference firmware's table layout (typed via the generated
//! [`KeyVaultTableTRegs`]), so key IDs, sizes, and on-storage bytes are
//! interchangeable with that firmware.
//!
//! The crate is deliberately platform-light so its allocator, layout, and
//! error mapping can be unit-tested on the host: storage is the typed RDL
//! struct (overlaid on real GSRAM in firmware, on owned memory in tests),
//! and large-key DMA copy/zeroize go through the
//! [`HsmGdmaController`](azihsm_fw_hsm_pal_traits::HsmGdmaController) trait
//! (real GDMA in firmware, a CPU fake in tests).
//!
//! [`KeyVaultTableTRegs`]: azihsm_fw_uno_reg_soc::key_vault_table_t::regs::KeyVaultTableTRegs
//! [`HsmVault`]: azihsm_fw_hsm_pal_traits::HsmVault

#![cfg_attr(not(test), no_std)]

mod block;
mod entry;
mod kind;
mod storage;
mod vault;

pub use entry::Entry;
pub use kind::key_len;
pub use kind::KeyLen;
pub use storage::TableStorage;
pub use storage::ATTRIBUTES_BLOB_SIZE;
pub use storage::BITMAP_WORDS;
pub use storage::BLOB_BLOCKS;
pub use storage::BLOB_SIZE;
pub use storage::BLOCK_ALIGNMENT;
pub use storage::ENTRIES_PER_TABLE;
pub use storage::MAX_TABLE_COUNT;
pub use vault::KeyVault;
pub use vault::DMA_THRESHOLD;

#[cfg(test)]
mod tests;

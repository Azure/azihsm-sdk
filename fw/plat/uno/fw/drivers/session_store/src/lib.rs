// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Persistent session indirection table for the Uno platform.
//!
//! Maps logical session IDs (the stable IDs handed to the host) to
//! physical vault key IDs (where the session masking key lives). The
//! indirection keeps customer-visible session IDs stable across physical
//! remaps (live migration / disaster recovery), so it is the *persistent*
//! subset of the session manager's state.
//!
//! This driver owns only that persistent subset — `alloc_mask`,
//! `renego_mask`, and the logical→physical map — which is exactly the
//! 18-byte `session_table` region carried in each partition's persistent
//! store. It reaches that region through the partition-store driver's
//! [`Partition`](azihsm_fw_uno_drivers_part_store::Partition) handle, so the
//! GSRAM addressing lives in one place.
//!
//! The volatile session state (in-flight handshake / Pending slots, the
//! one-shot PSK-change budget, eviction sequencing) is NOT here — it lives
//! in the PAL's DTCM partition struct and is managed separately.

#![no_std]

mod session_store;

pub use session_store::SessionStore;
pub use session_store::SessionTable;
pub use session_store::MAX_SESSIONS;
pub use session_store::SESSION_STORE_LEN;

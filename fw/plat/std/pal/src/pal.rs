// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standard (host-native) Platform Abstraction Layer (PAL).
//!
//! This module defines [`StdHsmPal`], the host-native PAL that runs on a
//! standard OS (Linux/Windows) using tokio for async scheduling. It
//! implements the [`HsmPal`] supertrait, which bundles:
//!
//! - [`HsmIoController`] — IO request receive / completion send (via channels)
//! - [`HsmGdmaController`] — memory copy (simulated, no real DMA hardware)
//! - [`HsmCrypto`] — cryptographic primitives (delegates to `HsmRng`)
//! - [`HsmPartitionManager`] — partition queries (currently stubbed)
//!
//! On a real Cortex-M7 target, a different PAL implementation would be
//! selected at compile time via the `pal-std` feature flag in
//! `azihsm_fw_hsm_core`.
//!
//! ## Ownership model
//!
//! `StdHsmPal` can be constructed in two ways:
//!
//! 1. **[`new`](StdHsmPal::new)** — caller provides channel endpoints and a
//!    tokio handle. The caller owns the runtime; `StdHsmPal` borrows it via
//!    the handle.
//!
//! 2. **[`Default`]** — creates its own single-threaded tokio runtime and
//!    dummy channels. Used primarily for trait-bound satisfaction in tests and
//!    default construction. The runtime is held in `_rt` to keep the handle
//!    valid for the PAL's lifetime.
//!
//! ## IO flow
//!
//! ```text
//! Host → [async_channel] → StdIic (iic) → core processes IO → StdOic (oic) → [async_channel] → Host
//!                                              ↕
//!                                         StdGdma (gdma)
//!                                     (simulated DMA copy)
//! ```

use std::cell::UnsafeCell;

use async_channel::Receiver;
use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex as EmbassyMutex;
use tokio::runtime::Handle;
use tokio::runtime::Runtime;

use crate::cert::SharedCertStore;
use crate::drivers::aes::StdAes;
use crate::drivers::ecc::StdEcc;
use crate::drivers::gdma::StdGdma;
use crate::drivers::hash::StdHash;
use crate::drivers::hmac::StdHmac;
use crate::drivers::iic::StdIic;
use crate::drivers::kdf::StdKdf;
use crate::drivers::oic::StdOic;
use crate::drivers::rsa::StdRsa;
use crate::io::HsmIoRequest;
use crate::part::PartitionTable;
use crate::part::NUM_PARTITIONS;
use crate::worker::WorkerPool;

/// Type alias for the per-partition async mutex.
///
/// `NoopRawMutex` is correct for single-threaded Embassy — no OS mutex
/// needed, just async yielding at contention points.
pub(crate) type PartMutex = EmbassyMutex<NoopRawMutex, ()>;

/// Host-native HSM Platform Abstraction Layer.
///
/// Provides a simulated hardware environment for running the HSM core on
/// a standard OS. Wraps three drivers and a worker pool:
///
/// - **[`StdIic`]** — Inbound IO controller. Receives [`HsmIoRequest`]s from
///   the host via an `async_channel` and manages the buffer pool for DMA
///   simulation.
/// - **[`StdOic`]** — Outbound IO controller. Sends [`HsmIoResponse`]s back
///   to the submitter via the per-IO oneshot reply channel.
/// - **[`StdGdma`]** — GDMA controller. Simulates DMA memory copies between
///   host and device memory using `memcpy`.
/// - **[`WorkerPool`]** — Tokio-backed thread pool for offloading async work
///   (e.g., simulated delays for crypto operations).
pub struct StdHsmPal {
    /// Inbound IO controller — receives requests and manages buffer pool.
    pub(crate) iic: StdIic,

    /// Outbound IO controller — sends completions.
    pub(crate) oic: StdOic,

    /// GDMA controller — memory copy.
    pub(crate) gdma: StdGdma,

    /// Hash driver — SHA digest computation.
    pub(crate) hash: StdHash,

    /// ECC driver — key generation, signing, verification, ECDH.
    pub(crate) ecc: StdEcc,

    /// AES driver — key generation, CBC, ECB encryption/decryption.
    pub(crate) aes: StdAes,

    /// HMAC driver — key generation, signing, verification.
    pub(crate) hmac: StdHmac,

    /// KDF driver — HKDF and KBKDF key derivation.
    pub(crate) kdf: StdKdf,

    /// RSA driver — key generation, modular exponentiation.
    pub(crate) rsa: StdRsa,

    /// Tokio-backed worker pool for offloading async work.
    #[allow(dead_code)]
    pub(crate) pool: WorkerPool,

    /// Partition table — stores state, identity, and keys for all 65
    /// partitions.
    ///
    /// Uses [`UnsafeCell`] so that `&self` trait methods can return
    /// borrowed slices and sideband alloc/free can mutate through `&self`.
    ///
    /// # Safety
    ///
    /// Access is safe because:
    /// - The Embassy executor is single-threaded.
    /// - Trait read methods are synchronous (no `.await`), so borrows
    ///   cannot span a yield point.
    /// - Alloc/free mutations happen in a separate Embassy task that
    ///   only runs between yield points, after all sync borrows are
    ///   dropped.
    pub(crate) part_table: UnsafeCell<PartitionTable>,

    /// Shared certificate store — Root CA, DeviceId CA, and Alias CA
    /// certs plus the Alias key pair for signing partition leaf certs.
    ///
    /// Uses [`UnsafeCell`] so that `init_cert_store` (async) can
    /// populate it after construction.  Immutable after initialization.
    pub(crate) cert_store: UnsafeCell<Box<SharedCertStore>>,

    /// Per-partition async locks for serializing state-modifying DDI
    /// handlers.  Stored separately from the partition table so the
    /// lock can be held across `.await` points without conflicting
    /// with `UnsafeCell` access to partition data.
    pub(crate) part_locks: Box<[PartMutex; NUM_PARTITIONS]>,

    /// Tokio runtime owned by this instance when constructed via [`Default`].
    ///
    /// `None` when constructed via [`new`](Self::new) — the caller owns the
    /// runtime. `Some` when constructed via `Default` so the runtime is kept
    /// alive as long as the `StdHsmPal` is alive.
    #[allow(dead_code)]
    _rt: Option<Runtime>,
}

impl core::fmt::Debug for StdHsmPal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StdHsmPal").finish()
    }
}

// SAFETY: StdHsmPal is only ever accessed from the single-threaded Embassy
// executor. The UnsafeCell<PartitionTable> is protected by the cooperative
// scheduling model — sync trait methods create temporary borrows that are
// dropped before the next yield point, and mutation only occurs in a
// separate Embassy task between yield points.
unsafe impl Sync for StdHsmPal {}

impl StdHsmPal {
    /// Create a new StdHsmPal with caller-provided channel endpoints and
    /// tokio handle.
    ///
    /// # Parameters
    /// - `submit_rx` — Receive end of the IO submission channel. The host
    ///   sends [`HsmIoRequest`]s through the corresponding sender.
    /// - `tokio_handle` — Handle to an existing tokio runtime for the
    ///   worker pool. The caller is responsible for keeping this runtime
    ///   alive.
    pub fn new(submit_rx: Receiver<HsmIoRequest>, tokio_handle: Handle) -> Self {
        Self {
            iic: StdIic::new(submit_rx),
            oic: StdOic::new(),
            gdma: StdGdma::new(),
            hash: StdHash::new(WorkerPool::new(tokio_handle.clone())),
            ecc: StdEcc::new(WorkerPool::new(tokio_handle.clone())),
            aes: StdAes::new(WorkerPool::new(tokio_handle.clone())),
            hmac: StdHmac::new(WorkerPool::new(tokio_handle.clone())),
            kdf: StdKdf::new(WorkerPool::new(tokio_handle.clone())),
            rsa: StdRsa::new(WorkerPool::new(tokio_handle.clone())),
            pool: WorkerPool::new(tokio_handle),
            part_table: UnsafeCell::new(PartitionTable::default()),
            cert_store: UnsafeCell::new(Box::new(SharedCertStore::new())),
            part_locks: Box::new(core::array::from_fn(|_| PartMutex::new(()))),
            _rt: None,
        }
    }
}

/// Default construction creates a self-contained PAL with its own
/// single-threaded tokio runtime and dummy channels.
///
/// The dummy channels are bounded(1) and immediately dropped on the other
/// end, so no real IO can flow. This is used for trait-bound satisfaction
/// and testing scenarios where the full IO pipeline is not needed.
impl Default for StdHsmPal {
    fn default() -> Self {
        let (_tx, rx) = async_channel::bounded(1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let handle = rt.handle().clone();
        Self {
            iic: StdIic::new(rx),
            oic: StdOic::new(),
            gdma: StdGdma::new(),
            hash: StdHash::new(WorkerPool::new(handle.clone())),
            ecc: StdEcc::new(WorkerPool::new(handle.clone())),
            aes: StdAes::new(WorkerPool::new(handle.clone())),
            hmac: StdHmac::new(WorkerPool::new(handle.clone())),
            kdf: StdKdf::new(WorkerPool::new(handle.clone())),
            rsa: StdRsa::new(WorkerPool::new(handle.clone())),
            pool: WorkerPool::new(handle),
            part_table: UnsafeCell::new(PartitionTable::default()),
            cert_store: UnsafeCell::new(Box::new(SharedCertStore::new())),
            part_locks: Box::new(core::array::from_fn(|_| PartMutex::new(()))),
            // Keep the runtime alive so `handle` remains valid.
            _rt: Some(rt),
        }
    }
}

/// [`HsmPal`] lifecycle implementation for the standard platform.
///
/// - **`init`** — Logs initialization; no hardware to configure.
/// - **`run`** — Pends forever (the core drives the event loop via Embassy
///   tasks, not through this method).
/// - **`deinit`** — No-op; resources are cleaned up on drop.
impl HsmPal for StdHsmPal {
    fn init(&self) {
        info!("pal", "initialized (std)");
    }

    async fn run(&self) {
        core::future::pending::<()>().await;
    }

    fn deinit(&self) {}
}

/// Marker impl — [`HsmCrypto`] is a supertrait of [`HsmRng`]. The actual
/// RNG implementation lives in [`crate::rng`].
impl HsmCrypto for StdHsmPal {}

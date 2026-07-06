// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::ops::AsyncFnOnce;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_reg_soc::io_gsram::UPKA_ENGINE_CMD_COUNT;
use embassy_sync::waitqueue::WakerRegistration;

use crate::engine::UpkaEngine;
use crate::pool::EngineSlot;
use crate::pool::QueueSlot;
use crate::pool::SpecificWaiter;
use crate::pool::UpkaState;
use crate::scheduler::Scheduler;
use crate::UpkaEccCurve;
use crate::UpkaRsaKeyType;

/// Async PKA driver.
///
/// Owns an `ENGINES`-engine pool with a `DEPTH`-deep waiter queue.
/// Each acquired [`UpkaEngine`] is exclusive until released back to the pool.
///
/// # Type Parameters
///
/// - `DEPTH`: Maximum number of concurrent waiters. Must be a power of 2,
///   at most 128.
/// - `ENGINES`: Number of hardware PKA engines. Must be 1–16.
pub struct UpkaDriver<const DEPTH: usize, const ENGINES: usize> {
    pub(crate) state: SingleCell<UpkaState<DEPTH, ENGINES>>,
}

impl<const DEPTH: usize, const ENGINES: usize> core::fmt::Debug for UpkaDriver<DEPTH, ENGINES> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpkaDriver")
            .field("DEPTH", &DEPTH)
            .field("ENGINES", &ENGINES)
            .finish()
    }
}

impl<const DEPTH: usize, const ENGINES: usize> UpkaDriver<DEPTH, ENGINES> {
    const _ASSERT_DEPTH_NONZERO: () = assert!(DEPTH > 0, "DEPTH must be > 0");
    const _ASSERT_DEPTH_POW2: () =
        assert!(DEPTH.is_power_of_two(), "DEP/wakeTH must be power of 2");
    const _ASSERT_DEPTH_MAX: () = assert!(DEPTH <= 128, "DEPTH must be <= 128 (u8 indices)");
    const _ASSERT_ENGINES_NONZERO: () = assert!(ENGINES > 0, "ENGINES must be > 0");
    const _ASSERT_ENGINES_MAX: () = assert!(ENGINES <= 16, "ENGINES must be <= 16 (u16 bitmask)");
    const _ASSERT_ENGINE_COUNT: () = assert!(
        UPKA_ENGINE_CMD_COUNT as usize == ENGINES,
        "UPKA_ENGINE_CMD_COUNT must match engine count"
    );

    // ---------------------------------------------------------------------
    // Construction and validation helpers
    // ---------------------------------------------------------------------

    /// Initialize the PKA engine pool.
    ///
    /// No MMIO setup is required. Engines are always present and command status
    /// is reported through the per-engine status registers.
    ///
    /// # Returns
    ///
    /// - A fully initialized driver with all engines marked free and waiter
    ///   state reset.
    ///
    /// # Panics
    ///
    /// Compile-time assertion if `DEPTH` is 0, not a power of 2, or exceeds 128.
    pub fn new() -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = (
            Self::_ASSERT_DEPTH_NONZERO,
            Self::_ASSERT_DEPTH_POW2,
            Self::_ASSERT_DEPTH_MAX,
            Self::_ASSERT_ENGINES_NONZERO,
            Self::_ASSERT_ENGINES_MAX,
            Self::_ASSERT_ENGINE_COUNT,
        );

        Self {
            state: SingleCell::new(UpkaState {
                free_mask: ((1u32 << ENGINES) - 1) as u16,
                engine_slots: core::array::from_fn(|_| EngineSlot {
                    waker: WakerRegistration::new(),
                    status: 0,
                    state: crate::EngineState::Idle,
                    completion_armed: false,
                }),
                specific_waiters: core::array::from_fn(|_| SpecificWaiter {
                    waker: WakerRegistration::new(),
                    waiting: false,
                    assigned: false,
                }),
                queue_slots: core::array::from_fn(|_| QueueSlot {
                    waker: WakerRegistration::new(),
                    state: crate::QueueSlotState::Free,
                }),
                queue_head: 0,
                queue_tail: 0,
            }),
        }
    }

    pub(crate) fn scheduler(&self) -> Scheduler<'_, DEPTH, ENGINES> {
        Scheduler::new(self)
    }

    /// Wake a specific engine by ID.
    ///
    /// Called from the per-engine Done/Error IRQ handler via the PAL
    /// WAKE_ENTRIES dispatch.
    ///
    /// # Parameters
    ///
    /// - `id`: Hardware engine index to poll and wake.
    ///
    /// # Returns
    ///
    /// - No return value. The method updates internal completion state and may
    ///   wake a waiting task.
    pub fn wake_engine(&self, id: u8) {
        self.scheduler().wake_engine(id);
    }

    pub(crate) fn release_engine(&self, id: u8) {
        self.scheduler().release_engine(id);
    }

    /// Acquire any free engine.
    ///
    /// # Returns
    ///
    /// - `Ok(UpkaEngine)`: Exclusive engine handle.
    /// - `Err(UpkaError::QUEUE_FULL)`: All waiter slots are occupied.
    pub async fn acquire_any(&self) -> HsmResult<UpkaEngine<'_, DEPTH, ENGINES>> {
        self.scheduler().acquire_any().await
    }

    /// Acquire a specific engine by ID.
    ///
    /// # Parameters
    ///
    /// - `target`: Engine index to acquire.
    ///
    /// # Returns
    ///
    /// - `Ok(UpkaEngine)`: Exclusive handle for the requested engine.
    /// - `Err(UpkaError::QUEUE_FULL)`: Another task is already waiting for the
    ///   same engine.
    /// - `Err(UpkaError::CMD_ERROR)`: Engine index is out of range.
    pub async fn acquire_engine(&self, target: u8) -> HsmResult<UpkaEngine<'_, DEPTH, ENGINES>> {
        self.scheduler().acquire_engine(target).await
    }

    /// Sign a digest using ECDSA.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `hash`: DMA-capable digest buffer.
    /// - `signature`: DMA-capable output buffer for `r || s`.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Signature was generated and written to `signature`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn ecc_sign(
        &self,
        curve: UpkaEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| eng.ecc_sign(curve, priv_key, hash, signature).await)
            .await
    }

    /// Verify an ECDSA signature.
    ///
    /// `result` is a caller-allocated DMA-capable buffer (at least 4 bytes)
    /// that receives the hardware status word.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `pub_key`: DMA-capable public key buffer.
    /// - `hash`: DMA-capable digest buffer.
    /// - `signature`: DMA-capable signature buffer.
    /// - `result`: DMA-capable output status word buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Verification completed and status is written to `result`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn ecc_verify(
        &self,
        curve: UpkaEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| {
            eng.ecc_verify(curve, pub_key, hash, signature, result)
                .await
        })
        .await
    }

    /// Generate an ECC key pair.
    ///
    /// Hardware writes `pub_key_hsm || priv_key_hsm` contiguously into
    /// `key_buf`.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `key_buf`: DMA-capable output buffer for generated key material.
    ///
    /// # Returns
    ///
    /// - `Ok(usize)`: Total HSM wire-format bytes written.
    /// - `Err(UpkaError::CMD_ERROR)`: Output buffer is too small or hardware
    ///   rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn ecc_gen_keypair(
        &self,
        curve: UpkaEccCurve,
        key_buf: &mut DmaBuf,
    ) -> HsmResult<usize> {
        self.with_engine(async |eng| eng.ecc_gen_keypair(curve, key_buf).await)
            .await
    }

    /// Derive an ECDH shared secret.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `pub_key`: DMA-capable peer public key buffer.
    /// - `secret`: DMA-capable output buffer for the derived secret.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Shared secret was written to `secret`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn ecdh_derive(
        &self,
        curve: UpkaEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| eng.ecdh_derive(curve, priv_key, pub_key, secret).await)
            .await
    }

    /// Run an RSA private-key modular exponentiation.
    ///
    /// `key_type` selects both modulus size and key format (standard or CRT).
    /// Input and output buffers must match the selected modulus size.
    ///
    /// # Parameters
    ///
    /// - `key_type`: RSA key type (size + format selector).
    /// - `key`: DMA-capable private key buffer.
    /// - `input`: DMA-capable input block buffer.
    /// - `output`: DMA-capable output block buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Result block was written to `output`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn rsa_mod_exp_priv(
        &self,
        key_type: UpkaRsaKeyType,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| eng.rsa_mod_exp_priv(key_type, key, input, output).await)
            .await
    }

    /// Run an RSA public-key modular exponentiation.
    ///
    /// `key_type` selects modulus size. Input and output buffers must match
    /// the selected modulus size.
    ///
    /// # Parameters
    ///
    /// - `key_type`: RSA key type (size selector for public exponent path).
    /// - `key`: DMA-capable public key buffer.
    /// - `input`: DMA-capable input block buffer.
    /// - `output`: DMA-capable output block buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Result block was written to `output`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn rsa_mod_exp_pub(
        &self,
        key_type: UpkaRsaKeyType,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| eng.rsa_mod_exp_pub(key_type, key, input, output).await)
            .await
    }

    /// Validate that a public key is on the specified ECC curve.
    ///
    /// `result` is a caller-allocated DMA-capable buffer (at least 4 bytes)
    /// that receives the hardware validation status word.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `pub_key`: DMA-capable public key buffer.
    /// - `result`: DMA-capable output status word buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Validation completed and status was written to `result`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn ecc_point_validate(
        &self,
        curve: UpkaEccCurve,
        pub_key: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| eng.ecc_point_validate(curve, pub_key, result).await)
            .await
    }

    /// Derive a public key from a private key.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `pub_key`: DMA-capable output buffer for the derived public key.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Public key was written to `pub_key`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    /// - `Err(UpkaError::QUEUE_FULL)`: No engine can be acquired.
    /// - `Err(UpkaError::WIPE_FAILED)`: Post-operation wipe failed.
    pub async fn ecc_gen_pub_key(
        &self,
        curve: UpkaEccCurve,
        priv_key: &DmaBuf,
        pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.with_engine(async |eng| eng.ecc_gen_pub_key(curve, priv_key, pub_key).await)
            .await
    }

    /// Wipe a specific engine by ID.
    ///
    /// # Parameters
    ///
    /// - `id`: Engine index to wipe.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Engine was wiped and released.
    /// - `Err(UpkaError::QUEUE_FULL)`: Another task is already waiting on this
    ///   engine.
    /// - `Err(UpkaError::CMD_ERROR)`: Engine index is out of range.
    /// - `Err(UpkaError::WIPE_FAILED)`: Wipe command failed.
    pub async fn wipe_engine(&self, id: u8) -> HsmResult<()> {
        let eng = self.acquire_engine(id).await?;
        eng.release().await
    }

    /// Wipe all engines.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: All engines were wiped successfully.
    /// - `Err(HsmError)`: First wipe failure encountered while iterating.
    pub async fn wipe_all_engines(&self) -> HsmResult<()> {
        for id in 0..ENGINES as u8 {
            self.wipe_engine(id).await?;
        }
        Ok(())
    }

    /// Execute an async closure on any free engine.
    ///
    /// The engine is automatically wiped and released after the closure
    /// completes, even if it returns an error.
    ///
    /// # Parameters
    ///
    /// - `f`: Async closure that receives a mutable engine reference.
    ///
    /// # Returns
    ///
    /// - `Ok(R)`: Closure result when operation and cleanup succeed.
    /// - `Err(HsmError)`: Operation error, or cleanup error if operation
    ///   succeeded but release failed.
    ///
    /// # Error Precedence
    ///
    /// If both operation and cleanup fail, the operation error is returned.
    pub async fn with_engine<F, R>(&self, f: F) -> HsmResult<R>
    where
        F: for<'a> AsyncFnOnce(&'a mut UpkaEngine<'_, DEPTH, ENGINES>) -> HsmResult<R>,
    {
        let mut eng = self.acquire_any().await?;
        let result = f(&mut eng).await;
        let release_result = eng.release().await;
        match (result, release_result) {
            (Err(primary_err), _) => Err(primary_err),
            (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    /// Execute a closure on a specific engine by ID.
    ///
    /// The engine is automatically wiped and released after the closure
    /// completes. Use for self-test or targeted operations.
    ///
    /// # Parameters
    ///
    /// - `id`: Engine index to acquire.
    /// - `f`: Async closure that receives a mutable engine reference.
    ///
    /// # Returns
    ///
    /// - `Ok(T)`: Closure result when operation and cleanup succeed.
    /// - `Err(HsmError)`: Operation error, or cleanup error if operation
    ///   succeeded but release failed.
    ///
    /// # Error Precedence
    ///
    /// If both operation and cleanup fail, the operation error is returned.
    pub async fn with_specific_engine<F, T>(&self, id: u8, f: F) -> HsmResult<T>
    where
        F: for<'a> AsyncFnOnce(&'a mut UpkaEngine<'_, DEPTH, ENGINES>) -> HsmResult<T>,
    {
        let mut eng = self.acquire_engine(id).await?;
        let result = f(&mut eng).await;
        let release_result = eng.release().await;
        match (result, release_result) {
            (Err(primary_err), _) => Err(primary_err),
            (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}

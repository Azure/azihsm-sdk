// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA (FIPS 204) post-quantum signatures.
//!
//! Unlike the other crypto traits here, this one exists because the
//! operations may not run on the core that receives the request at all. On
//! uno they are performed by FP1, which has the RAM for them and whose
//! wolfCrypt implementation is the one that can ship; the std platform runs
//! them in process. The command handlers are identical either way, which is
//! the point of putting this behind a trait rather than behind a `cfg`.
//!
//! # Parameter set
//!
//! A build speaks exactly one parameter set and every buffer length is fixed
//! by it, so none of these take a selector: an implementation checks the
//! lengths it is given against the set it was built for and rejects a
//! mismatch. Carrying the selector on the wire would imply the device could
//! switch, which it cannot.
//!
//! # Latency
//!
//! These are slow by the standards of everything else in this trait family.
//! An ML-DSA-87 signature measured a 461 ms median and 1,345 ms worst case on
//! FP1. They are `async` so the executor keeps running, but a caller should
//! not assume any of them is cheap.

use crate::HsmIo;
use crate::HsmResult;

/// ML-DSA key generation, signing and verification.
pub trait HsmMlDsa {
    /// Derives a keypair from `seed` (FIPS 204 KeyGen).
    ///
    /// Writes the encoded verifying key into `vk` and the encoded signing key
    /// into `sk`. Either may be empty when the caller does not want that
    /// half: `MlDsaKeyGen` returns the seed rather than the expanded signing
    /// key, so it asks only for the verifying key.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — both requested halves are written.
    /// - `Err(HsmError::MlDsaKeyGenFailed)` — generation failed, or a
    ///   requested buffer is not the length this parameter set produces.
    async fn ml_dsa_keygen(
        &self,
        io: &impl HsmIo,
        seed: &[u8; 32],
        vk: &mut [u8],
        sk: &mut [u8],
    ) -> HsmResult<()>;

    /// Signs `msg` under the encoded signing key `sk`.
    ///
    /// **Deterministic** (FIPS 204 with `rnd = 0^32`), so the same key and
    /// message always produce the same signature. Callers rely on that: it is
    /// what lets a test assert byte equality against an independent
    /// implementation rather than settling for "it verifies".
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `sig` holds the encoded signature.
    /// - `Err(HsmError::MlDsaInvalidSigningKey)` — `sk` is the right length
    ///   but not a well-formed key.
    /// - `Err(HsmError::InvalidArg)` — `sk` or `sig` is the wrong length.
    /// - `Err(HsmError::MlDsaSignFailed)` — signing failed.
    async fn ml_dsa_sign(
        &self,
        io: &impl HsmIo,
        sk: &[u8],
        msg: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()>;

    /// Verifies `sig` over `msg` under the encoded verifying key `vk`.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` / `Ok(false)` — the check completed; the signature is or
    ///   is not valid. A bad signature is a completed request with a negative
    ///   answer, not a failure, so the caller chooses the wire status.
    /// - `Err(HsmError::InvalidArg)` — `vk` or `sig` is the wrong length.
    async fn ml_dsa_verify(
        &self,
        io: &impl HsmIo,
        vk: &[u8],
        sig: &[u8],
        msg: &[u8],
    ) -> HsmResult<bool>;
}

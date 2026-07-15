// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC trait implementation for the Uno PAL.
//!
//! All curve arithmetic is performed by the on-chip PKA engine; this file
//! is a thin adapter that:
//!
//! 1. Maps the trait-level [`HsmEccCurve`] enum to the driver-level
//!    [`UpkaEccCurve`] enum via [`map_ecc_curve`].
//! 2. Forwards the public/private key, hash, and signature buffers to
//!    [`UnoHsmPal::pka`].
//! 3. Performs one piece of buffer surgery for
//!    [`HsmEcc::ecc_gen_keypair`]: the PKA driver writes
//!    `pub_key ‖ priv_key` contiguously into scoped scratch, so this
//!    layer splits that scratch and copies the two halves into the
//!    caller's separate output buffers.
//!
//! Pairwise Consistency Test (PCT) execution is currently a no-op — the
//! `_pct` parameter is accepted for API parity with the trait but no
//! self-test is run.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_upka::UpkaEccCurve;
use azihsm_fw_uno_drivers_upka::hash_size;
use azihsm_fw_uno_drivers_upka::hsm_point_size;

use crate::UnoHsmPal;

// =============================================================================
// Curve mapping
// =============================================================================

/// Translate the trait-level [`HsmEccCurve`] enum to the PKA driver's
/// [`UpkaEccCurve`] enum.
///
/// # Parameters
/// * `curve` — the curve identifier supplied by the caller.
///
/// # Returns
/// * `Ok(UpkaEccCurve)` — the corresponding driver-level variant
///   (`P256`, `P384`, or `P521`).
///
/// # Errors
/// * [`HsmError::InvalidArg`] if a future variant is added to
///   [`HsmEccCurve`] that this PAL does not yet support. The wildcard
///   arm exists so adding a new variant in the trait crate fails
///   gracefully at runtime instead of failing to compile here.
#[allow(unreachable_patterns)]
fn map_ecc_curve(curve: HsmEccCurve) -> HsmResult<UpkaEccCurve> {
    match curve {
        HsmEccCurve::P256 => Ok(UpkaEccCurve::P256),
        HsmEccCurve::P384 => Ok(UpkaEccCurve::P384),
        HsmEccCurve::P521 => Ok(UpkaEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// NIST P-256 prime modulus in PKA little-endian operand order.
const PRIME256_LE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-384 prime modulus in PKA little-endian operand order.
pub(super) const PRIME384_LE: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-521 prime modulus in PKA little-endian operand order (68-byte,
/// DWORD-aligned per PKA hardware requirement).
const PRIME521_LE: [u8; 68] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x01, 0x00, 0x00,
];

/// Curve prime modulus (PKA little-endian) for the Montgomery-constant setup.
fn curve_prime_le(curve: UpkaEccCurve) -> &'static [u8] {
    match curve {
        UpkaEccCurve::P256 => &PRIME256_LE,
        UpkaEccCurve::P384 => &PRIME384_LE,
        UpkaEccCurve::P521 => &PRIME521_LE,
    }
}

// =============================================================================
// HsmEcc trait impl
// =============================================================================
//
// The primary contract for each method (intended semantics, parameter
// shapes, error model) lives on the [`HsmEcc`] trait itself. The notes
// below describe only the Uno-specific behaviour and the buffer
// surgery `ecc_gen_keypair` performs on top of the PKA driver.

impl HsmEcc for UnoHsmPal {
    /// Generate an ECC key pair on the selected NIST curve.
    ///
    /// # Layout
    ///
    /// The PKA driver writes `pub_key ‖ priv_key` contiguously into a
    /// scratch buffer allocated from `alloc`. This PAL then copies the
    /// public and private halves into the caller's separate output
    /// buffers.
    ///
    /// `pub_len` is `2 * hsm_point_size(curve)` (X ‖ Y in HSM
    /// wire-format coordinates); `priv_len` is whatever remains of the
    /// `total_len` returned by the driver.
    ///
    /// # Parameters
    /// * `curve` — NIST curve to use ([`HsmEccCurve::P256`],
    ///   [`HsmEccCurve::P384`], or [`HsmEccCurve::P521`]).
    /// * `alloc` — scoped allocator used for the internal contiguous
    ///   `pub_key ‖ priv_key` PKA scratch buffer.
    /// * `out` — `None` to query required buffer sizes, or
    ///   `Some((priv_key, pub_key))` to generate into caller-provided
    ///   output buffers.
    /// * `_pct` — pairwise consistency test mode. Accepted for API
    ///   parity with the trait; no self-test is currently executed.
    ///
    /// # Returns
    /// * `Ok((priv_len, pub_len))` — the private and public key lengths.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if the supplied curve is not one of
    ///   P-256/P-384/P-521, or `out` is `Some` and either output buffer
    ///   is shorter than required.
    /// * Any [`HsmError`] surfaced by [`UnoHsmPal::pka.ecc_gen_keypair`]
    ///   or the scoped allocator.
    async fn ecc_gen_keypair(
        &self,
        _io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        let pka_curve = map_ecc_curve(curve)?;
        let priv_len = hsm_point_size(pka_curve);
        let pub_len = hsm_point_size(pka_curve) * 2;

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < pub_len {
            return Err(HsmError::InvalidArg);
        }

        let scratch = alloc.dma_alloc(pub_len + priv_len)?;
        let total_len = match self.pka.ecc_gen_keypair(pka_curve, scratch).await {
            Ok(n) => n,
            Err(e) => {
                // Keygen may have written partial key material into
                // `scratch`; wipe the whole buffer before it returns to the
                // per-IO pool (scope rewind does not clear DMA memory).
                scratch.zeroize();
                return Err(e);
            }
        };
        let (pub_key, priv_key) = scratch[..total_len].split_at(pub_len);

        priv_out[..priv_len].copy_from_slice(priv_key);
        pub_out[..pub_len].copy_from_slice(pub_key);

        // Scrub the private-scalar half of the scratch before returning:
        // scope rewind does not clear DMA memory, so the freshly generated
        // scalar would otherwise linger in — and leak through — a later
        // per-IO allocation. (The pub half is not secret.)
        scratch[pub_len..total_len].zeroize();

        Ok((priv_len, pub_len))
    }

    /// Deterministic ECC key generation from caller-supplied OKM is not
    /// yet implemented on this PAL.
    async fn ecc_gen_keypair_from_okm(
        &self,
        _io: &impl HsmIo,
        _alloc: &impl HsmScopedAlloc,
        _curve: HsmEccCurve,
        _okm: &DmaBuf,
        _out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        Err(HsmError::UnsupportedCmd)
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecc_sign`] after curve mapping.
    /// The PKA driver enforces the per-curve length requirements on
    /// `priv_key`, `hash`, and `signature`.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the key was generated on.
    /// * `priv_key` — signing key in the wire format produced by
    ///   [`Self::ecc_gen_keypair`].
    /// * `hash` — pre-computed hash digest to sign. Caller is responsible
    ///   for hashing the message first.
    /// * `signature` — destination buffer for `R ‖ S`. Must be at least
    ///   [`HsmEccCurve::sig_len`] bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success. `signature` contains the `R ‖ S` pair.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_sign(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;
        self.pka
            .ecc_sign(pka_curve, priv_key, hash, signature)
            .await
    }

    /// Raw EC verify of a signature over a pre-computed hash digest.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecc_verify`] after curve mapping.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the key was generated on.
    /// * `pub_key` — verification key as `(X ‖ Y)` in the wire format
    ///   produced by [`Self::ecc_gen_keypair`].
    /// * `hash` — pre-computed hash digest that was signed.
    /// * `signature` — `R ‖ S` signature pair to verify.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. malformed
    ///   inputs, hardware fault).
    async fn ecc_verify(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;

        let digest_len = hash_size(pka_curve);
        if hash.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        let prime_le = curve_prime_le(pka_curve);

        // Allocate the per-call PKA scratch (curve prime + transient
        // Montgomery-constant scratch) from a scoped heap so it is released
        // as soon as the verify completes rather than living for the whole
        // IO. A single IO that verifies several signatures (e.g. cert-chain
        // validation) would otherwise accumulate this scratch and can
        // exhaust the DMA pool.
        self.alloc_scoped_async(io, async |scope| {
            // The digest arrives PKA-native little-endian: the DDI handler
            // hashes big-endian and then fully byte-reverses it (a full BE->LE
            // reversal, not `hash(.., big_endian = false)`, which only swaps
            // within each 32-bit word). pub_key and signature likewise arrive
            // LE via the host DDI serde. No byte-order conversion is done below
            // the PAL.

            // Per-call Montgomery constant from the curve prime (like
            // ecdh_derive). `mont_result` is transient scratch consumed
            // internally by the driver's verify; it is not surfaced back.
            let prime = scope.dma_alloc(prime_le.len())?;
            prime.copy_from_slice(prime_le);
            let mont_result = scope.dma_alloc(prime_le.len())?;

            self.pka
                .ecc_verify(
                    pka_curve,
                    pub_key,
                    &hash[..digest_len],
                    signature,
                    result,
                    prime,
                    mont_result,
                )
                .await
        })
        .await
    }

    /// Derive an ECDH shared secret.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecdh_derive`] after curve mapping.
    ///
    /// # Parameters
    /// * `curve` — NIST curve both peers agreed on.
    /// * `priv_key` — local private key.
    /// * `pub_key` — remote party's public key as `(X ‖ Y)`.
    /// * `secret` — destination buffer for the derived shared secret.
    ///   Must be at least [`HsmEccCurve::secret_len`] bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success. `secret` contains the shared secret.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. invalid
    ///   public-key point, undersized buffer, hardware fault).
    async fn ecdh_derive(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;

        let prime_le = curve_prime_le(pka_curve);

        // Scope the per-call Montgomery scratch (curve prime + result) so it is
        // freed as soon as the point-multiply completes instead of living for
        // the whole IO; keeping it IO-bounded needlessly grows DMA-pool
        // pressure in multi-step flows.
        self.alloc_scoped_async(io, async |scope| {
            // The PKA point-multiply requires a per-call Montgomery constant
            // computed from the curve prime.
            let prime = scope.dma_alloc(prime_le.len())?;
            prime.copy_from_slice(prime_le);
            let mont_result = scope.dma_alloc(prime_le.len())?;

            self.pka
                .ecdh_derive(pka_curve, priv_key, pub_key, secret, prime, mont_result)
                .await?;

            // The shared secret is returned PKA-native little-endian, like
            // pub_key and priv_key. Any byte-order conversion (e.g. LE->BE for
            // an internal HKDF consumer that must match the host's openssl-BE
            // secret) is the DDI handler's responsibility, not the PAL's.
            Ok(())
        })
        .await
    }

    fn ecc_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        _der: &DmaBuf,
        _out: Option<&mut DmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        // TODO: parse the recovered PKCS#8 ECC private key on Uno and
        // re-export it in the vault representation (RsaUnwrap ECC import).
        Err(HsmError::UnsupportedCmd)
    }

    async fn ecc_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        _priv_key: &DmaBuf,
        _pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // TODO: derive the wire public key from a vault-stored ECC private
        // key on Uno PKA (RsaUnwrap ECC import).
        Err(HsmError::UnsupportedCmd)
    }

    /// Derive the public key from a raw private scalar (`pub = priv · G`).
    ///
    /// Delegates to [`UnoHsmPal::pka.ecc_gen_pub_key`] (PKA base-point
    /// scalar multiplication) after curve mapping. Both buffers are in
    /// the little-endian PKA wire format.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the private key is on.
    /// * `priv_key` — raw HSM-format private scalar
    ///   ([`HsmEccCurve::wire_priv_key_len`] bytes).
    /// * `pub_key` — output buffer for `X ‖ Y`
    ///   ([`HsmEccCurve::wire_pub_key_len`] bytes).
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is unsupported or a buffer is
    ///   undersized.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_pub_from_priv(
        &self,
        _io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;
        let wire_pub_len = curve.wire_pub_key_len();
        if priv_key.len() != curve.wire_priv_key_len() || pub_key.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        // Pass an exact-sized sub-view: the PKA writes a fixed number of
        // bytes per curve and is not given a length, so an oversized caller
        // buffer would otherwise keep stale bytes in its tail.
        self.pka
            .ecc_gen_pub_key(pka_curve, priv_key, &mut pub_key[..wire_pub_len])
            .await
    }
}

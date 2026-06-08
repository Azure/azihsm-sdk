// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate chain validation state machine.
//!
//! [`ChainValidator`] processes certificates one at a time, from root
//! (index 0) to leaf (index `chain_len - 1`). It uses double-buffering:
//! the caller keeps the previous certificate's DER buffer alive while
//! processing the current one, so the validator can borrow fields from
//! both without copying.
//!
//! ## Validation checks per certificate (RFC 5280 §6.1.3, simplified)
//!
//! 1. **Signature** — verify `tbs_raw` with the appropriate key.
//! 2. **Name chain** — `curr.issuer == prev.subject` (byte compare).
//! 3. **AKID↔SKID** — if both present.
//! 4. **BasicConstraints** — `cA=true` required for non-leaf certs.
//! 5. **KeyUsage** — `keyCertSign` required for CA certs.
//! 6. **Critical extensions** — reject unrecognized (checked in parser).
//!
//! No time validation, no CRL, no policy processing.

use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::ecdsa;
use crate::types::key_usage;
use crate::types::CertInfo;
use crate::types::EcPubKey;
use crate::types::StepResult;

/// X.509 certificate chain validator.
///
/// Processes one certificate at a time using double-buffering.
/// The caller must keep the previous certificate's DER buffer alive
/// when calling [`step`](Self::step), so the validator can borrow
/// the previous certificate's parsed fields for comparison.
///
/// ## State
///
/// Only three integers are stored between calls — everything else
/// is borrowed from the certificate DER buffers:
///
/// - `index` — current certificate position (0-based).
/// - `chain_len` — total number of certificates in the chain.
/// - `max_path_len` — remaining permitted CA depth.
#[derive(Debug)]
pub struct ChainValidator {
    /// Total number of certificates in the chain (including root).
    chain_len: u16,

    /// Index of the next certificate to process (0-based).
    index: u16,

    /// Maximum remaining path length (from BasicConstraints).
    max_path_len: u16,
}

impl ChainValidator {
    /// Create a new chain validator.
    ///
    /// `max_path_len` is initialized to `chain_len` so it never
    /// constrains validation by itself; it is then tightened by each
    /// non-leaf certificate's `pathLenConstraint`.
    ///
    /// # Parameters
    /// * `chain_len` — total number of certificates to validate,
    ///   including the root. Must be ≥ 1; passing `0` causes the
    ///   first call to [`step`](Self::step) to fail with
    ///   [`HsmError::X509AlreadyComplete`].
    ///
    /// # Returns
    /// A fresh [`ChainValidator`] positioned before the root
    /// certificate (`index == 0`).
    pub fn new(chain_len: u16) -> Self {
        Self {
            chain_len,
            index: 0,
            max_path_len: chain_len,
        }
    }

    /// Process one certificate in the chain.
    ///
    /// Must be called exactly `chain_len` times, in order from root
    /// (index 0) to leaf (index `chain_len - 1`).
    ///
    /// # Parameters
    /// * `pal` — PAL providing hash and ECC verify (implements
    ///   [`HsmHash`] + [`HsmEcc`]).
    /// * `io` — I/O context for the current operation.
    /// * `alloc` — scoped allocator for temporary DMA buffers
    ///   (digest and decoded signature). The caller's DER buffers
    ///   must already be in DMA-accessible memory (`&DmaBuf`).
    /// * `prev` — the parsed previous certificate, or `None` for the
    ///   root (index 0). The previous cert's DER buffer must still be
    ///   alive so `prev`'s slices are valid.
    /// * `curr` — the parsed current certificate. Its DER buffer must
    ///   be alive for the duration of this call.
    ///
    /// # Returns
    /// * [`StepResult::NeedNext`] — chain validation is incomplete;
    ///   caller should provide the next certificate.
    /// * [`StepResult::Valid`] — the entire chain has been validated;
    ///   contains the leaf's verified public key and subject.
    /// * [`StepResult::Invalid`] — validation failed.
    pub async fn step<'a, P>(
        &mut self,
        pal: &P,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        prev: Option<&CertInfo<'_>>,
        curr: &'a CertInfo<'a>,
    ) -> StepResult<'a>
    where
        P: HsmHash + HsmEcc,
    {
        if self.index >= self.chain_len {
            return StepResult::Invalid(HsmError::X509AlreadyComplete);
        }

        let is_root = self.index == 0;
        let is_leaf = self.index == self.chain_len - 1;

        let verify_key = match self.select_verify_key(is_root, prev, curr) {
            Ok(key) => key,
            Err(error) => return StepResult::Invalid(error),
        };

        if !is_leaf {
            if let Err(error) = self.apply_ca_constraints(curr) {
                return StepResult::Invalid(error);
            }
        }

        if let Err(error) = self
            .verify_signature(pal, io, alloc, verify_key, curr)
            .await
        {
            return StepResult::Invalid(error);
        }

        self.index += 1;

        if is_leaf {
            StepResult::Valid {
                leaf_pub_key: &curr.pub_key,
                leaf_subject: curr.subject_raw,
            }
        } else {
            StepResult::NeedNext
        }
    }

    /// Choose the public key that should verify the current
    /// certificate's signature, and enforce the per-certificate name
    /// chaining checks.
    ///
    /// For the root, the certificate must be self-signed (issuer ==
    /// subject byte-for-byte) and its own public key is used. For a
    /// non-root certificate the previous certificate's subject must
    /// match the current certificate's issuer, and — if both sides
    /// publish the relevant key identifiers — the AKID must match
    /// the issuer's SKID.
    ///
    /// # Parameters
    /// * `is_root` — `true` when validating the chain's root
    ///   certificate (`self.index == 0`).
    /// * `prev` — the previously validated certificate, or `None`
    ///   when `is_root` is `true`.
    /// * `curr` — the certificate currently being validated.
    ///
    /// # Returns
    /// * `Ok(&EcPubKey)` — the public key to verify `curr`'s
    ///   signature with (either `curr.pub_key` for the root or
    ///   `prev.pub_key` for non-roots).
    /// * `Err(HsmError::X509NotSelfSigned)` if `is_root` and the
    ///   issuer/subject names disagree.
    /// * `Err(HsmError::X509IssuerMismatch)` if `prev` is `None` for
    ///   a non-root, or the issuer/subject names disagree.
    /// * `Err(HsmError::X509AkidSkidMismatch)` if both AKID and SKID
    ///   are present but do not match.
    fn select_verify_key<'a>(
        &self,
        is_root: bool,
        prev: Option<&'a CertInfo<'a>>,
        curr: &'a CertInfo<'a>,
    ) -> HsmResult<&'a EcPubKey<'a>> {
        if is_root {
            if **curr.issuer_raw != **curr.subject_raw {
                return Err(HsmError::X509NotSelfSigned);
            }
            return Ok(&curr.pub_key);
        }

        let prev = prev.ok_or(HsmError::X509IssuerMismatch)?;

        if **curr.issuer_raw != **prev.subject_raw {
            return Err(HsmError::X509IssuerMismatch);
        }

        if let (Some(akid), Some(skid)) = (curr.akid, prev.skid) {
            if akid != skid {
                return Err(HsmError::X509AkidSkidMismatch);
            }
        }

        Ok(&prev.pub_key)
    }

    /// Apply the CA-only constraints to a non-leaf certificate.
    ///
    /// Enforces:
    /// 1. BasicConstraints is present and `cA == true`.
    /// 2. The remaining permitted CA depth (`max_path_len`) is
    ///    non-zero, and is decremented by one for this certificate.
    /// 3. The certificate's own `pathLenConstraint`, if present,
    ///    further tightens `max_path_len`.
    /// 4. If KeyUsage is present, the `keyCertSign` bit is set.
    ///
    /// # Parameters
    /// * `curr` — the non-leaf (CA) certificate currently being
    ///   validated. The leaf certificate must not be passed here.
    ///
    /// # Returns
    /// * `Ok(())` — all CA constraints are satisfied;
    ///   `self.max_path_len` may have been reduced.
    /// * `Err(HsmError::X509NotCa)` if BasicConstraints is missing
    ///   or has `cA == false`.
    /// * `Err(HsmError::X509PathLenExceeded)` if the remaining path
    ///   budget is zero before this certificate is consumed.
    /// * `Err(HsmError::X509KeyUsageInvalid)` if KeyUsage is present
    ///   but lacks `keyCertSign`.
    fn apply_ca_constraints(&mut self, curr: &CertInfo<'_>) -> HsmResult<()> {
        let basic_constraints = match curr.basic_constraints {
            Some(constraints) if constraints.ca => constraints,
            _ => return Err(HsmError::X509NotCa),
        };

        if self.max_path_len == 0 {
            return Err(HsmError::X509PathLenExceeded);
        }
        self.max_path_len -= 1;

        if let Some(path_len) = basic_constraints.path_len {
            if path_len < self.max_path_len {
                self.max_path_len = path_len;
            }
        }

        if let Some(key_usage_bits) = curr.key_usage {
            if key_usage_bits & key_usage::KEY_CERT_SIGN == 0 {
                return Err(HsmError::X509KeyUsageInvalid);
            }
        }

        Ok(())
    }

    /// Verify the ECDSA signature on the current certificate.
    ///
    /// Hashes `curr.tbs_raw` with the algorithm declared in
    /// `curr.sig_algo`, decodes the DER `r || s` signature into a
    /// raw fixed-width buffer, copies the verifier public key into
    /// the hardware's expected wire format (zero-padded coordinates
    /// for P-521), and asks the PAL to verify.
    ///
    /// `curr.tbs_raw` and `verify_key.point` are already in DMA
    /// memory; only the digest, raw signature, and reformatted
    /// public key need temporary DMA allocations from `alloc`.
    ///
    /// # Parameters
    /// * `pal` — PAL providing both [`HsmHash`] and [`HsmEcc`].
    /// * `io` — I/O context for the in-flight HSM operation.
    /// * `alloc` — scoped DMA allocator for the digest, raw
    ///   signature, and public-key buffers.
    /// * `verify_key` — the issuer's EC public key (its `curve`
    ///   field selects the hardware sizes used below).
    /// * `curr` — the certificate whose signature is being
    ///   verified.
    ///
    /// # Returns
    /// * `Ok(())` — the signature is valid for `curr.tbs_raw`
    ///   under `verify_key`.
    /// * `Err(HsmError::X509UnsupportedAlgorithm)` if the signature
    ///   algorithm's expected curve does not match the verifier's
    ///   curve.
    /// * `Err(HsmError::X509SignatureInvalid)` if the PAL reports
    ///   the signature is cryptographically invalid.
    /// * Any other [`HsmError`] propagated from `dma_alloc`,
    ///   `pal.hash`, `pal.ecc_verify`, or DER decoding of the raw
    ///   signature.
    async fn verify_signature<P>(
        &self,
        pal: &P,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        verify_key: &EcPubKey<'_>,
        curr: &CertInfo<'_>,
    ) -> HsmResult<()>
    where
        P: HsmHash + HsmEcc,
    {
        // Verify the signature algorithm matches the signer's curve
        // (RFC 5480 §3 standard pairings).
        if curr.sig_algo.expected_curve() != verify_key.curve {
            return Err(HsmError::X509UnsupportedAlgorithm);
        }

        let hash_algo = curr.sig_algo.hash_algo();
        let digest_len = hash_algo.digest_len();
        let curve = verify_key.curve;
        let coord_len = curve.priv_key_len();
        let hw_len = curve.priv_key_len();
        let sig_len = curve.sig_len();

        // Allocate DMA buffer for digest output.
        let digest_dma = alloc.dma_alloc(digest_len)?;

        // Hash the TBSCertificate (already in DMA memory).
        pal.hash(io, hash_algo, curr.tbs_raw, digest_dma, true)
            .await?;

        // Decode DER ECDSA signature directly into a DMA buffer.
        // Use hw_len per component (68 for P-521) for zero-padded output.
        let sig_dma = alloc.dma_alloc(sig_len)?;
        ecdsa::decode_ecdsa_sig(curr.signature, curve, sig_dma)?;

        // Copy public key into hardware wire format.
        // X.509 uses coord_len per coordinate (66 for P-521),
        // hardware expects hw_len (68 for P-521) with leading zeros.
        let pk_dma = alloc.dma_alloc(curve.pub_key_len())?;
        pk_dma.fill(0);
        let pad = hw_len - coord_len;
        pk_dma[pad..pad + coord_len].copy_from_slice(&verify_key.point[..coord_len]);
        pk_dma[hw_len + pad..hw_len + pad + coord_len]
            .copy_from_slice(&verify_key.point[coord_len..coord_len * 2]);

        let valid = pal
            .ecc_verify(io, curve, pk_dma, digest_dma, sig_dma)
            .await?;

        if valid {
            Ok(())
        } else {
            Err(HsmError::X509SignatureInvalid)
        }
    }
}

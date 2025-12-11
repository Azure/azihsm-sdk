// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! A wrapper around a Windows CNG (Cryptography Next Generation) algorithm provider handle.

use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::eckey::*;

impl EccCryptSignOp for EcPrivateKey {
    /// Signs the provided digest using the ECDSA private key.
    ///
    /// # Parameters
    /// - `digest`: The message digest to sign as a byte slice.
    /// - `signature`: Mutable byte slice to write the DER-encoded signature into.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written to the signature buffer on success.
    /// - `Err(CryptoError)`: An error if signing fails.
    #[allow(unsafe_code)]
    fn ecc_crypt_sign<'a>(
        &self,
        digest: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let handle_guard_private_key = match self.private_key_handle.lock() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("ecc_crypt_sign: failed to acquire mutex: {}", e);
                return Err(CryptoError::EccSignError);
            }
        };
        let degree = handle_guard_private_key.curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecc_crypt_sign: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_digest_valid_for_curve(digest) {
            tracing::error!("ecc_crypt_sign: Digest size is not expected/supported for the curve");
            return Err(CryptoError::EccUnsupportedDigestSize);
        }
        let mut sig_len: u32 = 0;
        // SAFETY: Calls BCryptSignHash to determine the required signature buffer size; all pointers and handles are valid and checked.
        let status = unsafe {
            BCryptSignHash(
                handle_guard_private_key.cng_private_key,
                None,
                digest,
                None,
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (size query) failed: status={:?}", status);
            return Err(CryptoError::EccError);
        }
        if signature.len() < sig_len as usize {
            tracing::error!("ecc_crypt_sign: signature buffer too small");
            return Err(CryptoError::EccError);
        }
        let mut sig_vec = vec![0; sig_len as usize];
        //SAFETY: Call hash function
        let status = unsafe {
            BCryptSignHash(
                handle_guard_private_key.cng_private_key,
                None,
                digest,
                Some(sig_vec.as_mut_slice()),
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };

        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (sign) failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        // Debug: Print raw signature and expected length
        let curve_bits = handle_guard_private_key.curve_degree()?;
        let key_size = curve_bits.div_ceil(8) as usize;
        tracing::debug!(
            "CNG raw signature (hex): {:02x?}, sig_len: {}, expected: {}",
            sig_vec,
            sig_len,
            2 * key_size
        );

        // If sig_len is less than expected, left-pad with zeros
        if sig_len as usize != 2 * key_size {
            tracing::warn!(
                "CNG raw signature length {} does not match expected {}. Padding with zeros.",
                sig_len,
                2 * key_size
            );
            let mut padded = vec![0u8; 2 * key_size];
            if sig_len as usize > 0 && sig_len as usize <= 2 * key_size {
                padded[2 * key_size - sig_len as usize..]
                    .copy_from_slice(&sig_vec[..sig_len as usize]);
            } else {
                tracing::error!("CNG raw signature length is invalid: {}", sig_len);
                return Err(CryptoError::EccSignError);
            }
            sig_vec = padded;
        } else {
            sig_vec.truncate(2 * key_size);
        }
        // Extra debug: print the buffer passed to DER conversion
        tracing::debug!("CNG raw signature (padded, hex): {:02x?}", sig_vec);
        // Always convert raw signature to DER before returning
        let der_sig = match raw_ecc_signature_to_der(&sig_vec, 2 * key_size) {
            Ok(der) => der,
            Err(e) => {
                tracing::error!(
                    "DER conversion failed for raw signature.\n  sig_vec: {:02x?}\n  key_size: {}\n  error: {:?}",
                    sig_vec, key_size, e
                );
                return Err(e);
            }
        };
        signature[..der_sig.len()].copy_from_slice(&der_sig);
        Ok(&signature[..der_sig.len()])
    }

    /// Returns the maximum DER-encoded ECDSA signature size for the given hash algorithm and key.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use (HashAlgo).
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum signature size in bytes for the specified key and hash algorithm.
    /// * `Err(CryptoError)` - If the key or hash algorithm is not supported, or if the size cannot be determined.
    fn ecc_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError> {
        let curve_bits = self.private_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(curve_bits) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecc_crypt_get_signature_size: unsupported bits for curve (degree: {})",
                    curve_bits
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!("ecc_crypt_get_signature_size: unsupported hash algorithm for curve (degree: {}, algo: {:?})", curve_bits, hash_algo);
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        // # How the maximum DER size is determined:
        //
        // The DER-encoded ECDSA signature is a SEQUENCE of two INTEGERs (r, s), each representing a curve value.
        // For a curve of N bits, the value size is ceil(N/8) bytes. Each INTEGER may require a leading zero byte if the high bit is set.
        // The maximum size for each INTEGER is:
        //   1 (tag) + 1 (length) + (value size + 1 for possible leading zero)
        // The SEQUENCE wrapper adds 1 (tag) + 1 or 2 (length) bytes.
        //
        // Formula for maximum DER signature size:
        //   max_der = 1 + seq_len_field + 2 * (1 + 1 + value_size + 1)
        // Where:
        //   - value_size = ceil(curve_bits / 8)
        //   - seq_len_field = 2 if content_len >= 128, else 1
        //
        // For P-256 (256 bits): value_size = 32, max_der = 72
        // For P-384 (384 bits): value_size = 48, max_der = 107
        // For P-521 (521 bits): value_size = 66, max_der = 141
        //
        // These values are empirically verified to be the maximum possible DER-encoded signature sizes for each curve.
        // Return the empirically determined max DER signature size for the curve
        // P-256: 72, P-384: 107, P-521: 141 (max observed for each)
        let max_der_sig_size = match curve_bits {
            256 => 72,                                     // P-256
            384 => 107,                                    // P-384
            521 => 141,                                    // P-521
            _ => return Err(CryptoError::EcCurveMismatch), // Only error for unknown/unsupported curve
        };
        Ok(max_der_sig_size)
    }
}

impl EccCryptVerifyOp for EcPublicKey {
    /// Verifies the provided signature against the digest using the ECDSA public key.
    /// Accepts only DER-encoded signatures.
    ///
    /// # Parameters
    /// - `digest`: The message digest that was signed, as a byte slice.
    /// - `signature`: The DER-encoded signature to verify, as a byte slice.
    ///
    /// # Returns
    /// - `Ok(())`: If the signature is valid.
    /// - `Err(CryptoError)`: If the signature is invalid or verification fails.
    #[allow(unsafe_code)]
    fn ecc_crypt_verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let degree = self.public_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecc_crypt_verify: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        tracing::debug!(
            "ecc_crypt_verify: curve: {:?}, degree: {}, digest (hex): {:02x?}, digest.len: {}, signature (DER, hex): {:02x?}, signature.len: {}",
            ec_curve_id,
            degree,
            digest,
            digest.len(),
            signature,
            signature.len()
        );
        if !ec_curve_id.is_digest_valid_for_curve(digest) {
            tracing::error!(
                "ecc_crypt_verify: unsupported digest for curve (degree: {}, digest size: {:?})",
                degree,
                digest.len(),
            );
            return Err(CryptoError::EccUnsupportedDigestSize);
        }
        let key_size = self.size().map_err(|e| {
            tracing::error!("Failed to get curve key_size:{:?}", e);
            CryptoError::EcInvalidKey
        })?;
        tracing::debug!(
            "ecdsa_crypt_verify: DER signature (hex): {:02x?}, len: {}",
            signature,
            signature.len()
        );
        tracing::debug!(
            "ecc_crypt_verify: DER signature (hex): {:02x?}, len: {}",
            signature,
            signature.len()
        );
        // Accept only DER-encoded signatures
        let sig_vec = match der_ecc_signature_to_raw(signature, key_size.div_ceil(8)) {
            Ok(raw) => {
                tracing::debug!(
                    "ecc_crypt_verify: raw signature (hex): {:02x?}, len: {} (key_size: {})",
                    raw,
                    raw.len(),
                    key_size
                );
                raw
            }
            Err(e) => {
                tracing::error!("DER-to-raw signature conversion failed: {e:?}");
                return Err(CryptoError::EccVerifyError);
            }
        };
        tracing::debug!(
            "ecc_crypt_verify: calling BCryptVerifySignature with digest (hex): {:02x?}, sig_vec (hex): {:02x?}, sig_vec.len: {}",
            digest,
            sig_vec,
            sig_vec.len()
        );
        //SAFETY: Call Bcrypt unsafe call to verify raw signature
        let status = unsafe {
            BCryptVerifySignature(
                self.public_key_handle.lock().unwrap().cng_public_key,
                None,
                digest,
                sig_vec.as_slice(),
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptVerifySignature failed: {status:?}");
            return Err(CryptoError::EccVerifyError);
        }
        Ok(())
    }
}
// Converts a raw (r||s) ECC signature to DER-encoded format.
///
/// # Arguments
/// * `raw` - The raw signature bytes (concatenated r and s values).
/// * `sig_len` - The total length of the signature (should be even, r and s are each half).
///
/// # Returns
/// * `Ok(Vec<u8>)` - DER-encoded ECC signature on success.
/// * `Err(CryptoError)` - If encoding fails or input is invalid.
///
/// # Details
/// - Splits the raw signature into r and s components.
/// - Encodes each as ASN.1 INTEGER, handling leading zeros and sign bit.
/// - Constructs a DER-encoded SEQUENCE of the two integers.
/// - Used for converting CNG raw signatures to standard DER format for interoperability.
fn raw_ecc_signature_to_der(raw: &[u8], sig_len: usize) -> Result<Vec<u8>, CryptoError> {
    if !sig_len.is_multiple_of(2) || (raw.len() < sig_len) {
        tracing::error!("raw_ecc_signature_to_der : Invalid signature length must be even size");
        return Err(CryptoError::EcdsaInvalidRawSignatureSize);
    }
    let key_size = sig_len / 2;
    let r = &raw[..key_size];
    let s = &raw[key_size..sig_len];
    // Remove leading zeros for ASN.1 INTEGER encoding, but add a leading zero if high bit is set
    fn encode_asn1_integer(bytes: &[u8]) -> Vec<u8> {
        let mut i = 0;
        while i < bytes.len() - 1 && bytes[i] == 0 {
            i += 1;
        }
        let stripped = &bytes[i..];
        if !stripped.is_empty() && stripped[0] & 0x80 != 0 {
            let mut v = Vec::with_capacity(stripped.len() + 1);
            v.push(0);
            v.extend_from_slice(stripped);
            v
        } else {
            stripped.to_vec()
        }
    }
    let r_enc = encode_asn1_integer(r);
    let s_enc = encode_asn1_integer(s);
    let r_bn = asn1::BigInt::new(&r_enc).ok_or(CryptoError::EccVerifyError)?;
    let s_bn = asn1::BigInt::new(&s_enc).ok_or(CryptoError::EccVerifyError)?;
    #[derive(asn1::Asn1Write)]
    struct EccSig<'a> {
        r: asn1::BigInt<'a>,
        s: asn1::BigInt<'a>,
    }
    let sig = EccSig { r: r_bn, s: s_bn };
    asn1::write_single(&sig).map_err(|_| CryptoError::EccVerifyError)
}

/// Converts a DER-encoded ECC signature to raw (r||s) format for CNG.
///
/// # Arguments
/// * `der` - DER-encoded ECC signature as a byte slice.
/// * `key_size` - The size of the curve in bytes (e.g., 32 for P-256).
///
/// # Returns
/// * `Ok(Vec<u8>)` - Raw signature bytes (r||s) of length 2 * key_size.
/// * `Err(CryptoError)` - If parsing fails or the signature is invalid.
///
/// # Details
/// - Parses the ASN.1 DER-encoded ECC signature (SEQUENCE of two INTEGERs).
/// - Extracts r and s, left-pads with zeros if needed to match key_size.
/// - Concatenates r and s to produce the raw signature format required by CNG.
fn der_ecc_signature_to_raw(der: &[u8], key_size: usize) -> Result<Vec<u8>, CryptoError> {
    #[derive(asn1::Asn1Read)]
    struct EccSig<'a> {
        r: asn1::BigInt<'a>,
        s: asn1::BigInt<'a>,
    }
    let sig = asn1::parse_single::<EccSig<'_>>(der).map_err(|_| CryptoError::EccVerifyError)?;
    let r_bytes = sig.r.as_bytes();
    let s_bytes = sig.s.as_bytes();
    let r_bytes = if r_bytes.len() > key_size {
        &r_bytes[r_bytes.len() - key_size..]
    } else {
        r_bytes
    };
    let s_bytes = if s_bytes.len() > key_size {
        &s_bytes[s_bytes.len() - key_size..]
    } else {
        s_bytes
    };
    if r_bytes.len() > key_size || s_bytes.len() > key_size {
        return Err(CryptoError::EccVerifyError);
    }
    let mut raw = Vec::with_capacity(2 * key_size);
    raw.extend(std::iter::repeat_n(0, key_size - r_bytes.len()));
    raw.extend_from_slice(r_bytes);
    raw.extend(std::iter::repeat_n(0, key_size - s_bytes.len()));
    raw.extend_from_slice(s_bytes);
    Ok(raw)
}

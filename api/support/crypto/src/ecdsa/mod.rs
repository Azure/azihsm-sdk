// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! ECDSA (Elliptic Curve Cryptography) module for cross-platform key management and operations.

#[cfg(target_os = "windows")]
mod ecdsa_cng;

#[cfg(target_os = "linux")]
mod ecdsa_ossl;

use crate::CryptoError;
use crate::HashAlgo;

/// Trait for ECDSA signing operations (one-shot and streaming).
pub trait EcdsaCryptSignOp {
    /// One-shot sign: signs the given data using the specified hash algorithm.
    fn ecdsa_crypt_sign<'a>(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError>;

    /// Initializes a streaming signing context for multi-part signing.
    fn ecdsa_crypt_sign_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl EcdsaCryptSignContextOp, CryptoError>;

    /// Get size of signature for  private key
    fn ecdsa_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError>;
}

/// Trait for streaming (multi-part) ECDSA signing context.
pub trait EcdsaCryptSignContextOp {
    /// Updates the signing context with more data.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
    /// Finalizes the signature and writes it to the output buffer.
    fn finalize(self, signature: &mut [u8]) -> Result<&[u8], CryptoError>;
}

/// Trait for ECDSA signature verification (one-shot and streaming).
pub trait EcdsaCryptVerifyOp {
    /// One-shot verify: verifies the given signature for the data.
    fn ecdsa_crypt_verify(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// One-shot verify of the digest
    fn ecdsa_crypt_verify_digest(&self, digest: &[u8], signature: &[u8])
        -> Result<(), CryptoError>;

    /// Initializes a streaming verification context for multi-part verification.
    fn ecdsa_crypt_verify_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl EcdsaCryptVerifyContextOp, CryptoError>;
}

/// Trait for streaming (multi-part) ECDSA verification context.
pub trait EcdsaCryptVerifyContextOp {
    /// Updates the verification context with more data.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
    /// Finalizes the verification and checks the signature.
    fn finalize(self, signature: &[u8]) -> Result<(), CryptoError>;
}

/// Converts a raw (r||s) ECDSA signature to DER-encoded format.
///
/// # Arguments
/// * `raw` - The raw signature bytes (concatenated r and s values).
/// * `sig_len` - The total length of the signature (should be even, r and s are each half).
///
/// # Returns
/// * `Ok(Vec<u8>)` - DER-encoded ECDSA signature on success.
/// * `Err(CryptoError)` - If encoding fails or input is invalid.
///
/// # Details
/// - Splits the raw signature into r and s components.
/// - Encodes each as ASN.1 INTEGER, handling leading zeros and sign bit.
/// - Constructs a DER-encoded SEQUENCE of the two integers.
/// - Used for converting CNG raw signatures to standard DER format for interoperability.
pub fn raw_ecdsa_signature_to_der(raw: &[u8], sig_len: usize) -> Result<Vec<u8>, CryptoError> {
    if !sig_len.is_multiple_of(2) || (raw.len() < sig_len) {
        tracing::error!("raw_ecdsa_signature_to_der : Invalid signature length must be even size");
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
    struct EcdsaSig<'a> {
        r: asn1::BigInt<'a>,
        s: asn1::BigInt<'a>,
    }
    let sig = EcdsaSig { r: r_bn, s: s_bn };
    asn1::write_single(&sig).map_err(|_| CryptoError::EccVerifyError)
}

/// Converts a DER-encoded ECDSA signature to raw (r||s) format for CNG.
///
/// # Arguments
/// * `der` - DER-encoded ECDSA signature as a byte slice.
/// * `key_size` - The size of the curve in bytes (e.g., 32 for P-256).
///
/// # Returns
/// * `Ok(Vec<u8>)` - Raw signature bytes (r||s) of length 2 * key_size.
/// * `Err(CryptoError)` - If parsing fails or the signature is invalid.
///
/// # Details
/// - Parses the ASN.1 DER-encoded ECDSA signature (SEQUENCE of two INTEGERs).
/// - Extracts r and s, left-pads with zeros if needed to match key_size.
/// - Concatenates r and s to produce the raw signature format required by CNG.
pub fn der_ecdsa_signature_to_raw(der: &[u8], key_size: usize) -> Result<Vec<u8>, CryptoError> {
    #[derive(asn1::Asn1Read)]
    struct EcdsaSig<'a> {
        r: asn1::BigInt<'a>,
        s: asn1::BigInt<'a>,
    }
    let sig = asn1::parse_single::<EcdsaSig<'_>>(der).map_err(|_| CryptoError::EccVerifyError)?;
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

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;
    use crate::eckey::eckey_test_vectors::*;
    use crate::eckey::*;
    // Helper: all supported curves
    const CURVES: [EcCurveId; 3] = [EcCurveId::EccP256, EcCurveId::EccP384, EcCurveId::EccP521];
    // Helper: all supported hash algorithms
    const HASHALGOS: [HashAlgo; 4] = [
        HashAlgo::Sha1,
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
    ];

    #[test]
    /// Tests that a public key can be DER-encoded and decoded (roundtrip) without loss of information.
    fn test_public_key_der_roundtrip() {
        for &curve in &CURVES {
            let (_priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let mut der = vec![0u8; 256];
            let len = pub_key.ec_key_to_der(&mut der).unwrap();
            let der = &der[..len];
            let pub2 = EcPublicKey::ec_key_from_der(der, curve).unwrap();
            let mut der2 = vec![0u8; 256];
            let len2 = pub2.ec_key_to_der(&mut der2).unwrap();
            assert_eq!(der, &der2[..len2]);
        }
    }

    #[test]
    /// Tests one-shot sign and verify for all valid hash algorithms and curves.
    fn test_sign_and_verify_oneshot() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let valid_hashes = curve.valid_hash_algos_for_curve();
            let data = b"test message for ecdsa sign/verify";
            for hash_algo in valid_hashes {
                let sig_size = priv_key.ecdsa_crypt_get_signature_size(hash_algo).unwrap();
                let mut sig = vec![0u8; sig_size];
                let sig = priv_key
                    .ecdsa_crypt_sign(hash_algo, data, &mut sig)
                    .unwrap();
                pub_key.ecdsa_crypt_verify(hash_algo, data, sig).unwrap();
            }
        }
    }

    #[test]
    /// Tests streaming (multi-part) sign and verify for all valid hash algorithms and curves.
    fn test_sign_and_verify_streaming() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let valid_hashes = curve.valid_hash_algos_for_curve();
            let data = b"streaming sign verify test data";
            for hash_algo in valid_hashes {
                // Sign
                let mut ctx = priv_key.ecdsa_crypt_sign_init(hash_algo).unwrap();
                ctx.update(&data[..10]).unwrap();
                ctx.update(&data[10..]).unwrap();
                let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
                let sig = ctx.finalize(&mut sig).unwrap();
                // Verify
                let mut vctx = pub_key.ecdsa_crypt_verify_init(hash_algo).unwrap();
                vctx.update(&data[..10]).unwrap();
                vctx.update(&data[10..]).unwrap();
                vctx.finalize(sig).unwrap();
            }
        }
    }

    #[test]
    /// Tests that using an invalid hash algorithm for a curve fails for both sign and verify.
    fn test_invalid_hash_for_curve() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let invalid_hashes: Vec<_> = HASHALGOS
                .iter()
                .cloned()
                .filter(|h| !curve.valid_hash_algos_for_curve().contains(h))
                .collect();
            let data = b"test";
            for hash_algo in invalid_hashes {
                let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
                assert!(priv_key
                    .ecdsa_crypt_sign(hash_algo, data, &mut sig)
                    .is_err());
                assert!(pub_key
                    .ecdsa_crypt_verify(hash_algo, data, &sig[..64])
                    .is_err());
            }
        }
    }

    #[test]
    /// Tests that signature verification fails for wrong data or corrupted signature.
    fn test_verify_wrong_signature_and_data() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let valid_hashes = curve.valid_hash_algos_for_curve();
            let data = b"correct data";
            let wrong_data = b"wrong data";
            for hash_algo in valid_hashes {
                let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
                let sig = priv_key
                    .ecdsa_crypt_sign(hash_algo, data, &mut sig)
                    .unwrap();
                // Wrong data
                assert!(pub_key
                    .ecdsa_crypt_verify(hash_algo, wrong_data, sig)
                    .is_err());
                // Corrupted signature
                let mut bad_sig = sig.to_vec();
                let idx = bad_sig.len() / 2;
                bad_sig[idx] ^= 0xFF;
                let bad_sig_ref = &bad_sig;
                assert!(pub_key
                    .ecdsa_crypt_verify(hash_algo, data, bad_sig_ref)
                    .is_err());
            }
        }
    }

    #[test]
    /// Tests that signing and verifying empty data works for all valid hash algorithms and curves.
    fn test_empty_data_sign_verify() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let valid_hashes = curve.valid_hash_algos_for_curve();
            let data = b"";
            for hash_algo in valid_hashes {
                let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
                let sig = priv_key
                    .ecdsa_crypt_sign(hash_algo, data, &mut sig)
                    .unwrap();
                pub_key.ecdsa_crypt_verify(hash_algo, data, sig).unwrap();
            }
        }
    }

    #[test]
    /// Tests that signature verification fails if the public key is from a different curve (key size mismatch).
    fn test_key_size_mismatch() {
        // Try to verify a signature with a public key from a different curve
        let (priv_key, _pub_key) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP256).unwrap();
        let (_priv2, pub2) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP384).unwrap();
        let data = b"key size mismatch";
        let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
        let sig = priv_key
            .ecdsa_crypt_sign(HashAlgo::Sha256, data, &mut sig)
            .unwrap();
        // Should fail: pub2 is not the right curve
        assert!(pub2
            .ecdsa_crypt_verify(HashAlgo::Sha256, data, sig)
            .is_err());
    }

    #[test]
    /// Signs the NIST test vector message and verifies the signature with the public key.
    ///
    /// Note: We do not compare the generated signature bytes directly to the test vector.
    /// ECDSA signatures are not deterministic by default (unless RFC 6979 is used),
    /// so the signature bytes may differ on each run or across platforms, even for the same key and message.
    /// Instead, we verify that the generated signature is valid for the message and public key.
    ///
    /// Coverage: Signature generation for all supported curves and hash algorithms.
    fn test_nist_signature_generation() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_signature_generation] vector index: {}, curve: {:?}",
                i, vector.curve
            );
            let priv_key = match EcPrivateKey::ec_key_from_der(vector.private_key_der, vector.curve)
            {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] private ec_key_from_der failed: {:?}", i, e);
                    panic!("private ec_key_from_der failed");
                }
            };
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public ec_key_from_der failed: {:?}", i, e);
                    panic!("public ec_key_from_der failed");
                }
            };
            let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
            let sig = match priv_key.ecdsa_crypt_sign(vector.hash_algo, vector.msg, &mut sig) {
                Ok(l) => l,
                Err(e) => {
                    println!("  [vector {}] ecdsa_crypt_sign failed: {:?}", i, e);
                    panic!("ecdsa_crypt_sign failed");
                }
            };
            if let Err(e) = pub_key.ecdsa_crypt_verify(vector.hash_algo, vector.msg, sig) {
                println!("  [vector {}] ecdsa_crypt_verify failed: {:?}", i, e);
                panic!("Signature should verify");
            }
        }
    }

    #[test]
    /// Verifies the NIST test vector signature using the public key and message.
    /// Converts DER signatures to raw format for testing.
    ///
    /// Coverage: Signature verification for all supported curves and hash algorithms.
    fn test_nist_signature_verification() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_signature_verification] vector index: {}, curve: {:?}",
                i, vector.curve
            );
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public_ec_key_from_der failed: {:?}", i, e);
                    panic!("public_ec_key_from_der failed");
                }
            };
            // Convert DER signature to raw format for testing
            let key_size = (vector.curve.curve_degree().div_ceil(8)) as usize;
            let raw_sig = match der_ecdsa_signature_to_raw(vector.sig_der, key_size) {
                Ok(raw) => raw,
                Err(e) => {
                    println!("  [vector {}] DER-to-raw conversion failed: {:?}", i, e);
                    panic!("DER-to-raw conversion failed");
                }
            };
            if let Err(e) = pub_key.ecdsa_crypt_verify(vector.hash_algo, vector.msg, &raw_sig) {
                println!("  [vector {}] ecdsa_crypt_verify failed: {:?}", i, e);
                panic!("verify");
            }
        }
    }

    #[test]
    /// Checks that signature verification fails for corrupted signatures from NIST vectors.
    /// Converts DER signatures to raw format for testing.
    ///
    /// Coverage: Negative test for signature verification (corrupted signature).
    fn test_nist_signature_verification_negative() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_signature_verification_negative] vector index: {}, curve: {:?}",
                i, vector.curve
            );
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public_ec_key_from_der failed: {:?}", i, e);
                    panic!("public_ec_key_from_der failed");
                }
            };
            // Convert DER signature to raw format for testing
            let key_size = (vector.curve.curve_degree().div_ceil(8)) as usize;
            let raw_sig = match der_ecdsa_signature_to_raw(vector.sig_der, key_size) {
                Ok(raw) => raw,
                Err(e) => {
                    println!("  [vector {}] DER-to-raw conversion failed: {:?}", i, e);
                    panic!("DER-to-raw conversion failed");
                }
            };
            let mut bad_sig = raw_sig.clone();
            if !bad_sig.is_empty() {
                bad_sig[0] ^= 0xFF;
            }
            assert!(
                pub_key
                    .ecdsa_crypt_verify(vector.hash_algo, vector.msg, &bad_sig)
                    .is_err(),
                "Corrupted signature should not verify for {:?}",
                vector.curve
            );
        }
    }

    #[test]
    /// Tests that the implementation can import NIST test vector keys and verify the provided signature.
    /// Converts DER signatures to raw format for testing.
    ///
    /// Coverage: Key import and signature verification for all supported curves and hash algorithms.
    fn test_nist_signature_verification_with_sig_der() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_signature_verification_with_sig_der] vector index: {}, curve: {:?}",
                i, vector.curve
            );
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public_ec_key_from_der failed: {:?}", i, e);
                    panic!("public_ec_key_from_der failed");
                }
            };
            // Convert DER signature to raw format for testing
            let key_size = (vector.curve.curve_degree().div_ceil(8)) as usize;
            let raw_sig = match der_ecdsa_signature_to_raw(vector.sig_der, key_size) {
                Ok(raw) => raw,
                Err(e) => {
                    println!("  [vector {}] DER-to-raw conversion failed: {:?}", i, e);
                    panic!("DER-to-raw conversion failed");
                }
            };
            if let Err(e) = pub_key.ecdsa_crypt_verify(vector.hash_algo, vector.msg, &raw_sig) {
                println!("  [vector {}] ecdsa_crypt_verify failed: {:?}", i, e);
                panic!("verify");
            }
        }
    }

    #[test]
    /// Tests that the implementation can generate a signature for the NIST test vector and that it verifies with the public key.
    ///
    /// Coverage: Signature generation and verification for all supported curves and hash algorithms.
    fn test_nist_signature_generation_and_verification() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_signature_generation_and_verification] vector index: {}, curve: {:?}",
                i, vector.curve
            );
            let priv_key = match EcPrivateKey::ec_key_from_der(vector.private_key_der, vector.curve)
            {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] private_ec_key_from_der failed: {:?}", i, e);
                    panic!("private_ec_key_from_der failed");
                }
            };
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public_ec_key_from_der failed: {:?}", i, e);
                    panic!("public_ec_key_from_der failed");
                }
            };
            let mut sig = vec![0u8; 132]; // Max raw sig size for all curves (P-521)
            let sig = match priv_key.ecdsa_crypt_sign(vector.hash_algo, vector.msg, &mut sig) {
                Ok(l) => l,
                Err(e) => {
                    println!("  [vector {}] ecdsa_crypt_sign failed: {:?}", i, e);
                    panic!("ecdsa_crypt_sign failed");
                }
            };
            if let Err(e) = pub_key.ecdsa_crypt_verify(vector.hash_algo, vector.msg, sig) {
                println!("  [vector {}] ecdsa_crypt_verify failed: {:?}", i, e);
                panic!("Signature should verify");
            }
        }
    }

    #[test]
    /// Tests that signature verification fails for a corrupted signature from the NIST test vector.
    /// Converts DER signatures to raw format for testing.
    ///
    /// Coverage: Negative test for signature verification (corrupted signature).
    fn test_nist_signature_verification_negative_with_sig_der() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!("[test_nist_signature_verification_negative_with_sig_der] vector index: {}, curve: {:?}", i, vector.curve);
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public_ec_key_from_der failed: {:?}", i, e);
                    panic!("public_ec_key_from_der failed");
                }
            };
            // Convert DER signature to raw format for testing
            let key_size = (vector.curve.curve_degree().div_ceil(8)) as usize;
            let raw_sig = match der_ecdsa_signature_to_raw(vector.sig_der, key_size) {
                Ok(raw) => raw,
                Err(e) => {
                    println!("  [vector {}] DER-to-raw conversion failed: {:?}", i, e);
                    panic!("DER-to-raw conversion failed");
                }
            };
            let mut bad_sig = raw_sig.clone();
            if !bad_sig.is_empty() {
                bad_sig[0] ^= 0xFF;
            }
            assert!(
                pub_key
                    .ecdsa_crypt_verify(vector.hash_algo, vector.msg, &bad_sig)
                    .is_err(),
                "Corrupted signature should not verify for {:?}",
                vector.curve
            );
        }
    }

    #[test]
    /// Imports a public key from DER, exports it, re-imports, and verifies a known message/signature.
    /// Converts DER signatures to raw format for testing.
    /// This ensures that DER encoding differences do not affect cryptographic correctness.
    fn test_nist_public_key_import_export_reimport_and_verify() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_public_key_import_export_reimport_and_verify] vector index: {}, curve: {:?}, msg: {:02x?}",
                i, vector.curve, vector.msg
            );
            // Import public key from test vector DER
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] ec_key_from_der failed: {:?}", i, e);
                    panic!("ec_key_from_der failed");
                }
            };
            // Export to DER (use a large buffer for all curves)
            let mut der = vec![0u8; 256];
            let len = match pub_key.ec_key_to_der(&mut der) {
                Ok(l) => l,
                Err(e) => {
                    println!("  [vector {}] ec_key_to_der failed: {:?}", i, e);
                    panic!("ec_key_to_der failed");
                }
            };
            let der = &der[..len];
            // Re-import
            let pub_key2 = match EcPublicKey::ec_key_from_der(der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] re-import ec_key_from_der failed: {:?}", i, e);
                    panic!("re-import ec_key_from_der failed");
                }
            };
            // Convert DER signature to raw format for testing
            let key_size = (vector.curve.curve_degree().div_ceil(8)) as usize;
            let raw_sig = match der_ecdsa_signature_to_raw(vector.sig_der, key_size) {
                Ok(raw) => raw,
                Err(e) => {
                    println!("  [vector {}] DER-to-raw conversion failed: {:?}", i, e);
                    panic!("DER-to-raw conversion failed");
                }
            };
            // Verify known message and signature
            if let Err(e) = pub_key2.ecdsa_crypt_verify(vector.hash_algo, vector.msg, &raw_sig) {
                println!(
                    "  [vector {}] ecdsa_crypt_verify failed: {:?}\n  curve: {:?}\n  msg: {:02x?}\n  raw_sig: {:02x?}",
                    i, e, vector.curve, vector.msg, raw_sig
                );
                panic!("re-imported pubkey should verify signature");
            }
        }
    }

    #[test]
    /// Tests that ecdsa_crypt_get_signature_size returns a correct, nonzero size for all valid curves and hash algorithms.
    fn test_signature_size_validity() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let valid_hashes = curve.valid_hash_algos_for_curve();
            for hash_algo in valid_hashes {
                let size = priv_key
                    .ecdsa_crypt_get_signature_size(hash_algo)
                    .expect("size");
                // Should be nonzero and reasonable for raw ECDSA signature
                // Raw signatures: P-256=64, P-384=96, P-521=132
                assert!(
                    (64..=132).contains(&size),
                    "Signature size out of expected range: {}",
                    size
                );
                // Actually sign and check that the returned signature fits in the buffer
                let mut sig = vec![0u8; size];
                let sig_slice = priv_key
                    .ecdsa_crypt_sign(hash_algo, b"test", &mut sig)
                    .unwrap();
                assert!(sig_slice.len() <= size);
                // Should verify
                pub_key
                    .ecdsa_crypt_verify(hash_algo, b"test", sig_slice)
                    .unwrap();
            }
        }
    }

    #[test]
    /// Tests that ecdsa_crypt_get_signature_size returns an error for invalid hash algorithms for a curve.
    fn test_signature_size_invalid_hash() {
        for &curve in &CURVES {
            let (priv_key, _pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let invalid_hashes: Vec<_> = HASHALGOS
                .iter()
                .cloned()
                .filter(|h| !curve.valid_hash_algos_for_curve().contains(h))
                .collect();
            for hash_algo in invalid_hashes {
                let res = priv_key.ecdsa_crypt_get_signature_size(hash_algo);
                assert!(
                    res.is_err(),
                    "Should error for invalid hash {:?} on {:?}",
                    hash_algo,
                    curve
                );
            }
        }
    }

    #[test]
    /// Tests that the signature size is consistent for repeated calls and matches the actual signature length.
    fn test_signature_size_consistency() {
        for &curve in &CURVES {
            let (priv_key, _pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let valid_hashes = curve.valid_hash_algos_for_curve();
            for hash_algo in valid_hashes {
                let size1 = priv_key.ecdsa_crypt_get_signature_size(hash_algo).unwrap();
                let size2 = priv_key.ecdsa_crypt_get_signature_size(hash_algo).unwrap();
                assert_eq!(size1, size2, "Signature size should be consistent");
                let mut sig = vec![0u8; size1];
                let sig_slice = priv_key
                    .ecdsa_crypt_sign(hash_algo, b"consistency", &mut sig)
                    .unwrap();
                assert!(sig_slice.len() <= size1);
            }
        }
    }
}

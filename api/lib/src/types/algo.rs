// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(unused_imports)]
#![allow(dead_code)]

/// HSM Algorithm identifier enumeration.
///
/// This enum defines all supported cryptographic algorithms in the HSM.
/// The values are organized by algorithm family:
/// - 0x0000xxxx: Masking algorithms  
/// - 0x0001xxxx: RSA algorithms
/// - 0x0002xxxx: Elliptic Curve algorithms
/// - 0x0003xxxx: AES algorithms
/// - 0x0004xxxx: Hash algorithms (SHA family)
/// - 0x0005xxxx: HMAC algorithms
/// - 0x0006xxxx: Key Derivation Function algorithms
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum_macros::FromRepr)]
pub enum AlgoId {
    // =============================================================================
    // Masking Algorithms (0x0000xxxx)
    // =============================================================================
    /// Masking key generation algorithm.
    /// Corresponds to AZIHSM_ALGO_ID_MASKING_KEY_GEN
    MaskingKeyGen = 0x00000001,

    /// Masking key wrap algorithm.
    /// Corresponds to AZIHSM_ALGO_ID_MASKING_KEYWRAP
    MaskingKeywrap = 0x00000002,

    // =============================================================================
    // RSA Algorithms (0x0001xxxx)
    // =============================================================================
    /// RSA PKCS#1 v1.5 Key Pair Generation.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN
    RsaPkcsKeyPairGen = 0x00010001,

    /// RSA PKCS#1 v1.5 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS
    RsaPkcs = 0x00010002,

    /// RSA PKCS#1 v1.5 SHA-1 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_SHA1
    RsaPkcsSha1 = 0x00010003,

    /// RSA PKCS#1 v1.5 SHA-256 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_SHA256
    RsaPkcsSha256 = 0x00010004,

    /// RSA PKCS#1 v1.5 SHA-384 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_SHA384
    RsaPkcsSha384 = 0x00010005,

    /// RSA PKCS#1 v1.5 SHA-512 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_SHA512
    RsaPkcsSha512 = 0x00010006,

    /// RSA PKCS#1 PSS Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_PSS
    RsaPkcsPss = 0x00010007,

    /// RSA PKCS#1 PSS SHA-1 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1
    RsaPkcsPssSha1 = 0x00010008,

    /// RSA PKCS#1 PSS SHA-256 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256
    RsaPkcsPssSha256 = 0x00010009,

    /// RSA PKCS#1 PSS SHA-384 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384
    RsaPkcsPssSha384 = 0x0001000A,

    /// RSA PKCS#1 PSS SHA-512 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512
    RsaPkcsPssSha512 = 0x0001000B,

    /// RSA PKCS#1 OAEP Encrypt & Decrypt.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_PKCS_OAEP
    RsaPkcsOaep = 0x0001000C,

    /// RSA AES Key Wrap & Unwrap.
    /// Corresponds to AZIHSM_ALGO_ID_RSA_AES_KEYWRAP
    RsaAesKeywrap = 0x0001000D,

    // =============================================================================
    // Elliptic Curve Algorithms (0x0002xxxx)
    // =============================================================================
    /// EC Key Pair Generation.
    /// Corresponds to AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN
    EcKeyPairGen = 0x00020001,

    /// ECDSA Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_ECDSA
    Ecdsa = 0x00020002,

    /// ECDSA SHA-1 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_ECDSA_SHA1
    EcdsaSha1 = 0x00020003,

    /// ECDSA SHA-256 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_ECDSA_SHA256
    EcdsaSha256 = 0x00020004,

    /// ECDSA SHA-384 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_ECDSA_SHA384
    EcdsaSha384 = 0x00020005,

    /// ECDSA SHA-512 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_ECDSA_SHA512
    EcdsaSha512 = 0x00020006,

    /// ECDH Derive.
    /// Corresponds to AZIHSM_ALGO_ID_ECDH
    Ecdh = 0x00020007,

    // =============================================================================
    // AES Algorithms (0x0003xxxx)
    // =============================================================================
    /// AES Key Generation.
    /// Corresponds to AZIHSM_ALGO_ID_AES_KEY_GEN
    AesKeyGen = 0x00030001,

    /// AES CBC Encrypt & Decrypt.
    /// Corresponds to AZIHSM_ALGO_ID_AES_CBC
    AesCbc = 0x00030002,

    /// AES CBC Pad Encrypt & Decrypt.
    /// Corresponds to AZIHSM_ALGO_ID_AES_CBC_PAD
    AesCbcPad = 0x00030003,

    /// AES XTS Key Generation.
    /// Corresponds to AZIHSM_ALGO_ID_AES_XTS_KEY_GEN
    AesXtsKeyGen = 0x00030004,

    /// AES XTS Encrypt & Decrypt.
    /// Corresponds to AZIHSM_ALGO_ID_AES_XTS
    AesXts = 0x00030005,

    // =============================================================================
    // Hash Algorithms (0x0004xxxx)
    // =============================================================================
    /// SHA-1 Digest.
    /// Corresponds to AZIHSM_ALGO_ID_SHA1
    Sha1 = 0x00040001,

    /// SHA-256 Digest.
    /// Corresponds to AZIHSM_ALGO_ID_SHA256
    Sha256 = 0x00040002,

    /// SHA-384 Digest.
    /// Corresponds to AZIHSM_ALGO_ID_SHA384
    Sha384 = 0x00040003,

    /// SHA-512 Digest.
    /// Corresponds to AZIHSM_ALGO_ID_SHA512
    Sha512 = 0x00040004,

    // =============================================================================
    // HMAC Algorithms (0x0005xxxx)
    // =============================================================================
    /// HMAC SHA-1 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_HMAC_SHA1
    HmacSha1 = 0x00050001,

    /// HMAC SHA-256 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_HMAC_SHA256
    HmacSha256 = 0x00050002,

    /// HMAC SHA-384 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_HMAC_SHA384
    HmacSha384 = 0x00050003,

    /// HMAC SHA-512 Sign & Verify.
    /// Corresponds to AZIHSM_ALGO_ID_HMAC_SHA512
    HmacSha512 = 0x00050004,

    // =============================================================================
    // Key Derivation Function Algorithms (0x0006xxxx)
    // =============================================================================
    /// HKDF Derive.
    /// Corresponds to AZIHSM_ALGO_ID_HKDF_DERIVE
    HkdfDerive = 0x00060001,

    /// SP 800-108 KDF Counter Derive.
    /// Corresponds to AZIHSM_ALGO_ID_KBKDF_COUNTER_DERIVE
    KbkdfCounterDerive = 0x00060002,
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use open_enum::open_enum;
use pastey::paste;

pub mod error;
pub mod sessctrl;

// ── Per-command modules ────────────────────────────────────────────────
pub mod aes_encrypt_decrypt;
pub mod aes_generate_key;
pub mod attest_key;
pub mod change_pin;
pub mod close_session;
pub mod delete_key;
pub mod derive_hkdf;
pub mod derive_kbkdf;
pub mod ecc_generate_key_pair;
pub mod ecc_sign;
pub mod ecdh_key_exchange;
pub mod establish_credential;
pub mod get_api_rev;
pub mod get_cert_chain_info;
pub mod get_certificate;
pub mod get_device_info;
pub mod get_establish_cred_encryption_key;
pub mod get_sealed_bk3;
pub mod get_session_encryption_key;
pub mod get_unwrapping_key;
pub mod hmac;
pub mod init_bk3;
pub mod masked_key;
pub mod open_key;
pub mod open_session;
pub mod reopen_session;
pub mod rsa_mod_exp;
pub mod rsa_unwrap;
pub mod set_sealed_bk3;
pub mod sha_digest;
pub mod unmask_key;

// Re-export codec types.
pub use azihsm_fw_hsm_pal_traits::HsmError;
pub use azihsm_fw_hsm_pal_traits::HsmResult;
pub use error::DdiErrResp;
// Re-export per-command types.
pub use get_api_rev::*;
pub use get_device_info::*;

/// Backward-compatible alias for [`HsmError`].
pub type DdiStatus = u32;

/// Maximum key label length in bytes.
pub const DDI_MAX_KEY_LABEL_LENGTH: usize = 128;

// ── DDI operation codes ────────────────────────────────────────────────

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiOp {
    Invalid = 1001,
    GetApiRev = 1002,
    GetDeviceInfo = 1003,
    DeleteKey = 1014,
    OpenKey = 1015,
    AttestKey = 1016,
    RsaModExp = 1031,
    RsaUnwrap = 1035,
    GetUnwrappingKey = 1051,
    EccGenerateKeyPair = 1061,
    EccSign = 1062,
    AesGenerateKey = 1071,
    AesEncryptDecrypt = 1072,
    EcdhKeyExchange = 1074,
    HkdfDerive = 1075,
    KbkdfCounterHmacDerive = 1076,
    Hmac = 1077,
    GetEstablishCredEncryptionKey = 1101,
    EstablishCredential = 1102,
    GetSessionEncryptionKey = 1103,
    OpenSession = 1104,
    CloseSession = 1105,
    ChangePin = 1106,
    UnmaskKey = 1107,
    GetCertChainInfo = 1108,
    GetCertificate = 1109,
    ReopenSession = 1110,
    InitBk3 = 1111,
    GetSealedBk3 = 1112,
    SetSealedBk3 = 1113,
    ShaDigest = 2006,
}

// ── Key and crypto enums ───────────────────────────────────────────────

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyType {
    Rsa2kPrivate = 1,
    Rsa3kPrivate = 2,
    Rsa4kPrivate = 3,
    Rsa2kPrivateCrt = 4,
    Rsa3kPrivateCrt = 5,
    Rsa4kPrivateCrt = 6,
    Ecc256Private = 7,
    Ecc384Private = 8,
    Ecc521Private = 9,
    Aes128 = 10,
    Aes192 = 11,
    Aes256 = 12,
    AesXtsBulk256 = 13,
    AesGcmBulk256 = 14,
    AesGcmBulk256Unapproved = 15,
    Secret256 = 16,
    Secret384 = 17,
    Secret521 = 18,
    Rsa2kPublic = 19,
    Rsa3kPublic = 20,
    Rsa4kPublic = 21,
    Ecc256Public = 22,
    Ecc384Public = 23,
    Ecc521Public = 24,
    HmacSha256 = 25,
    HmacSha384 = 26,
    HmacSha512 = 27,
    AesCbc256Hmac384 = 28,
    KbKdfSecretSha384 = 29,
    VarHmac256 = 30,
    VarHmac384 = 31,
    VarHmac512 = 32,
    RsaUnwrap = 0xffff,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyClass {
    Rsa = 1,
    RsaCrt = 2,
    Aes = 3,
    AesXtsBulk = 4,
    AesGcmBulk = 5,
    AesGcmBulkUnapproved = 6,
    Ecc = 7,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiHashAlgorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyUsage {
    SignVerify = 1,
    EncryptDecrypt = 2,
    Unwrap = 3,
    Derive = 4,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyAvailability {
    App = 1,
    Session = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiDeviceKind {
    Virtual = 1,
    Physical = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiEccCurve {
    P256 = 1,
    P384 = 2,
    P521 = 3,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiRsaOpType {
    Decrypt = 1,
    Sign = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiRsaCryptoPadding {
    Oaep = 1,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiAesOp {
    Encrypt = 1,
    Decrypt = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[ddi(enumeration)]
#[repr(u32)]
pub enum DdiAesKeySize {
    Aes128 = 1,
    Aes192 = 2,
    Aes256 = 3,
    AesXtsBulk256 = 4,
    AesGcmBulk256 = 5,
    AesGcmBulk256Unapproved = 6,
}

// ── Session kind ───────────────────────────────────────────────────────

pub enum DdiSessionKind {
    None,
    User,
}

impl From<DdiOp> for DdiSessionKind {
    fn from(value: DdiOp) -> Self {
        match value {
            DdiOp::Invalid
            | DdiOp::GetApiRev
            | DdiOp::GetDeviceInfo
            | DdiOp::GetCertChainInfo
            | DdiOp::GetCertificate
            | DdiOp::ShaDigest
            | DdiOp::GetEstablishCredEncryptionKey
            | DdiOp::EstablishCredential
            | DdiOp::GetSessionEncryptionKey
            | DdiOp::OpenSession
            | DdiOp::InitBk3
            | DdiOp::GetSealedBk3
            | DdiOp::SetSealedBk3 => DdiSessionKind::None,
            _ => DdiSessionKind::User,
        }
    }
}

// ── Shared structs ─────────────────────────────────────────────────────

#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiApiRev {
    #[ddi(id = 1)]
    pub major: u32,
    #[ddi(id = 2)]
    pub minor: u32,
}

impl PartialOrd for DdiApiRev {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.major == other.major {
            self.minor.partial_cmp(&other.minor)
        } else {
            self.major.partial_cmp(&other.major)
        }
    }
}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiReqHdr {
    #[ddi(id = 1)]
    pub rev: Option<DdiApiRev>,
    #[ddi(id = 2)]
    pub op: DdiOp,
    #[ddi(id = 3)]
    pub sess_id: Option<u16>,
}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiReqExt {}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiRespHdr {
    #[ddi(id = 1)]
    pub rev: Option<DdiApiRev>,
    #[ddi(id = 2)]
    pub op: DdiOp,
    #[ddi(id = 3)]
    pub sess_id: Option<u16>,
    #[ddi(id = 4)]
    pub status: DdiStatus,
    #[ddi(id = 5)]
    pub fips_approved: bool,
}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiRespExt {}

/// Public key data (raw bytes, no DER conversion).
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiPublicKey<'a> {
    #[ddi(id = 1, max_len = 768)]
    pub raw: &'a DmaBuf,
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
}

/// Key properties for target key creation.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiKeyProperties<'a> {
    #[ddi(id = 1)]
    pub key_usage: DdiKeyUsage,
    #[ddi(id = 2)]
    pub key_availability: DdiKeyAvailability,
    #[ddi(id = 3, max_len = 128)]
    pub key_label: &'a DmaBuf,
}

/// Target key metadata (16-byte bitflag blob).
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiTargetKeyMetadata {
    #[ddi(id = 1)]
    pub blob: [u8; 16],
}

/// Target key properties for key creation/unwrap.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTargetKeyProperties<'a> {
    #[ddi(id = 1)]
    pub key_metadata: DdiTargetKeyMetadata,
    #[ddi(id = 2, max_len = 128)]
    pub key_label: &'a DmaBuf,
}

// ── ddi_op_req_resp! macro ─────────────────────────────────────────────

/// Trait for DDI operation requests.
pub trait DdiOpReq {
    type OpResp;
    fn get_opcode(&self) -> DdiOp;
    fn get_session_id(&self) -> Option<u16>;
}

#[macro_export]
macro_rules! ddi_op_req_resp {
    ($name:ident) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl $crate::DdiOpReq for [<$name CmdReq>] {
                type OpResp = [<$name CmdResp>];
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
    ($name:ident, $lt:lifetime) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl<$lt> $crate::DdiOpReq for [<$name CmdReq>]<$lt> {
                type OpResp = [<$name CmdResp>]<$lt>;
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
    // Variant: Req has no lifetime, Resp has lifetime
    ($name:ident,resp $lt:lifetime) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl $crate::DdiOpReq for [<$name CmdReq>] {
                type OpResp = [<$name CmdResp>]<'static>;
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
    // Variant: Req has lifetime, Resp has no lifetime
    ($name:ident,req $lt:lifetime) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl<$lt> $crate::DdiOpReq for [<$name CmdReq>]<$lt> {
                type OpResp = [<$name CmdResp>];
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
}

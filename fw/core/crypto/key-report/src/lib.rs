// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 key-attestation report builder and parser for AZIHSM
//! firmware.
//!
//! Emits and parses CBOR / `COSE_Sign1` key-attestation reports whose
//! wire format matches `~/mcr-hsm` and the AZIHSM simulator
//! (`ddi/mbor/sim/src/report.rs`) byte-for-byte. The attested public key
//! may be ECC, RSA, or symmetric; the report is always signed with ES384
//! (ECDSA-P384). SHA-384 + ECDSA signing/verification are routed through
//! the supplied [`HsmCrypto`](azihsm_fw_hsm_pal_traits::HsmCrypto)
//! implementation, and all working buffers are
//! [`DmaBuf`](azihsm_fw_hsm_pal_traits::DmaBuf) allocations.
//!
//! * [`key_report`] — build a signed report (query/copy convention).
//! * [`parse_key_report`] — zero-copy decode into a [`KeyReportView`].
//! * [`verify_key_report`] — check a report's ES384 signature.

#![no_std]

mod codec;
mod consts;
mod cose_key;
mod decode;
mod encode;
mod sig;

pub use consts::KeyFlags;
pub use consts::APP_UUID_LEN;
pub use consts::KEY_REPORT_MAX_LEN;
pub use consts::POLICY_HASH_LEN;
pub use consts::PRIV_KEY_LEN;
pub use consts::PUBLIC_KEY_MAX_SIZE;
pub use consts::REPORT_DATA_LEN;
pub use consts::REPORT_VERSION;
pub use consts::REPORT_VERSION_V2;
pub use consts::SIGNATURE_LEN;
pub use consts::VM_LAUNCH_ID_LEN;
pub use cose_key::parse_ec2_cose_key;
pub use cose_key::AttestedPubKey;
pub use cose_key::Ec2CoseKey;
pub use decode::parse_key_report;
pub use decode::verify_key_report;
pub use decode::KeyReportView;
pub use encode::key_report;
pub use encode::KeyReportParams;

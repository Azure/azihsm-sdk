// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic PTA subject shared by CSR generation, certificate issuance,
//! and on-demand PID certificates. PTA certificates preserve this exact DER
//! subject and use SHA-1 of the SEC1 public key as their SKID.

use azihsm_fw_core_crypto_x509_builder::cert_builder;
use azihsm_fw_core_crypto_x509_builder::cert_builder::LeafCertParams;
use azihsm_fw_core_crypto_x509_builder::csr;
use azihsm_fw_core_crypto_x509_chain::key_usage;
use azihsm_fw_core_crypto_x509_chain::CertInfo;
use azihsm_fw_ddi_tbor_types::CERT_MAX_LEN;
use azihsm_fw_hsm_pal_traits::CertChainInfo;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::PartState;

use crate::part_state;

const P384_PRIVATE_KEY_LEN: usize = 48;
const P384_RAW_PUBLIC_KEY_LEN: usize = 96;
const P384_SEC1_PUBLIC_KEY_LEN: usize = P384_RAW_PUBLIC_KEY_LEN + 1;
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
const SHA1_DIGEST_LEN: usize = 20;
const SHA256_DIGEST_LEN: usize = 32;
const SHA384_DIGEST_LEN: usize = 48;
const CERT_SERIAL_LEN: usize = 20;
const CERT_SUBJECT_CN_LEN: usize = 32;
const CERT_NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const CERT_NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const PID_SUBJECT_CN: &[u8] = b"AZIHSM Partition";

/// Fixed PTA commonName prefix. The PTAID hex is appended to it inside the
/// single `commonName`, so the PTA subject is a one-RDN DN.
pub const PTA_SUBJECT_CN: &str = "Azure Integrated HSM PTA";
/// Domain-separation label for SHA-384(label || SEC1 public key).
pub const PTAID_LABEL: &[u8] = b"AZIHSM-PTAID-v1";
/// Digest bytes encoded as hexadecimal inside the subject commonName.
pub const PTAID_LEN: usize = 16;

const _: () = assert!(PTA_SUBJECT_CN.len() + 1 + PTAID_LEN * 2 <= csr::SUBJECT_CN_LEN);
const _: () = assert!(PID_SUBJECT_CN.len() <= CERT_SUBJECT_CN_LEN);

/// Fixed DER prefix of the single-`commonName(64)` Name SEQUENCE shared by
/// the PTA subject and the on-demand PID leaf's issuer:
/// `SEQUENCE { SET { SEQUENCE { OID id-at-commonName, UTF8String(64) } } }`.
/// The 64 CN bytes follow this prefix.
const PTA_SUBJECT_DER_PREFIX: [u8; 13] = [
    0x30, 0x4b, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x40,
];
/// Total length of the PTA subject Name SEQUENCE DER (prefix + CN bytes).
const PTA_SUBJECT_DER_LEN: usize = PTA_SUBJECT_DER_PREFIX.len() + csr::SUBJECT_CN_LEN;

fn fixed_size<const N: usize>(bytes: &[u8]) -> HsmResult<&[u8; N]> {
    bytes.try_into().map_err(|_| HsmError::InternalError)
}

fn sec1_public_key<'a>(
    alloc: &'a impl HsmScopedAlloc,
    raw_public_key: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    if raw_public_key.len() != P384_RAW_PUBLIC_KEY_LEN {
        return Err(HsmError::InternalError);
    }

    let public_key = alloc.dma_alloc(P384_SEC1_PUBLIC_KEY_LEN)?;
    public_key[0] = SEC1_UNCOMPRESSED_TAG;
    public_key[1..].copy_from_slice(raw_public_key);
    Ok(public_key)
}

async fn hash<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    algorithm: HsmHashAlgo,
    input: &DmaBuf,
) -> HsmResult<&'a mut DmaBuf> {
    let digest = alloc.dma_alloc(algorithm.digest_len())?;
    pal.hash(io, algorithm, input, digest, true).await?;
    Ok(digest)
}

async fn issuer_cn<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    pta_public_key: &DmaBuf,
) -> HsmResult<[u8; csr::SUBJECT_CN_LEN]> {
    let input = alloc.dma_alloc(PTAID_LABEL.len() + pta_public_key.len())?;
    input[..PTAID_LABEL.len()].copy_from_slice(PTAID_LABEL);
    input[PTAID_LABEL.len()..].copy_from_slice(pta_public_key);

    let digest = hash(pal, io, alloc, HsmHashAlgo::Sha384, input).await?;
    Ok(subject_cn(fixed_size::<SHA384_DIGEST_LEN>(digest)?))
}

/// Enforce the PTA certificate profile that the on-demand slot-2 PID leaf
/// depends on.
///
/// The PID leaf deterministically stamps its issuer DN and authority key
/// identifier from the partition PTA public key (see
/// [`build_pid_certificate`]). A PTA certificate can therefore anchor
/// future PID leaves only when it carries that exact subject DN (the
/// single-`commonName(64)` CSR profile), a SHA-1(SEC1 PTA public key)
/// subject key identifier, and CA / `keyCertSign` constraints. Rejecting a
/// non-conformant PTA at finalization fails fast instead of silently
/// finalizing a partition whose slot-2 PID leaf could never chain to the
/// accepted PTA certificate.
///
/// The partition's PTA public key must already have been matched against
/// the chain's terminal certificate (`validate_pta_chain`) before this
/// check; here it is used to recompute the expected subject DN and SKID.
pub(crate) async fn validate_pta_profile<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    pta_cert: &CertInfo<'_>,
) -> HsmResult<()> {
    let pta_public_key = sec1_public_key(alloc, part_state::part_pta_pub_key(pal, io)?)?;

    // Subject DN must byte-match the deterministic single-CN(64) profile
    // the PID leaf stamps as its issuer.
    let issuer_cn = issuer_cn(pal, io, alloc, pta_public_key).await?;
    let mut expected_subject = [0u8; PTA_SUBJECT_DER_LEN];
    expected_subject[..PTA_SUBJECT_DER_PREFIX.len()].copy_from_slice(&PTA_SUBJECT_DER_PREFIX);
    expected_subject[PTA_SUBJECT_DER_PREFIX.len()..].copy_from_slice(&issuer_cn);
    if **pta_cert.subject_raw != expected_subject[..] {
        return Err(HsmError::PartFinalPtaMismatch);
    }

    // Subject Key Identifier must be SHA-1 of the SEC1 PTA public key — the
    // value the PID leaf stamps as its authority key identifier.
    let expected_skid = hash(pal, io, alloc, HsmHashAlgo::Sha1, pta_public_key).await?;
    let skid = pta_cert.skid.ok_or(HsmError::PartFinalPtaMismatch)?;
    if skid != &**expected_skid {
        return Err(HsmError::PartFinalPtaMismatch);
    }

    // The PTA must be a CA authorized to sign the PID leaf.
    match pta_cert.basic_constraints {
        Some(constraints) if constraints.ca => {}
        _ => return Err(HsmError::PartFinalPtaMismatch),
    }
    match pta_cert.key_usage {
        Some(bits) if bits & key_usage::KEY_CERT_SIGN != 0 => {}
        _ => return Err(HsmError::PartFinalPtaMismatch),
    }

    Ok(())
}

async fn build_pid_certificate<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    private_key: &DmaBuf,
    output: &mut DmaBuf,
) -> HsmResult<usize> {
    let public_key = sec1_public_key(alloc, part_state::part_id_pub_key(pal, io)?)?;
    let pta_public_key = sec1_public_key(alloc, part_state::part_pta_pub_key(pal, io)?)?;
    let issuer_cn = issuer_cn(pal, io, alloc, pta_public_key).await?;
    let subject_key_id = hash(pal, io, alloc, HsmHashAlgo::Sha1, public_key).await?;
    let authority_key_id = hash(pal, io, alloc, HsmHashAlgo::Sha1, pta_public_key).await?;

    // Bind the serial to the PID public key (via its SHA-1 subject key
    // identifier) so distinct PID keys never share an issuer-and-serial
    // identity across partition resets, while keeping a positive leading
    // byte (bit 7 clear, bit 6 set) for a conformant DER INTEGER.
    let mut serial_number = *fixed_size::<CERT_SERIAL_LEN>(subject_key_id)?;
    serial_number[0] = (serial_number[0] & 0x3f) | 0x40;

    let mut subject_cn = [b' '; CERT_SUBJECT_CN_LEN];
    subject_cn[..PID_SUBJECT_CN.len()].copy_from_slice(PID_SUBJECT_CN);

    let params = LeafCertParams {
        public_key: fixed_size::<P384_SEC1_PUBLIC_KEY_LEN>(public_key)?,
        serial_number: &serial_number,
        not_before: CERT_NOT_BEFORE,
        not_after: CERT_NOT_AFTER,
        issuer_cn: &issuer_cn,
        subject_cn: &subject_cn,
        subject_key_id: fixed_size::<SHA1_DIGEST_LEN>(subject_key_id)?,
        authority_key_id: fixed_size::<SHA1_DIGEST_LEN>(authority_key_id)?,
    };
    cert_builder::build_leaf_cert(pal, io, alloc, &params, private_key, Some(output)).await
}

/// Derive the PTA subject `commonName`: the fixed PTA name, a separating
/// space, and the lowercase-hex PTAID, space-padded to `csr::SUBJECT_CN_LEN`.
///
/// This single CN is the entire PTA subject DN. The on-demand slot-2 PID
/// leaf stamps it verbatim as its issuer CN (via the shared single-CN
/// `leaf_cert` template), so the leaf's issuer DER byte-matches the PTA
/// certificate's subject DER with no runtime DER manipulation.
pub fn subject_cn(digest: &[u8; 48]) -> [u8; csr::SUBJECT_CN_LEN] {
    let mut cn = [b' '; csr::SUBJECT_CN_LEN];
    cn[..PTA_SUBJECT_CN.len()].copy_from_slice(PTA_SUBJECT_CN.as_bytes());
    let hex = b"0123456789abcdef";
    let base = PTA_SUBJECT_CN.len() + 1;
    for (i, byte) in digest[..PTAID_LEN].iter().enumerate() {
        cn[base + 2 * i] = hex[usize::from(byte >> 4)];
        cn[base + 2 * i + 1] = hex[usize::from(byte & 15)];
    }
    cn
}

/// Generate one PTA-signed PID leaf for this request, without caching it.
pub(crate) async fn pid_certificate<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
) -> HsmResult<&'p DmaBuf> {
    if part_state::part_state(pal, io)? != PartState::Initialized {
        return Err(HsmError::InvalidArg);
    }
    let out = pal.dma_alloc(io, CERT_MAX_LEN)?;
    let len = pal
        .alloc_scoped_async(io, async |alloc| {
            let key_id = part_state::part_pta_key_id(pal, io)?;
            let key = pal.vault_key(io, key_id)?;
            if key.len() != P384_PRIVATE_KEY_LEN {
                return Err(HsmError::InternalError);
            }
            let private = alloc.dma_alloc(P384_PRIVATE_KEY_LEN)?;
            private.copy_from_slice(key);
            let result = build_pid_certificate(pal, io, alloc, private, out).await;
            private.zeroize();
            result
        })
        .await?;
    Ok(out.split_at(len).0)
}

/// Fingerprint of a newly generated leaf; later reads generate different DER.
pub(crate) async fn chain_info<P: HsmPal>(pal: &P, io: &impl HsmIo) -> HsmResult<CertChainInfo> {
    let cert = pid_certificate(pal, io).await?;
    let digest = pal.dma_alloc(io, SHA256_DIGEST_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha256, cert, digest, true)
        .await?;
    let thumbprint = *fixed_size::<SHA256_DIGEST_LEN>(digest)?;
    Ok(CertChainInfo {
        count: 1,
        thumbprint,
    })
}

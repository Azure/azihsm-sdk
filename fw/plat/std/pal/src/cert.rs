// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate storage and generation for the standard PAL.
//!
//! Generates a 4-certificate chain for slot 0:
//!
//! | Index | Certificate | Scope |
//! |-------|-------------|-------|
//! | 0 | Root CA (self-signed) | Shared |
//! | 1 | DeviceId CA (Intermediate, path_len=1) | Shared |
//! | 2 | Alias CA (Intermediate, path_len=0) | Shared |
//! | 3 | Partition Id Leaf | Per-partition (on-demand) |
//!
//! The first 3 certificates are generated once at PAL construction time.
//! The partition leaf cert is generated on-demand when `get_cert(slot=0,
//! idx=3)` is first called, then cached in the partition entry for
//! consistency (ECDSA signatures are non-deterministic).
//!
//! The Alias CA key pair is retained so it can sign partition leaf certs.

use azihsm_crypto::*;
use azihsm_fw_hsm_std_x509::cert_builder;
use azihsm_fw_hsm_std_x509::cert_builder::*;

use super::*;
use crate::part::NUM_PARTITIONS;
use crate::part::P384_PUB_KEY_LEN;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ROOT_CN: &str = "AZIHSM Root CA";
const ROOT_SN: &str = "ROOTCA01";
const DEVICEID_CN: &str = "AZIHSM DeviceId CA";
const DEVICEID_SN: &str = "DEVICEIDCA01";
const ALIAS_CN: &str = "AZIHSM Alias CA";
const ALIAS_SN: &str = "ALIASCA01";
const LEAF_CN: &str = "AZIHSM Partition";

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";

/// Maximum DER-encoded certificate size.
pub(crate) const MAX_CERT_DER_LEN: usize = 2048;

/// P-384 ECDSA signature component size (r or s).
const P384_SIG_COMPONENT: usize = 48;

/// Uncompressed P-384 public key length (0x04 || x || y).
const P384_UNCOMPRESSED_LEN: usize = 97;

/// P-384 private key DER max length.
const P384_PRIV_DER_MAX: usize = 256;

/// Number of certs in slot 0 chain.
pub(crate) const SLOT0_CERT_COUNT: u8 = 4;

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

/// Temporary key pair used during cert chain construction.
struct KeyPair {
    priv_key: EccPrivateKey,
    uncompressed: [u8; P384_UNCOMPRESSED_LEN],
    ski: [u8; 20],
}

impl KeyPair {
    /// Generate a new P-384 key pair and compute SKI.
    fn generate() -> HsmResult<Self> {
        let priv_key =
            EccPrivateKey::from_curve(EccCurve::P384).map_err(|_| HsmError::InternalError)?;
        let (x, y) = priv_key.coord_vec().map_err(|_| HsmError::InternalError)?;
        let mut uncompressed = [0u8; P384_UNCOMPRESSED_LEN];
        uncompressed[0] = 0x04;
        uncompressed[1..49].copy_from_slice(&x);
        uncompressed[49..97].copy_from_slice(&y);
        let ski = compute_ski(&uncompressed)?;
        Ok(Self {
            priv_key,
            uncompressed,
            ski,
        })
    }

    /// Sign TBS data with this key pair.
    fn sign_tbs(
        &self,
        tbs: &[u8],
    ) -> HsmResult<([u8; P384_SIG_COMPONENT], [u8; P384_SIG_COMPONENT])> {
        sign_with_key(&self.priv_key, tbs)
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Compute SHA-1 Subject Key Identifier from uncompressed public key.
fn compute_ski(uncompressed: &[u8; P384_UNCOMPRESSED_LEN]) -> HsmResult<[u8; 20]> {
    let mut algo = HashAlgo::sha1();
    let mut result = [0u8; 20];
    algo.hash(uncompressed, Some(&mut result))
        .map_err(|_| HsmError::InternalError)?;
    Ok(result)
}

/// Compute SHA-256 hash of a single buffer.
fn sha256(data: &[u8]) -> HsmResult<[u8; 32]> {
    let mut algo = HashAlgo::sha256();
    let mut result = [0u8; 32];
    algo.hash(data, Some(&mut result))
        .map_err(|_| HsmError::InternalError)?;
    Ok(result)
}

/// Compute SHA-256 hash of two buffers concatenated.
fn sha256_concat(a: &[u8], b: &[u8]) -> HsmResult<[u8; 32]> {
    let algo = HashAlgo::sha256();
    let mut ctx = algo.hash_init().map_err(|_| HsmError::InternalError)?;
    ctx.update(a).map_err(|_| HsmError::InternalError)?;
    ctx.update(b).map_err(|_| HsmError::InternalError)?;
    let mut result = [0u8; 32];
    ctx.finish(Some(&mut result))
        .map_err(|_| HsmError::InternalError)?;
    Ok(result)
}

/// Sign TBS data with an ECC private key, returning (r, s) components.
fn sign_with_key(
    key: &EccPrivateKey,
    tbs: &[u8],
) -> HsmResult<([u8; P384_SIG_COMPONENT], [u8; P384_SIG_COMPONENT])> {
    let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
    let sig_len = algo
        .sign(key, tbs, None)
        .map_err(|_| HsmError::InternalError)?;
    let mut sig_buf = [0u8; 96];
    algo.sign(key, tbs, Some(&mut sig_buf[..sig_len]))
        .map_err(|_| HsmError::InternalError)?;
    let mut r = [0u8; P384_SIG_COMPONENT];
    let mut s = [0u8; P384_SIG_COMPONENT];
    r.copy_from_slice(&sig_buf[..48]);
    s.copy_from_slice(&sig_buf[48..96]);
    Ok((r, s))
}

/// Generate a deterministic serial number for cert at `index` (1-based).
fn make_serial(index: u8) -> [u8; 20] {
    let mut serial = [0u8; 20];
    serial[0] = index;
    for (i, byte) in serial.iter_mut().enumerate().skip(1) {
        *byte = (i as u8).wrapping_mul(index.wrapping_mul(7));
    }
    serial
}

/// Generate a hex-encoded serial number string for a partition leaf cert.
fn make_leaf_sn(pid: u8) -> [u8; 4] {
    let hi = pid >> 4;
    let lo = pid & 0x0F;
    let to_hex = |n: u8| if n < 10 { b'0' + n } else { b'A' + n - 10 };
    [b'P', b'D', to_hex(hi), to_hex(lo)]
}

// ---------------------------------------------------------------------------
// TBS patching helpers (mirrors integration test pattern)
// ---------------------------------------------------------------------------

fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    use azihsm_fw_hsm_std_x509::root_cert::*;
    let cn = cert_builder::pad_cn(params.subject_cn).expect("valid CN");
    let sn = cert_builder::pad_sn(params.subject_sn).expect("valid SN");
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
}

fn patch_tbs_intermediate(tbs: &mut [u8], params: &IntermediateCertParams<'_>) {
    use azihsm_fw_hsm_std_x509::intermediate_cert::*;
    let s_cn = cert_builder::pad_cn(params.subject_cn).expect("valid CN");
    let i_cn = cert_builder::pad_cn(params.issuer_cn).expect("valid CN");
    let s_sn = cert_builder::pad_sn(params.subject_sn).expect("valid SN");
    let i_sn = cert_builder::pad_sn(params.issuer_sn).expect("valid SN");
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[PATH_LEN_OFFSET] = params.path_len;
}

fn patch_tbs_leaf(tbs: &mut [u8], params: &LeafCertParams<'_>) {
    use azihsm_fw_hsm_std_x509::leaf_cert::*;
    let s_cn = cert_builder::pad_cn(params.subject_cn).expect("valid CN");
    let i_cn = cert_builder::pad_cn(params.issuer_cn).expect("valid CN");
    let s_sn = cert_builder::pad_sn(params.subject_sn).expect("valid SN");
    let i_sn = cert_builder::pad_sn(params.issuer_sn).expect("valid SN");
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[KEY_USAGE_OFFSET..KEY_USAGE_OFFSET + 2].copy_from_slice(&params.key_usage.to_bytes());
}

// ---------------------------------------------------------------------------
// SharedCertStore
// ---------------------------------------------------------------------------

/// Shared certificate storage for the 3 common certs (Root, DeviceId, Alias)
/// plus the Alias key material needed for on-demand leaf cert signing.
pub(crate) struct SharedCertStore {
    /// Root CA DER-encoded certificate.
    root_cert: [u8; MAX_CERT_DER_LEN],
    root_cert_len: usize,

    /// DeviceId CA DER-encoded certificate.
    deviceid_cert: [u8; MAX_CERT_DER_LEN],
    deviceid_cert_len: usize,

    /// Alias CA DER-encoded certificate.
    alias_cert: [u8; MAX_CERT_DER_LEN],
    alias_cert_len: usize,

    /// Alias CA private key (PKCS#8 DER) — retained for signing leaf certs.
    alias_priv_key_der: [u8; P384_PRIV_DER_MAX],
    alias_priv_key_len: usize,

    /// Alias CA uncompressed public key (0x04 || x || y).
    #[allow(dead_code)]
    alias_uncompressed: [u8; P384_UNCOMPRESSED_LEN],

    /// Alias CA Subject Key Identifier (SHA-1 of uncompressed pubkey).
    alias_ski: [u8; 20],

    /// Precomputed SHA-256(root_cert_der || deviceid_cert_der).
    root_deviceid_hash: [u8; 32],
}

impl SharedCertStore {
    /// Generate all 3 shared certificates and store them.
    ///
    /// # Panics
    ///
    /// Panics if cryptographic operations fail during initialization.
    /// This is acceptable for a simulator — if crypto fails at init,
    /// the entire system is non-functional.
    pub(crate) fn new() -> Self {
        Self::try_new().expect("shared cert store initialization failed")
    }

    fn try_new() -> HsmResult<Self> {
        // --- Root CA ---
        let root_key = KeyPair::generate()?;
        let root_serial = make_serial(1);
        let root_params = RootCertParams {
            public_key: &root_key.uncompressed,
            serial_number: &root_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: ROOT_CN,
            subject_sn: ROOT_SN,
            subject_key_id: &root_key.ski,
        };
        let mut root_cert = [0u8; MAX_CERT_DER_LEN];
        let mut tbs = azihsm_fw_hsm_std_x509::root_cert::TBS_TEMPLATE;
        patch_tbs_root(&mut tbs, &root_params);
        let (r, s) = root_key.sign_tbs(&tbs)?;
        let root_cert_len = cert_builder::build_root_cert(&root_params, &r, &s, &mut root_cert)
            .ok_or(HsmError::InternalError)?;

        // --- DeviceId CA ---
        let deviceid_key = KeyPair::generate()?;
        let deviceid_serial = make_serial(2);
        let deviceid_params = IntermediateCertParams {
            public_key: &deviceid_key.uncompressed,
            serial_number: &deviceid_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: DEVICEID_CN,
            subject_sn: DEVICEID_SN,
            issuer_cn: ROOT_CN,
            issuer_sn: ROOT_SN,
            subject_key_id: &deviceid_key.ski,
            authority_key_id: &root_key.ski,
            path_len: 1,
        };
        let mut deviceid_cert = [0u8; MAX_CERT_DER_LEN];
        let mut tbs = azihsm_fw_hsm_std_x509::intermediate_cert::TBS_TEMPLATE;
        patch_tbs_intermediate(&mut tbs, &deviceid_params);
        let (r, s) = root_key.sign_tbs(&tbs)?;
        let deviceid_cert_len =
            cert_builder::build_intermediate_cert(&deviceid_params, &r, &s, &mut deviceid_cert)
                .ok_or(HsmError::InternalError)?;

        // --- Alias CA ---
        let alias_key = KeyPair::generate()?;
        let alias_serial = make_serial(3);
        let alias_params = IntermediateCertParams {
            public_key: &alias_key.uncompressed,
            serial_number: &alias_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: ALIAS_CN,
            subject_sn: ALIAS_SN,
            issuer_cn: DEVICEID_CN,
            issuer_sn: DEVICEID_SN,
            subject_key_id: &alias_key.ski,
            authority_key_id: &deviceid_key.ski,
            path_len: 0,
        };
        let mut alias_cert = [0u8; MAX_CERT_DER_LEN];
        let mut tbs = azihsm_fw_hsm_std_x509::intermediate_cert::TBS_TEMPLATE;
        patch_tbs_intermediate(&mut tbs, &alias_params);
        let (r, s) = deviceid_key.sign_tbs(&tbs)?;
        let alias_cert_len =
            cert_builder::build_intermediate_cert(&alias_params, &r, &s, &mut alias_cert)
                .ok_or(HsmError::InternalError)?;

        // Export alias private key for on-demand leaf signing.
        let mut alias_priv_key_der = [0u8; P384_PRIV_DER_MAX];
        let alias_priv_key_len = alias_key
            .priv_key
            .to_bytes(Some(&mut alias_priv_key_der))
            .map_err(|_| HsmError::InternalError)?;

        // Precompute SHA-256(root_cert || deviceid_cert).
        let root_deviceid_hash = sha256_concat(
            &root_cert[..root_cert_len],
            &deviceid_cert[..deviceid_cert_len],
        )?;

        Ok(Self {
            root_cert,
            root_cert_len,
            deviceid_cert,
            deviceid_cert_len,
            alias_cert,
            alias_cert_len,
            alias_priv_key_der,
            alias_priv_key_len,
            alias_uncompressed: alias_key.uncompressed,
            alias_ski: alias_key.ski,
            root_deviceid_hash,
        })
    }

    /// Returns the shared cert at `idx` (0=Root, 1=DeviceId, 2=Alias).
    pub(crate) fn shared_cert(&self, idx: u8) -> Option<&[u8]> {
        match idx {
            0 => Some(&self.root_cert[..self.root_cert_len]),
            1 => Some(&self.deviceid_cert[..self.deviceid_cert_len]),
            2 => Some(&self.alias_cert[..self.alias_cert_len]),
            _ => None,
        }
    }

    /// Build a partition leaf cert on-demand, signed by the Alias CA key.
    ///
    /// `raw_pubkey` is the partition's 96-byte (x || y) public key.
    pub(crate) fn build_partition_leaf(
        &self,
        pid: u8,
        raw_pubkey: &[u8; P384_PUB_KEY_LEN],
        out: &mut [u8; MAX_CERT_DER_LEN],
    ) -> HsmResult<usize> {
        // Build uncompressed public key (0x04 prefix).
        let mut subject_pubkey = [0u8; P384_UNCOMPRESSED_LEN];
        subject_pubkey[0] = 0x04;
        subject_pubkey[1..].copy_from_slice(raw_pubkey);

        let subject_ski = compute_ski(&subject_pubkey)?;
        let leaf_serial = make_serial(4_u8.wrapping_add(pid));
        let sn_bytes = make_leaf_sn(pid);
        let leaf_sn = core::str::from_utf8(&sn_bytes).map_err(|_| HsmError::InternalError)?;

        let params = LeafCertParams {
            public_key: &subject_pubkey,
            serial_number: &leaf_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: LEAF_CN,
            subject_sn: leaf_sn,
            issuer_cn: ALIAS_CN,
            issuer_sn: ALIAS_SN,
            subject_key_id: &subject_ski,
            authority_key_id: &self.alias_ski,
            key_usage: KeyUsage::DIGITAL_SIGNATURE,
        };

        // Patch TBS template and sign with alias key.
        let mut tbs = azihsm_fw_hsm_std_x509::leaf_cert::TBS_TEMPLATE;
        patch_tbs_leaf(&mut tbs, &params);

        let alias_key =
            EccPrivateKey::from_bytes(&self.alias_priv_key_der[..self.alias_priv_key_len])
                .map_err(|_| HsmError::InternalError)?;
        let (r, s) = sign_with_key(&alias_key, &tbs)?;

        cert_builder::build_leaf_cert(&params, &r, &s, out).ok_or(HsmError::InternalError)
    }

    /// Compute the thumbprint for a partition's cert chain.
    ///
    /// ```text
    /// thumbprint = SHA-256(
    ///     SHA-256(root_cert || deviceid_cert)  ||   // precomputed
    ///     SHA-256(alias_cert)                  ||
    ///     SHA-256(partition_leaf_cert)
    /// )
    /// ```
    pub(crate) fn compute_thumbprint(&self, leaf_cert: &[u8]) -> HsmResult<[u8; 32]> {
        let alias_hash = sha256(&self.alias_cert[..self.alias_cert_len])?;
        let leaf_hash = sha256(leaf_cert)?;

        // Concatenate: root_deviceid_hash || alias_hash || leaf_hash → 96 bytes
        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(&self.root_deviceid_hash);
        combined[32..64].copy_from_slice(&alias_hash);
        combined[64..96].copy_from_slice(&leaf_hash);
        sha256(&combined)
    }
}

// ---------------------------------------------------------------------------
// CertificateStore trait implementation
// ---------------------------------------------------------------------------

impl HsmCertStore for StdHsmPal {
    async fn get_cert_chain_info(&self, part_id: u8, slot_id: u8) -> HsmResult<CertChainInfo> {
        if slot_id != 0 {
            return Err(HsmError::InvalidArg);
        }

        // SAFETY: Single-threaded Embassy executor, sync method.
        let table = unsafe { &mut *self.part_table.get() };
        let idx = part_id as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &mut table.entries[idx];
        if entry.state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }

        // Ensure leaf cert is cached for consistent thumbprint.
        if entry.leaf_cert_len == 0 {
            let len = self.cert_store.build_partition_leaf(
                part_id,
                &entry.pub_key,
                &mut entry.leaf_cert,
            )?;
            entry.leaf_cert_len = len;
        }

        let thumbprint = self
            .cert_store
            .compute_thumbprint(&entry.leaf_cert[..entry.leaf_cert_len])?;

        Ok(CertChainInfo {
            count: SLOT0_CERT_COUNT,
            thumbprint,
        })
    }

    async fn get_cert(
        &self,
        part_id: u8,
        slot_id: u8,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        if slot_id != 0 {
            return Err(HsmError::InvalidArg);
        }

        // Shared certs (idx 0–2) — no partition state needed.
        if idx <= 2 {
            let src = self
                .cert_store
                .shared_cert(idx)
                .ok_or(HsmError::InvalidArg)?;
            if let Some(buf) = cert {
                if buf.len() < src.len() {
                    return Err(HsmError::NotEnoughSpace);
                }
                buf[..src.len()].copy_from_slice(src);
            }
            return Ok(src.len());
        }

        // Partition leaf cert (idx 3).
        if idx != 3 {
            return Err(HsmError::InvalidArg);
        }

        // SAFETY: Single-threaded Embassy executor, no .await with active borrow.
        let table = unsafe { &mut *self.part_table.get() };
        let pidx = part_id as usize;
        if pidx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &mut table.entries[pidx];
        if entry.state == PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }

        // Lazy-generate and cache.
        if entry.leaf_cert_len == 0 {
            let len = self.cert_store.build_partition_leaf(
                part_id,
                &entry.pub_key,
                &mut entry.leaf_cert,
            )?;
            entry.leaf_cert_len = len;
        }

        let len = entry.leaf_cert_len;
        if let Some(buf) = cert {
            if buf.len() < len {
                return Err(HsmError::NotEnoughSpace);
            }
            buf[..len].copy_from_slice(&entry.leaf_cert[..len]);
        }
        Ok(len)
    }
}

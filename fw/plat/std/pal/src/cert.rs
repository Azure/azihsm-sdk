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
//! The first 3 certificates are generated during PAL initialization via
//! [`StdHsmPal::init_cert_store`].  The leaf cert is generated lazily
//! on first access per partition.
//!
//! Sideband paths (init / leaf-cert generation / chain hashing) call the
//! underlying [`StdHash`](crate::drivers::hash::StdHash) and
//! [`StdEcc`](crate::drivers::ecc::StdEcc) drivers directly — they have
//! no `HsmIo` context to satisfy the new PAL crypto trait surface, so
//! they bypass it entirely. The trait impl ([`HsmCertStore`]) at the
//! bottom of this file is the only path the core uses.

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::ExportableHsmKey;
use azihsm_crypto::HashAlgo;
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

/// Number of certs in slot 0 chain.
pub(crate) const SLOT0_CERT_COUNT: u8 = 4;

// ---------------------------------------------------------------------------
// Pure helpers (no crypto)
// ---------------------------------------------------------------------------

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

/// Build uncompressed public key (0x04 || x || y) from raw coords.
fn to_uncompressed(raw: &[u8; P384_PUB_KEY_LEN]) -> [u8; P384_UNCOMPRESSED_LEN] {
    let mut out = [0u8; P384_UNCOMPRESSED_LEN];
    out[0] = 0x04;
    out[1..].copy_from_slice(raw);
    out
}

// ---------------------------------------------------------------------------
// TBS patching helpers
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
// SharedCertStore — holds generated certs + alias key for leaf signing
// ---------------------------------------------------------------------------

/// Shared certificate storage for the 3 common certs (Root, DeviceId, Alias)
/// plus the Alias key material needed for on-demand leaf cert signing.
///
/// Initialized lazily via [`StdHsmPal::init_cert_store`] during PAL init.
pub(crate) struct SharedCertStore {
    root_cert: [u8; MAX_CERT_DER_LEN],
    root_cert_len: usize,
    deviceid_cert: [u8; MAX_CERT_DER_LEN],
    deviceid_cert_len: usize,
    alias_cert: [u8; MAX_CERT_DER_LEN],
    alias_cert_len: usize,
    /// Alias CA private key DER — for signing leaf certs.
    alias_priv_key: Vec<u8>,
    /// Alias CA Subject Key Identifier.
    pub(crate) alias_ski: [u8; 20],
    /// Precomputed SHA-256(root_cert || deviceid_cert).
    root_deviceid_hash: [u8; 32],
}

impl SharedCertStore {
    /// Create an empty (uninitialized) cert store.
    pub(crate) fn new() -> Self {
        Self {
            root_cert: [0u8; MAX_CERT_DER_LEN],
            root_cert_len: 0,
            deviceid_cert: [0u8; MAX_CERT_DER_LEN],
            deviceid_cert_len: 0,
            alias_cert: [0u8; MAX_CERT_DER_LEN],
            alias_cert_len: 0,
            alias_priv_key: Vec::new(),
            alias_ski: [0u8; 20],
            root_deviceid_hash: [0u8; 32],
        }
    }

    pub(crate) fn shared_cert(&self, idx: u8) -> Option<&[u8]> {
        match idx {
            0 => Some(&self.root_cert[..self.root_cert_len]),
            1 => Some(&self.deviceid_cert[..self.deviceid_cert_len]),
            2 => Some(&self.alias_cert[..self.alias_cert_len]),
            _ => None,
        }
    }

    pub(crate) fn alias_priv_key(&self) -> &[u8] {
        &self.alias_priv_key
    }
}

// ---------------------------------------------------------------------------
// Async cert generation on StdHsmPal (uses PAL traits)
// ---------------------------------------------------------------------------

/// Temporary key pair: raw pub coords + private DER.
struct CertKeyPair {
    priv_key: Vec<u8>,
    uncompressed: [u8; P384_UNCOMPRESSED_LEN],
    ski: [u8; 20],
}

impl StdHsmPal {
    /// Initialize the shared cert store by generating all 3 certs.
    ///
    /// Must be called during PAL initialization before any cert access.
    /// Uses [`HsmEcc::ecc_gen_keypair`] and [`HsmHash`] via PAL traits.
    pub async fn init_cert_store(&self) -> HsmResult<()> {
        // --- Generate 3 key pairs ---
        let root_kp = self.gen_cert_keypair().await?;
        let deviceid_kp = self.gen_cert_keypair().await?;
        let alias_kp = self.gen_cert_keypair().await?;

        // --- Root CA ---
        let root_serial = make_serial(1);
        let root_params = RootCertParams {
            public_key: &root_kp.uncompressed,
            serial_number: &root_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: ROOT_CN,
            subject_sn: ROOT_SN,
            subject_key_id: &root_kp.ski,
        };
        let mut tbs = azihsm_fw_hsm_std_x509::root_cert::TBS_TEMPLATE;
        patch_tbs_root(&mut tbs, &root_params);
        let (r, s) = self.hash_and_sign(&root_kp.priv_key, &tbs).await?;
        let mut root_cert = [0u8; MAX_CERT_DER_LEN];
        let root_cert_len = cert_builder::build_root_cert(&root_params, &r, &s, &mut root_cert)
            .ok_or(HsmError::InternalError)?;

        // --- DeviceId CA ---
        let deviceid_serial = make_serial(2);
        let deviceid_params = IntermediateCertParams {
            public_key: &deviceid_kp.uncompressed,
            serial_number: &deviceid_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: DEVICEID_CN,
            subject_sn: DEVICEID_SN,
            issuer_cn: ROOT_CN,
            issuer_sn: ROOT_SN,
            subject_key_id: &deviceid_kp.ski,
            authority_key_id: &root_kp.ski,
            path_len: 1,
        };
        let mut tbs = azihsm_fw_hsm_std_x509::intermediate_cert::TBS_TEMPLATE;
        patch_tbs_intermediate(&mut tbs, &deviceid_params);
        let (r, s) = self.hash_and_sign(&root_kp.priv_key, &tbs).await?;
        let mut deviceid_cert = [0u8; MAX_CERT_DER_LEN];
        let deviceid_cert_len =
            cert_builder::build_intermediate_cert(&deviceid_params, &r, &s, &mut deviceid_cert)
                .ok_or(HsmError::InternalError)?;

        // --- Alias CA ---
        let alias_serial = make_serial(3);
        let alias_params = IntermediateCertParams {
            public_key: &alias_kp.uncompressed,
            serial_number: &alias_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: ALIAS_CN,
            subject_sn: ALIAS_SN,
            issuer_cn: DEVICEID_CN,
            issuer_sn: DEVICEID_SN,
            subject_key_id: &alias_kp.ski,
            authority_key_id: &deviceid_kp.ski,
            path_len: 0,
        };
        let mut tbs = azihsm_fw_hsm_std_x509::intermediate_cert::TBS_TEMPLATE;
        patch_tbs_intermediate(&mut tbs, &alias_params);
        let (r, s) = self.hash_and_sign(&deviceid_kp.priv_key, &tbs).await?;
        let mut alias_cert = [0u8; MAX_CERT_DER_LEN];
        let alias_cert_len =
            cert_builder::build_intermediate_cert(&alias_params, &r, &s, &mut alias_cert)
                .ok_or(HsmError::InternalError)?;

        // Precompute SHA-256(root_cert || deviceid_cert).
        let mut rd_concat = vec![0u8; root_cert_len + deviceid_cert_len];
        rd_concat[..root_cert_len].copy_from_slice(&root_cert[..root_cert_len]);
        rd_concat[root_cert_len..].copy_from_slice(&deviceid_cert[..deviceid_cert_len]);
        let mut root_deviceid_hash = [0u8; 32];
        self.hash
            .hash(HashAlgo::sha256(), &rd_concat, &mut root_deviceid_hash)
            .await?;

        // Commit to store.
        let store = &mut *self.cert_store_mut();
        store.root_cert = root_cert;
        store.root_cert_len = root_cert_len;
        store.deviceid_cert = deviceid_cert;
        store.deviceid_cert_len = deviceid_cert_len;
        store.alias_cert = alias_cert;
        store.alias_cert_len = alias_cert_len;
        store.alias_priv_key = alias_kp.priv_key;
        store.alias_ski = alias_kp.ski;
        store.root_deviceid_hash = root_deviceid_hash;

        Ok(())
    }

    /// Generate a P-384 key pair and compute SKI for cert construction.
    ///
    /// Bypasses the [`HsmEcc`] trait (which requires an `HsmIo`) and
    /// drives the [`StdEcc`] driver directly, mirroring what the trait
    /// impl in `crate::ecc` would do.
    async fn gen_cert_keypair(&self) -> HsmResult<CertKeyPair> {
        // Generate the keypair, then serialize: the public key as raw
        // big-endian `x ∥ y`, the private key as raw HSM scalar bytes.
        let (pk, pub_key) = self.ecc.gen_keypair(EccCurve::P384).await?;
        let mut pub_raw = [0u8; P384_PUB_KEY_LEN];
        self.ecc.pub_coords(&pub_key, true, &mut pub_raw).await?;
        let priv_len = pk.hsm_bytes_len();
        let mut priv_key = vec![0u8; priv_len];
        pk.to_hsm_bytes(&mut priv_key[..priv_len])
            .map_err(|_| HsmError::EccExportError)?;

        let uncompressed = to_uncompressed(&pub_raw);
        let mut ski = [0u8; 20];
        self.hash
            .hash(HashAlgo::sha1(), &uncompressed, &mut ski)
            .await?;

        Ok(CertKeyPair {
            priv_key,
            uncompressed,
            ski,
        })
    }

    /// Hash TBS with SHA-384, then sign with ECC P-384. Returns (r, s).
    ///
    /// Sideband helper that bypasses the PAL crypto trait surface
    /// (no `HsmIo` available during cert init / leaf-cert generation).
    async fn hash_and_sign(
        &self,
        priv_key: &[u8],
        tbs: &[u8],
    ) -> HsmResult<([u8; P384_SIG_COMPONENT], [u8; P384_SIG_COMPONENT])> {
        let mut tbs_hash = [0u8; 48];
        self.hash
            .hash(HashAlgo::sha384(), tbs, &mut tbs_hash)
            .await?;

        let key = EccPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let sig = self.ecc.ecc_sign(&key, &tbs_hash).await?;
        if sig.len() < 2 * P384_SIG_COMPONENT {
            return Err(HsmError::EccSignFailed);
        }

        let mut r = [0u8; P384_SIG_COMPONENT];
        let mut s = [0u8; P384_SIG_COMPONENT];
        r.copy_from_slice(&sig[..P384_SIG_COMPONENT]);
        s.copy_from_slice(&sig[P384_SIG_COMPONENT..2 * P384_SIG_COMPONENT]);
        Ok((r, s))
    }

    /// Ensure the partition's leaf cert is cached.
    async fn ensure_leaf_cert(&self, pid: u8) -> HsmResult<()> {
        {
            let table = unsafe { &*self.part_table.get() };
            let idx = pid as usize;
            if idx >= NUM_PARTITIONS {
                return Err(HsmError::InvalidArg);
            }
            // Reject Unallocated and Disabled — in both cases the
            // partition has no live identity key to sign against
            // (Unallocated has no `id_pub_key` at all; Disabled has
            // a zeroed one).  Allocated is fine: `part_alloc`
            // provisions `id_pub_key` before transitioning.
            let state = table.entries[idx].state;
            if state == PartState::Unallocated || state == PartState::Disabled {
                return Err(HsmError::InvalidArg);
            }
            if table.entries[idx].leaf_cert_len > 0 {
                return Ok(());
            }
        }

        let table = unsafe { &*self.part_table.get() };
        let entry = &table.entries[pid as usize];
        let uncompressed = to_uncompressed(&entry.id_pub_key);

        // SKI = SHA-1(uncompressed pubkey).
        let mut ski = [0u8; 20];
        self.hash
            .hash(HashAlgo::sha1(), &uncompressed, &mut ski)
            .await?;

        // Prepare TBS.
        let leaf_serial = make_serial(4_u8.wrapping_add(pid));
        let sn_bytes = make_leaf_sn(pid);
        let leaf_sn = core::str::from_utf8(&sn_bytes).map_err(|_| HsmError::InternalError)?;
        let params = LeafCertParams {
            public_key: &uncompressed,
            serial_number: &leaf_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: LEAF_CN,
            subject_sn: leaf_sn,
            issuer_cn: ALIAS_CN,
            issuer_sn: ALIAS_SN,
            subject_key_id: &ski,
            authority_key_id: &self.cert_store().alias_ski,
            key_usage: KeyUsage::DIGITAL_SIGNATURE,
        };
        let mut tbs = azihsm_fw_hsm_std_x509::leaf_cert::TBS_TEMPLATE;
        patch_tbs_leaf(&mut tbs, &params);

        // Sign via PAL.
        let (r, s) = self
            .hash_and_sign(self.cert_store().alias_priv_key(), &tbs)
            .await?;

        // Build final cert and cache.
        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[pid as usize];
        let len = cert_builder::build_leaf_cert(&params, &r, &s, &mut entry.leaf_cert)
            .ok_or(HsmError::InternalError)?;
        entry.leaf_cert_len = len;
        Ok(())
    }

    /// Get mutable reference to cert store (for init).
    #[allow(clippy::mut_from_ref)]
    fn cert_store_mut(&self) -> &mut SharedCertStore {
        // SAFETY: only called during init, single-threaded.
        unsafe { &mut *self.cert_store.get() }
    }

    /// Get immutable reference to cert store.
    fn cert_store(&self) -> &SharedCertStore {
        // SAFETY: single-threaded Embassy executor.
        unsafe { &*self.cert_store.get() }
    }
}

// ---------------------------------------------------------------------------
// CertificateStore trait implementation
// ---------------------------------------------------------------------------

impl HsmCertStore for StdHsmPal {
    async fn get_cert_chain_info(
        &self,
        _io: &impl HsmIo,
        part_id: HsmPartId,
        slot_id: u8,
    ) -> HsmResult<CertChainInfo> {
        let pid = u8::from(part_id);
        if slot_id != 0 {
            return Err(HsmError::InvalidArg);
        }

        self.ensure_leaf_cert(pid).await?;

        let table = unsafe { &*self.part_table.get() };
        let entry = &table.entries[pid as usize];

        // Thumbprint = SHA-256(SHA-256(root||devid) || SHA-256(alias) || SHA-256(leaf))
        let mut alias_hash = [0u8; 32];
        self.hash
            .hash(
                HashAlgo::sha256(),
                self.cert_store().shared_cert(2).unwrap(),
                &mut alias_hash,
            )
            .await?;

        let mut leaf_hash = [0u8; 32];
        self.hash
            .hash(
                HashAlgo::sha256(),
                &entry.leaf_cert[..entry.leaf_cert_len],
                &mut leaf_hash,
            )
            .await?;

        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(&self.cert_store().root_deviceid_hash);
        combined[32..64].copy_from_slice(&alias_hash);
        combined[64..96].copy_from_slice(&leaf_hash);

        let mut thumbprint = [0u8; 32];
        self.hash
            .hash(HashAlgo::sha256(), &combined, &mut thumbprint)
            .await?;

        Ok(CertChainInfo {
            count: SLOT0_CERT_COUNT,
            thumbprint,
        })
    }

    async fn get_cert(
        &self,
        _io: &impl HsmIo,
        part_id: HsmPartId,
        slot_id: u8,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        let pid = u8::from(part_id);
        if slot_id != 0 {
            return Err(HsmError::InvalidArg);
        }

        // Shared certs (idx 0–2).
        if idx <= 2 {
            let src = self
                .cert_store()
                .shared_cert(idx)
                .ok_or(HsmError::InvalidArg)?;
            if let Some(buf) = cert {
                if buf.len() < src.len() {
                    return Err(HsmError::InvalidArg);
                }
                buf[..src.len()].copy_from_slice(src);
            }
            return Ok(src.len());
        }

        // Partition leaf cert (idx 3).
        if idx != 3 {
            return Err(HsmError::InvalidArg);
        }

        self.ensure_leaf_cert(pid).await?;

        let table = unsafe { &*self.part_table.get() };
        let entry = &table.entries[pid as usize];
        let len = entry.leaf_cert_len;
        if let Some(buf) = cert {
            if buf.len() < len {
                return Err(HsmError::InvalidArg);
            }
            buf[..len].copy_from_slice(&entry.leaf_cert[..len]);
        }
        Ok(len)
    }
}

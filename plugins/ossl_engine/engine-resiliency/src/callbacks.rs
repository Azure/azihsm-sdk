// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! File-backed [`PotaEndorsementCallback`] and [`MobkProviderCallback`].

use std::path::PathBuf;

use azihsm_api::HsmError;
use azihsm_api::HsmPotaEndorsementData;
use azihsm_api::HsmResult;
use azihsm_api::MobkProviderCallback;
use azihsm_api::PotaEndorsementCallback;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::Signer;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::PKey;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Minimum length of the masked OBK accepted on load. The native bridge
/// enforces `len >= OBK_SIZE` (a masked blob may be larger), so anything
/// shorter is rejected.
const OBK_LEN: usize = 48;

/// POTA endorsement that signs the device's PID public key with a
/// caller-owned P-384 private key loaded from disk. Mirrors the provider's
/// `resiliency_pota_endorse` path.
pub struct FilePotaCallback {
    priv_path: PathBuf,
    pub_path: PathBuf,
}

impl FilePotaCallback {
    /// Create an endorser that signs with the P-384 private key at `priv_path`
    /// and returns the public key at `pub_path`.
    pub fn new(priv_path: PathBuf, pub_path: PathBuf) -> Self {
        Self {
            priv_path,
            pub_path,
        }
    }
}

impl PotaEndorsementCallback for FilePotaCallback {
    /// Sign the device's PID public key with the on-disk P-384 key, returning
    /// the raw `r‖s` signature paired with the POTA public key.
    fn endorse(
        &self,
        _pota_pub_key_der: &[u8],
        pid_pub_key_der: &[u8],
        _pid_cert_chain_pem: &[u8],
    ) -> HsmResult<HsmPotaEndorsementData> {
        // The DER buffer is zeroized on drop; the public key is not secret.
        // Note: OpenSSL's parsed copy (the PKey built from this DER in
        // ecdsa_sha384_raw) is freed but not guaranteed to be cleansed.
        let priv_der = Zeroizing::new(
            crate::read_regular_hardened(&self.priv_path).map_err(crate::io_to_hsm)?,
        );
        let pub_der = crate::read_regular_hardened(&self.pub_path).map_err(crate::io_to_hsm)?;

        let point_bytes = pid_pub_key_uncompressed(pid_pub_key_der)?;
        let sig_raw = ecdsa_sha384_raw(&priv_der, &point_bytes)?;

        Ok(HsmPotaEndorsementData::new(&sig_raw, &pub_der))
    }
}

/// MOBK provider that re-reads the masked-OBK file on demand. The file must be
/// at least [`OBK_LEN`] bytes; anything shorter is rejected as invalid.
pub struct FileMobkCallback {
    path: PathBuf,
}

impl FileMobkCallback {
    /// Create a MOBK provider that reads the masked OBK from `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl MobkProviderCallback for FileMobkCallback {
    /// Read and return the masked OBK; rejects a file shorter than [`OBK_LEN`].
    fn get_mobk(&self) -> HsmResult<Vec<u8>> {
        let mut bytes = crate::read_regular_hardened(&self.path).map_err(crate::io_to_hsm)?;
        if bytes.len() < OBK_LEN {
            // Scrub the rejected buffer; it may hold a truncated real OBK.
            // The accepted buffer is returned to the SDK, whose
            // HsmOwnerBackupKeyConfig zeroizes its own copy on drop.
            bytes.zeroize();
            return Err(HsmError::InvalidArgument);
        }
        Ok(bytes)
    }
}

/// Map any OpenSSL error to [`HsmError::InternalError`]. Details land in
/// the OpenSSL error queue; this just folds the boundary cast.
fn ossl<T>(r: Result<T, openssl::error::ErrorStack>) -> HsmResult<T> {
    r.map_err(|_| HsmError::InternalError)
}

/// Decode `pid_pub_key_der` (SubjectPublicKeyInfo) and return the public
/// point as uncompressed `0x04 || X || Y` (97 bytes for P-384).
fn pid_pub_key_uncompressed(pid_pub_key_der: &[u8]) -> HsmResult<Vec<u8>> {
    let pkey = ossl(PKey::public_key_from_der(pid_pub_key_der))?;
    let ec = ossl(pkey.ec_key())?;
    let mut ctx = ossl(BigNumContext::new())?;
    ossl(
        ec.public_key()
            .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx),
    )
}

/// ECDSA-SHA384 sign `data` with the P-384 key in `priv_der` (PKCS#8 DER) and
/// return a raw `r||s` signature (96 bytes for P-384). Uses `azihsm_crypto`,
/// whose `Signer::sign_vec` emits the raw signature directly.
fn ecdsa_sha384_raw(priv_der: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    let priv_key = EccPrivateKey::from_bytes(priv_der).map_err(|_| HsmError::InternalError)?;
    let mut ecdsa = EcdsaAlgo::new(HashAlgo::sha384());
    Signer::sign_vec(&mut ecdsa, &priv_key, data).map_err(|_| HsmError::InternalError)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use openssl::bn::BigNum;
    use openssl::ec::EcGroup;
    use openssl::ec::EcKey;
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    use super::*;
    use crate::test_util::Scratch;

    /// Bytes per coordinate of a P-384 ECDSA component (raw r/s half-length).
    const P384_COORD_LEN: usize = 48;

    /// Generate a fresh P-384 key pair; return (`PKey`, priv-PKCS#8-DER,
    /// pub-DER). The private key is PKCS#8 because `ecdsa_sha384_raw` now
    /// accepts only that format.
    #[allow(clippy::type_complexity)]
    fn fresh_p384() -> (PKey<openssl::pkey::Private>, Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();
        let priv_der = pkey.private_key_to_pkcs8().unwrap();
        let pub_der = pkey.public_key_to_der().unwrap();
        (pkey, priv_der, pub_der)
    }

    #[test]
    fn pota_endorse_produces_verifiable_signature() {
        let scratch = Scratch::new("pota");
        let (pota_pkey, pota_priv, pota_pub) = fresh_p384();
        let (_, _, pid_pub) = fresh_p384();

        let priv_path = scratch.0.join("pota_priv.der");
        let pub_path = scratch.0.join("pota_pub.der");
        fs::write(&priv_path, &pota_priv).unwrap();
        fs::write(&pub_path, &pota_pub).unwrap();

        let cb = FilePotaCallback::new(priv_path, pub_path);
        let data = cb.endorse(&[], &pid_pub, &[]).unwrap();

        // Returned public key DER must match what we wrote.
        assert_eq!(data.pub_key(), pota_pub.as_slice());

        // Signature must be raw 96-byte r||s, verifiable against POTA pub.
        assert_eq!(data.signature().len(), 2 * P384_COORD_LEN);

        let r = BigNum::from_slice(&data.signature()[..P384_COORD_LEN]).unwrap();
        let s = BigNum::from_slice(&data.signature()[P384_COORD_LEN..]).unwrap();
        let ecdsa = EcdsaSig::from_private_components(r, s).unwrap();

        let point = pid_pub_key_uncompressed(&pid_pub).unwrap();
        let digest = openssl::sha::sha384(&point);

        let ec_pub = pota_pkey.ec_key().unwrap();
        assert!(ecdsa.verify(&digest, &ec_pub).unwrap(), "POTA sig invalid");
    }

    #[test]
    fn pota_missing_priv_file_is_not_found() {
        let scratch = Scratch::new("missprv");
        let (_, _, pid_pub) = fresh_p384();

        let cb = FilePotaCallback::new(
            scratch.0.join("absent_priv.der"),
            scratch.0.join("absent_pub.der"),
        );
        assert!(matches!(
            cb.endorse(&[], &pid_pub, &[]),
            Err(HsmError::NotFound)
        ));
    }

    #[test]
    fn obk_round_trip() {
        let scratch = Scratch::new("obk");
        let path = scratch.0.join("obk.bin");
        let obk = vec![0xAA; OBK_LEN];
        fs::write(&path, &obk).unwrap();

        let cb = FileMobkCallback::new(path);
        assert_eq!(cb.get_mobk().unwrap(), obk);
    }

    #[test]
    fn obk_too_short_rejected() {
        let scratch = Scratch::new("obksz");
        let path = scratch.0.join("obk.bin");
        fs::write(&path, vec![0u8; OBK_LEN - 1]).unwrap();

        let cb = FileMobkCallback::new(path);
        assert!(matches!(cb.get_mobk(), Err(HsmError::InvalidArgument)));
    }

    #[test]
    fn obk_larger_than_min_accepted() {
        // A masked OBK blob may exceed OBK_LEN; the native bridge enforces
        // `>= OBK_SIZE`, so a longer blob must pass through unchanged.
        let scratch = Scratch::new("obkbig");
        let path = scratch.0.join("obk.bin");
        let blob = vec![0xBB; OBK_LEN + 16];
        fs::write(&path, &blob).unwrap();

        let cb = FileMobkCallback::new(path);
        assert_eq!(cb.get_mobk().unwrap(), blob);
    }

    #[test]
    fn obk_missing_is_not_found() {
        let scratch = Scratch::new("obkmiss");
        let cb = FileMobkCallback::new(scratch.0.join("absent.bin"));
        assert!(matches!(cb.get_mobk(), Err(HsmError::NotFound)));
    }

    #[cfg(unix)]
    #[test]
    fn obk_via_symlink_rejected() {
        // O_NOFOLLOW must refuse a symlinked secret-material path even when
        // the link target is a valid 48-byte OBK.
        let scratch = Scratch::new("obklink");
        let real = scratch.0.join("real_obk.bin");
        fs::write(&real, vec![0xAA; OBK_LEN]).unwrap();
        let link = scratch.0.join("obk_link.bin");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let cb = FileMobkCallback::new(link);
        // O_NOFOLLOW open of a symlink fails (ELOOP), mapped to InternalError.
        assert!(matches!(cb.get_mobk(), Err(HsmError::InternalError)));
    }

    #[test]
    fn obk_directory_rejected() {
        // A directory passes open() but must fail the regular-file check,
        // surfacing as InternalError (InvalidInput is not NotFound).
        let scratch = Scratch::new("obkdir");
        let cb = FileMobkCallback::new(scratch.0.clone());
        assert!(matches!(cb.get_mobk(), Err(HsmError::InternalError)));
    }
}

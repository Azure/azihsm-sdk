// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit tests (mock) and hardware smoke tests for the engine context, split
//! out of `context.rs` for readability. Shared round-trip bodies live in
//! `round_trips`; `mock` runs them against the emulator, `hw_tests` against a
//! real device (`#[ignore]`d).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::ptr::NonNull;

use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::ffi;

use super::*;

/// Test helper: write key-material bytes to `path` with owner-only permissions
/// and the same open hardening the engine uses for secret files — create a new
/// file (`O_EXCL`, no clobber) mode 0600 and refuse a symlink at the path
/// (`O_NOFOLLOW`). Used by the round-trip tests to stage a masked-key blob.
fn write_key_material(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SECRET_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(data)
}

/// Test helper: a throwaway ENGINE for driving `keyload::load_key` in-process.
/// The loader binds returned keys to it (`EC_KEY_new_method`), so it must
/// outlive the loaded `EVP_PKEY`; the raw structural ref is returned so the
/// caller frees it with `ENGINE_free` after dropping the key.
#[allow(unsafe_code)]
#[allow(clippy::unwrap_used)]
fn new_test_engine() -> (Engine, *mut ffi::ENGINE) {
    // SAFETY: ENGINE_new returns a fresh structural ref; wrapping it in Engine
    // is sound for the test, and the caller ENGINE_free's the returned raw ref.
    unsafe {
        let raw = ffi::ENGINE_new();
        assert!(!raw.is_null(), "ENGINE_new");
        let engine = Engine::from_ptr(NonNull::new(raw).unwrap());
        // The loader binds keys via EC_KEY_new_method, which needs an EC method
        // on the engine (bind_helper does this in production).
        engine.set_default_ec_method().unwrap();
        (engine, raw)
    }
}

/// Sign `msg` (SHA-384) through `pkey` via OpenSSL's EVP interface — the same
/// path the ABI and `openssl dgst -sign` take. Exercises the loaded key's
/// `EC_KEY_METHOD` `sign_sig` (→ HSM). Shared by the mock and hardware sign tests.
#[allow(unsafe_code)]
fn evp_digest_sign_sha384(pkey: *mut ffi::EVP_PKEY, msg: &[u8]) -> Vec<u8> {
    // SAFETY: pkey is a valid EVP_PKEY; the calls follow the EVP_DigestSign
    // contract and every return code is checked.
    unsafe {
        let ctx = ffi::EVP_MD_CTX_new();
        assert!(!ctx.is_null());
        let md = ffi::EVP_sha384();
        assert_eq!(
            ffi::EVP_DigestSignInit(ctx, std::ptr::null_mut(), md, std::ptr::null_mut(), pkey),
            1,
            "EVP_DigestSignInit"
        );
        assert_eq!(
            ffi::EVP_DigestUpdate(ctx, msg.as_ptr().cast(), msg.len()),
            1,
            "EVP_DigestUpdate"
        );
        let mut siglen: usize = 0;
        assert_eq!(
            ffi::EVP_DigestSignFinal(ctx, std::ptr::null_mut(), &mut siglen),
            1,
            "EVP_DigestSignFinal (size query)"
        );
        let mut sig = vec![0u8; siglen];
        assert_eq!(
            ffi::EVP_DigestSignFinal(ctx, sig.as_mut_ptr(), &mut siglen),
            1,
            "EVP_DigestSignFinal"
        );
        sig.truncate(siglen);
        ffi::EVP_MD_CTX_free(ctx);
        sig
    }
}

/// Shared round-trip test bodies, driven against an already-opened
/// [`EngineData`] so the same flow runs on the mock (always) and on real
/// hardware (the `hw_tests` smokes). Only the `open` differs between the two.
mod round_trips {
    use azihsm_api::HsmEccCurve;
    use azihsm_api::HsmEccKeyGenAlgo;
    use azihsm_api::HsmKeyClass;
    use azihsm_api::HsmKeyCommonProps;
    use azihsm_api::HsmKeyKind;
    use azihsm_api::HsmKeyManager;
    use azihsm_api::HsmKeyPropsBuilder;
    use foreign_types::ForeignType;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::pkey::Public;
    use openssl::sign::Verifier;

    use super::*;

    /// Generate a persistent EC P-384 key pair on the open HSM and return its
    /// masked blob plus the public-key DER.
    fn generate_masked_p384(data: &EngineData) -> EngineResult<(Vec<u8>, Vec<u8>)> {
        data.with_session(|session| {
            let priv_props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Private)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(HsmEccCurve::P384)
                .is_session(false)
                .can_sign(true)
                .build()
                .map_err(|e| EngineError::wrap("build private key props", e))?;
            let pub_props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Public)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(HsmEccCurve::P384)
                .is_session(false)
                .can_verify(true)
                .build()
                .map_err(|e| EngineError::wrap("build public key props", e))?;
            let mut algo = HsmEccKeyGenAlgo::default();
            let (priv_key, _pub) =
                HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                    .map_err(|e| EngineError::wrap("generate EC key pair", e))?;
            Ok((
                priv_key
                    .masked_key_vec()
                    .map_err(|e| EngineError::wrap("export masked key", e))?,
                priv_key
                    .pub_key_der_vec()
                    .map_err(|e| EngineError::wrap("read public key DER", e))?,
            ))
        })
    }

    /// A transient masked-blob path for a round trip (removed by the caller).
    fn blob_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("engine-roundtrip-{tag}-{}.bin", std::process::id()))
    }

    /// Generate a key on `data`'s HSM, load it back through the engine, and
    /// verify the returned public key matches. Backend-agnostic: the caller
    /// opens `data` against the mock or a real device.
    #[allow(unsafe_code)]
    pub(super) fn run_load(data: &EngineData) -> EngineResult<()> {
        let (masked, expected_pub_der) = generate_masked_p384(data)?;
        let path = blob_path("load");
        let _ = std::fs::remove_file(&path);
        write_key_material(&path, &masked)
            .map_err(|e| EngineError::wrap(format!("write masked blob {}", path.display()), e))?;

        let (engine, engine_raw) = new_test_engine();
        let uri = format!("azihsm://{};type=ec", path.display());
        let raw = crate::keyload::load_key(&engine, data, &uri)?;
        assert!(!raw.is_null(), "load_key returned a NULL EVP_PKEY");

        // SAFETY: raw is an owning *mut EVP_PKEY returned by load_key.
        let loaded: PKey<Public> = unsafe { PKey::from_ptr(raw.cast()) };
        let loaded_der = loaded
            .public_key_to_der()
            .map_err(|e| EngineError::wrap("encode loaded public key", e))?;
        assert_eq!(loaded_der, expected_pub_der, "loaded public key mismatch");
        drop(loaded);

        // SAFETY: engine_raw is the ENGINE_new ref from new_test_engine.
        unsafe { ffi::ENGINE_free(engine_raw) };
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    /// Generate a key on `data`'s HSM, load it back through the engine, sign a
    /// digest through it (HSM `sign_sig` via `EVP_DigestSign*`), and verify the
    /// signature against the public half in software. Backend-agnostic.
    #[allow(unsafe_code)]
    pub(super) fn run_sign(data: &EngineData) -> EngineResult<()> {
        let (masked, expected_pub_der) = generate_masked_p384(data)?;
        let path = blob_path("sign");
        let _ = std::fs::remove_file(&path);
        write_key_material(&path, &masked)
            .map_err(|e| EngineError::wrap(format!("write masked blob {}", path.display()), e))?;

        let (engine, engine_raw) = new_test_engine();
        let uri = format!("azihsm://{};type=ec", path.display());
        let raw = crate::keyload::load_key(&engine, data, &uri)?;
        assert!(!raw.is_null(), "load_key returned a NULL EVP_PKEY");

        let msg = b"engine ecdsa signing over the EVP/ABI path";
        let sig = evp_digest_sign_sha384(raw, msg);
        assert!(!sig.is_empty(), "engine produced an empty signature");
        // SAFETY: raw is an owning *mut EVP_PKEY returned by load_key.
        let loaded: PKey<Public> = unsafe { PKey::from_ptr(raw.cast()) };

        let pubkey = PKey::public_key_from_der(&expected_pub_der)
            .map_err(|e| EngineError::wrap("parse public key", e))?;
        let mut verifier = Verifier::new(MessageDigest::sha384(), &pubkey)
            .map_err(|e| EngineError::wrap("init verifier", e))?;
        verifier
            .update(msg)
            .map_err(|e| EngineError::wrap("verifier update", e))?;
        assert!(
            verifier
                .verify(&sig)
                .map_err(|e| EngineError::wrap("verify", e))?,
            "engine ECDSA signature must verify against the public key"
        );
        drop(loaded);

        // SAFETY: engine_raw is the ENGINE_new ref from new_test_engine.
        unsafe { ffi::ENGINE_free(engine_raw) };
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

#[cfg(all(test, feature = "mock"))]
mod mock {
    #![allow(clippy::unwrap_used)]

    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use openssl::ec::EcGroup;
    use openssl::ec::EcKey;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use serial_test::serial;

    use super::*;

    /// Shared per-process MOBK path. The mock device's BK3 is global to the
    /// process: the first test establishes it (plaintext OBK) and the engine
    /// persists the MOBK here; later tests re-init from that MOBK (re-running
    /// init_bk3 fails). Shared across tests so the second open sees the first
    /// open's persisted MOBK.
    fn shared_mobk_path() -> PathBuf {
        std::env::temp_dir().join(format!("engine-test-mobk-{}.bin", std::process::id()))
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("engine-ctx-{tag}-{pid}-{n}"));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Materialize a fresh P-384 key pair on disk + a 48-byte OBK, return
    /// settings pointing at them with resiliency enabled.
    fn caller_settings(scratch: &Scratch) -> ResiliencySettings {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();
        // PKCS#8: FilePotaCallback signs via azihsm_crypto, which accepts only
        // that private-key format.
        let priv_der = pkey.private_key_to_pkcs8().unwrap();
        let pub_der = pkey.public_key_to_der().unwrap();

        let priv_path = scratch.0.join("pota_priv.der");
        let pub_path = scratch.0.join("pota_pub.der");
        let obk_path = scratch.0.join("obk.bin");
        fs::write(&priv_path, &priv_der).unwrap();
        fs::write(&pub_path, &pub_der).unwrap();
        fs::write(&obk_path, vec![0u8; 48]).unwrap();

        ResiliencySettings {
            enabled: true,
            storage_dir: scratch.0.join("res"),
            obk_source: HsmOwnerBackupKeySource::Caller,
            obk_path,
            mobk_path: shared_mobk_path(),
            pota_source: HsmPotaEndorsementSource::Caller,
            pota_priv_path: Some(priv_path),
            pota_pub_path: Some(pub_path),
        }
    }

    // `#[serial]`: these share the process-global mock device (BK3 state),
    // so they must not run concurrently.
    #[test]
    #[serial]
    fn open_hsm_with_resiliency_succeeds() {
        let scratch = Scratch::new("open");
        // The storage dir is created by the open path (setup_storage_dir) with
        // mode 0700; pre-creating it here would inherit the umask and could be
        // rejected, so leave it to the open path to stay umask-independent.
        let settings = caller_settings(&scratch);
        let creds = HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN);

        let data = EngineData::new();
        assert!(!data.is_hsm_open());
        data.open_hsm_with(settings, creds).unwrap();
        assert!(data.is_hsm_open());
    }

    /// Full engine key-load round trip: generate an EC key + its masked blob in
    /// the HSM, write the blob to disk, load it back through the engine's
    /// `load_private_key` path, and verify the returned EVP_PKEY's public key
    /// matches. Dropping the EVP_PKEY (no ex_data free callback) and then the
    /// EngineData (which deletes the loaded key from the HSM) must not crash.
    #[test]
    #[serial]
    fn load_ec_key_round_trips_through_engine() {
        let scratch = Scratch::new("load");
        // Leave the `res` storage dir to the open path (setup_storage_dir),
        // which creates it mode 0700; pre-creating it here would inherit the
        // umask and be rejected as insecure (see open_hsm_with_resiliency_succeeds).
        let data = EngineData::new();
        data.open_hsm_with(
            caller_settings(&scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();
        round_trips::run_load(&data).unwrap();
    }

    // A signature produced through a loaded key (HSM sign via our EC_KEY_METHOD,
    // reached the same way the ABI and CLI do — EVP_DigestSign*) must verify
    // against the key's public half in software.
    #[test]
    #[serial]
    fn sign_through_loaded_key_verifies() {
        let scratch = Scratch::new("sign");
        let data = EngineData::new();
        data.open_hsm_with(
            caller_settings(&scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();
        round_trips::run_sign(&data).unwrap();
    }

    #[test]
    #[serial]
    fn open_hsm_is_idempotent() {
        let scratch = Scratch::new("idem");
        // See open_hsm_with_resiliency_succeeds: let the open path create the
        // storage dir at 0700 rather than depending on the umask here.
        let data = EngineData::new();
        let creds = HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN);

        data.open_hsm_with(
            caller_settings(&scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();
        // Second call must not panic, must not re-open, must succeed.
        data.open_hsm_with(caller_settings(&scratch), creds)
            .unwrap();
        assert!(data.is_hsm_open());
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode_16("abcd", "X").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        let s = "g".repeat(32);
        assert!(hex_decode_16(&s, "X").is_err());
    }

    #[test]
    fn hex_decode_round_trip() {
        let s = "000102030405060708090a0b0c0d0e0f";
        assert_eq!(
            hex_decode_16(s, "X").unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    // An unset credential with no default must be a hard error, not a silent
    // fallback. (In production builds cred_field is called with None.)
    #[test]
    fn cred_field_missing_without_default_errors() {
        let r = cred_field("AZIHSM_CRED_FIELD_DEFINITELY_UNSET_XYZ", None);
        assert!(matches!(r, Err(EngineError::Other(_))));
    }

    #[test]
    fn cred_field_missing_with_default_uses_default() {
        let def = [7u8; 16];
        let got = cred_field("AZIHSM_CRED_FIELD_DEFINITELY_UNSET_XYZ", Some(def)).unwrap();
        assert_eq!(got, def);
    }
}

/// Hardware smoke test. Drives the full device open (`open_hsm_from_env`:
/// partition open → init → session) using the ambient `AZIHSM_*` environment,
/// so a real HSM host can validate a configuration end to end — e.g. the TPM
/// OBK/POTA sources, which the mock cannot exercise.
///
/// Compiled only in non-mock builds and `#[ignore]`d, so it never runs in the
/// normal (mock) CI cell — invoke it explicitly on a provisioned host:
///
/// ```text
/// export AZIHSM_CREDENTIALS_ID=<32 hex>  AZIHSM_CREDENTIALS_PIN=<32 hex>
/// export AZIHSM_RESILIENCY_ENABLED=1        # turns on resiliency persistence (storage dir + MOBK/POTA callbacks)
/// export AZIHSM_OBK_SOURCE=tpm  AZIHSM_POTA_SOURCE=tpm  # source selection applies regardless of the flag above
/// # Storage dir must already exist, be mode 0700, and be owned by you. The
/// # default is /var/lib/azihsm/resiliency; create it once (override with
/// # AZIHSM_RESILIENCY_STORAGE_DIR to use e.g. a path under $HOME):
/// sudo install -d -m 700 -o "$USER" /var/lib/azihsm/resiliency
/// umask 0077
/// cargo test -p azihsm_ossl_engine --features engine open_from_env_smoke -- --ignored --nocapture
/// ```
#[cfg(all(test, not(feature = "mock")))]
mod hw_tests {
    use super::*;

    #[test]
    #[ignore = "requires a provisioned HSM host; configure AZIHSM_* env first"]
    fn open_from_env_smoke() -> EngineResult<()> {
        let data = EngineData::new();
        data.open_hsm_from_env()?;
        assert!(
            data.is_hsm_open(),
            "HSM should be open after open_hsm_from_env"
        );
        Ok(())
    }

    /// Hardware key-loading round trip against a real device — the same flow
    /// `mock::load_ec_key_round_trips_through_engine` runs on the mock (see
    /// [`super::round_trips::run_load`]).
    ///
    /// Same env setup as `open_from_env_smoke` (configure `AZIHSM_*` first):
    ///
    /// ```text
    /// cargo test -p azihsm_ossl_engine --features engine load_ec_key_from_env_smoke -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a provisioned HSM host; configure AZIHSM_* env first"]
    fn load_ec_key_from_env_smoke() -> EngineResult<()> {
        let data = EngineData::new();
        data.open_hsm_from_env()?;
        round_trips::run_load(&data)
    }

    /// Hardware ECDSA signing round trip against a real device — the same flow
    /// `mock::sign_through_loaded_key_verifies` runs on the mock (see
    /// [`super::round_trips::run_sign`]). Proves the device produces a valid
    /// ECDSA signature.
    ///
    /// Same env setup as `open_from_env_smoke` (configure `AZIHSM_*` first):
    ///
    /// ```text
    /// cargo test -p azihsm_ossl_engine --features engine sign_ec_key_from_env_smoke -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a provisioned HSM host; configure AZIHSM_* env first"]
    fn sign_ec_key_from_env_smoke() -> EngineResult<()> {
        let data = EngineData::new();
        data.open_hsm_from_env()?;
        round_trips::run_sign(&data)
    }
}

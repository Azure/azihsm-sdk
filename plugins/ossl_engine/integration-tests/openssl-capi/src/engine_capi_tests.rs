// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ABI integration test for the OpenSSL 1.1.x engine.
//!
//! Drives the real C API: `ENGINE_by_id("dynamic")` + `SO_PATH`/`ID`/`LOAD`,
//! `ENGINE_init`, then `ENGINE_load_private_key` on an `azihsm://` URI, and
//! confirms a usable EC public key comes back — the load path the in-crate unit
//! tests (which call `keyload::load_key` directly) bypass.
//!
//! Requires `ENGINE_SO` (the engine `.so`) and `MASKED_KEYGEN` (the helper that
//! stages the blob), set by `xtask integration-tests` / the engine matrix. The
//! blob is staged out-of-process, sharing the keymat set up here so it unmasks.

#![cfg(feature = "integration")]
#![allow(clippy::unwrap_used)]

use std::ffi::CString;
use std::path::PathBuf;
use std::process::Command;

use azihsm_ossl_engine_sys as ffi;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use serial_test::serial;

/// Write owner-only (0600) key material.
fn write_secret(path: &std::path::Path, data: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(data).unwrap();
}

/// Provision the shared keymat and export the `AZIHSM_*` environment both the
/// generator and the engine read, returning the keymat dir.
#[allow(unsafe_code)]
fn setup_keymat() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("engine-capi-keymat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let res = dir.join("res");
    std::fs::create_dir(&res).unwrap();
    std::fs::set_permissions(&res, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();

    // OBK: 48 random bytes (= BK3). Owner-only — it seeds HSM key derivation.
    let mut obk = [0u8; 48];
    openssl::rand::rand_bytes(&mut obk).unwrap();
    write_secret(&dir.join("obk.bin"), &obk);

    // Caller POTA P-384 keypair, PKCS#8 priv + SPKI pub (what azihsm_crypto wants).
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    write_secret(
        &dir.join("pota_priv.der"),
        &pkey.private_key_to_pkcs8().unwrap(),
    );
    std::fs::write(dir.join("pota_pub.der"), pkey.public_key_to_der().unwrap()).unwrap();

    let set = |k: &str, v: String| {
        // SAFETY: single-threaded test setup before any HSM/engine call.
        unsafe { std::env::set_var(k, v) };
    };
    set("AZIHSM_RESILIENCY_ENABLED", "1".into());
    set("AZIHSM_RESILIENCY_STORAGE_DIR", res.display().to_string());
    set("AZIHSM_OBK_SOURCE", "caller".into());
    set("AZIHSM_OBK_PATH", dir.join("obk.bin").display().to_string());
    set(
        "AZIHSM_MOBK_PATH",
        dir.join("mobk.bin").display().to_string(),
    );
    set("AZIHSM_POTA_SOURCE", "caller".into());
    set(
        "AZIHSM_POTA_PRIVATE_KEY_PATH",
        dir.join("pota_priv.der").display().to_string(),
    );
    set(
        "AZIHSM_POTA_PUBLIC_KEY_PATH",
        dir.join("pota_pub.der").display().to_string(),
    );
    dir
}

/// Load `key_id` through a dynamically loaded azihsm engine, returning the owning
/// `*mut EVP_PKEY`. The engine's own functional ref (taken when the loader builds
/// the key via `EC_KEY_new_method`) keeps it alive after we finish/free our
/// handle, so the returned key stays valid.
#[allow(unsafe_code)]
fn load_via_engine(engine_so: &str, key_id: &str) -> *mut ffi::EVP_PKEY {
    let dynamic = CString::new("dynamic").unwrap();
    let so_path = CString::new("SO_PATH").unwrap();
    let so_val = CString::new(engine_so).unwrap();
    let id_cmd = CString::new("ID").unwrap();
    let id_val = CString::new("azihsm").unwrap();
    let load_cmd = CString::new("LOAD").unwrap();
    let key = CString::new(key_id).unwrap();

    // SAFETY: standard dynamic-engine load sequence; every return code is checked.
    unsafe {
        // The built-in "dynamic" engine is reachable via ENGINE_by_id in 1.1.x.
        let e = ffi::ENGINE_by_id(dynamic.as_ptr());
        assert!(!e.is_null(), "ENGINE_by_id(dynamic)");
        assert_eq!(
            ffi::ENGINE_ctrl_cmd_string(e, so_path.as_ptr(), so_val.as_ptr(), 0),
            1,
            "SO_PATH"
        );
        assert_eq!(
            ffi::ENGINE_ctrl_cmd_string(e, id_cmd.as_ptr(), id_val.as_ptr(), 0),
            1,
            "ID"
        );
        assert_eq!(
            ffi::ENGINE_ctrl_cmd_string(e, load_cmd.as_ptr(), std::ptr::null(), 0),
            1,
            "LOAD"
        );
        assert_eq!(ffi::ENGINE_init(e), 1, "ENGINE_init");
        let pkey = ffi::ENGINE_load_private_key(
            e,
            key.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        // Release our handle; the key holds the engine alive via its own ref.
        ffi::ENGINE_finish(e);
        ffi::ENGINE_free(e);
        pkey
    }
}

#[test]
#[serial]
#[allow(unsafe_code)]
fn load_ec_key_via_engine_capi() {
    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");
    let keygen = std::env::var("MASKED_KEYGEN").expect("MASKED_KEYGEN must point to the helper");

    let dir = setup_keymat();
    let blob = dir.join("ec_key.bin");

    // Stage the masked blob out-of-process (shares the keymat set above).
    let status = Command::new(&keygen).arg(&blob).status().unwrap();
    assert!(status.success(), "masked-keygen failed: {status}");

    let uri = format!("azihsm://{};type=ec", blob.display());
    let raw = load_via_engine(&engine_so, &uri);
    assert!(!raw.is_null(), "ENGINE_load_private_key returned NULL");

    // Confirm a usable EC public key came back through the C API, then free the
    // EVP_PKEY (which releases the engine ref the loaded key holds).
    // SAFETY: raw is a valid owning *mut EVP_PKEY from ENGINE_load_private_key.
    unsafe {
        let ec = ffi::EVP_PKEY_get0_EC_KEY(raw);
        assert!(!ec.is_null(), "loaded EVP_PKEY has no EC_KEY");
        assert!(
            !ffi::EC_KEY_get0_public_key(ec).is_null(),
            "loaded key carries no public point"
        );
        ffi::EVP_PKEY_free(raw);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

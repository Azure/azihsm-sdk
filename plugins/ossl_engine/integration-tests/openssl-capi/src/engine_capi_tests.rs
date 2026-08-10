// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ABI integration tests for the OpenSSL 1.1.x engine.
//!
//! Drive the real C API: `ENGINE_by_id("dynamic")` + `SO_PATH`/`ID`/`LOAD`,
//! `ENGINE_init`, then `ENGINE_load_private_key` on an `azihsm://` URI — the
//! load path the in-crate unit tests (which call `keyload::load_key` directly)
//! bypass — and sign through the loaded key via `EVP_DigestSign*` (verifying in
//! software with the public half on the same `EVP_PKEY`).
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
    use std::os::unix::fs::DirBuilderExt;

    // Owner-only (0700): the dir holds secret key material.
    let dir = std::env::temp_dir().join(format!("engine-capi-keymat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mkdir = |p: &std::path::Path| {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)
            .unwrap();
    };
    mkdir(&dir);
    let res = dir.join("res");
    mkdir(&res);

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

/// Stage a masked EC blob out-of-process (sharing the keymat set up by
/// [`setup_keymat`]) and return its `azihsm://` URI.
fn stage_masked_blob(keygen: &str, dir: &std::path::Path, name: &str) -> String {
    let blob = dir.join(name);
    let status = Command::new(keygen).arg(&blob).status().unwrap();
    assert!(status.success(), "masked-keygen failed: {status}");
    format!("azihsm://{};type=ec", blob.display())
}

#[test]
#[serial]
#[allow(unsafe_code)]
fn load_ec_key_via_engine_capi() {
    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");
    let keygen = std::env::var("MASKED_KEYGEN").expect("MASKED_KEYGEN must point to the helper");

    let dir = setup_keymat();
    let uri = stage_masked_blob(&keygen, &dir, "ec_key.bin");
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

/// Sign `msg` (SHA-384) through `pkey` via `EVP_DigestSign*` — the ABI path an
/// application takes — exercising the loaded key's `sign_sig` (→ HSM).
#[allow(unsafe_code)]
fn evp_digest_sign_sha384(pkey: *mut ffi::EVP_PKEY, msg: &[u8]) -> Vec<u8> {
    // SAFETY: pkey is a valid EVP_PKEY; the calls follow the EVP_DigestSign
    // contract and every return code is checked.
    unsafe {
        let ctx = ffi::EVP_MD_CTX_new();
        assert!(!ctx.is_null());
        assert_eq!(
            ffi::EVP_DigestSignInit(
                ctx,
                std::ptr::null_mut(),
                ffi::EVP_sha384(),
                std::ptr::null_mut(),
                pkey,
            ),
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
        let rc = ffi::EVP_DigestSignFinal(ctx, sig.as_mut_ptr(), &mut siglen);
        assert_eq!(
            rc,
            1,
            "EVP_DigestSignFinal: {}",
            openssl::error::ErrorStack::get()
        );
        sig.truncate(siglen);
        ffi::EVP_MD_CTX_free(ctx);
        sig
    }
}

/// Verify `sig` over `msg` (SHA-384) with `pkey` via `EVP_DigestVerify*`.
/// Software verify: the loaded key's method keeps OpenSSL's default verify and
/// uses the public half on the `EVP_PKEY`. Returns the final return code.
#[allow(unsafe_code)]
fn evp_digest_verify_sha384(pkey: *mut ffi::EVP_PKEY, msg: &[u8], sig: &[u8]) -> i32 {
    // SAFETY: pkey is a valid EVP_PKEY and sig a valid buffer; the calls follow
    // the EVP_DigestVerify contract and setup return codes are checked.
    unsafe {
        let ctx = ffi::EVP_MD_CTX_new();
        assert!(!ctx.is_null());
        assert_eq!(
            ffi::EVP_DigestVerifyInit(
                ctx,
                std::ptr::null_mut(),
                ffi::EVP_sha384(),
                std::ptr::null_mut(),
                pkey,
            ),
            1,
            "EVP_DigestVerifyInit"
        );
        assert_eq!(
            ffi::EVP_DigestUpdate(ctx, msg.as_ptr().cast(), msg.len()),
            1,
            "EVP_DigestUpdate"
        );
        let rc = ffi::EVP_DigestVerifyFinal(ctx, sig.as_ptr(), sig.len());
        ffi::EVP_MD_CTX_free(ctx);
        // A failed verify pushes to the error queue; clear it so it can't leak
        // into a later assertion's context.
        ffi::ERR_clear_error();
        rc
    }
}

#[test]
#[serial]
#[allow(unsafe_code)]
fn sign_ec_key_via_engine_capi() {
    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");
    let keygen = std::env::var("MASKED_KEYGEN").expect("MASKED_KEYGEN must point to the helper");

    let dir = setup_keymat();
    let uri = stage_masked_blob(&keygen, &dir, "ec_sign_key.bin");
    let raw = load_via_engine(&engine_so, &uri);
    assert!(!raw.is_null(), "ENGINE_load_private_key returned NULL");

    // Sign through the loaded key. Our own ENGINE handle was already released
    // by load_via_engine (ENGINE_finish + ENGINE_free), so this also proves the
    // key's engine reference — taken by EC_KEY_new_method and preserved by the
    // engine-wide EC method — keeps the engine and the HSM key alive: a per-key
    // EC_KEY_set_method would drop that reference and this sign would fail.
    let msg = b"engine ecdsa signing over the capi path";
    let sig = evp_digest_sign_sha384(raw, msg);
    assert!(!sig.is_empty(), "engine produced an empty signature");

    // Verify in software with the public half on the same EVP_PKEY: proves the
    // HSM signed the right digest with the matching private key.
    assert_eq!(
        evp_digest_verify_sha384(raw, msg, &sig),
        1,
        "engine ECDSA signature must verify against the public key"
    );

    // A tampered message must not verify.
    let tampered = b"engine ecdsa signing over the capi path?";
    assert_eq!(
        evp_digest_verify_sha384(raw, tampered, &sig),
        0,
        "tampered message unexpectedly verified"
    );

    // SAFETY: raw is the owning EVP_PKEY from ENGINE_load_private_key.
    unsafe { ffi::EVP_PKEY_free(raw) };

    let _ = std::fs::remove_dir_all(&dir);
}

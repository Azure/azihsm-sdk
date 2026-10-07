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
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::sign::RsaPssSaltlen;
use openssl::sign::Verifier;
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

/// Dynamically load the azihsm engine and return the initialized `*mut ENGINE`
/// (release with `ENGINE_finish` + `ENGINE_free`).
#[allow(unsafe_code)]
fn open_dynamic_engine(engine_so: &str) -> *mut ffi::ENGINE {
    let dynamic = CString::new("dynamic").unwrap();
    let so_path = CString::new("SO_PATH").unwrap();
    let so_val = CString::new(engine_so).unwrap();
    let id_cmd = CString::new("ID").unwrap();
    let id_val = CString::new("azihsm").unwrap();
    let load_cmd = CString::new("LOAD").unwrap();

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
        let load_rc = ffi::ENGINE_ctrl_cmd_string(e, load_cmd.as_ptr(), std::ptr::null(), 0);
        assert_eq!(
            load_rc,
            1,
            "LOAD failed: {}",
            openssl::error::ErrorStack::get()
        );
        assert_eq!(ffi::ENGINE_init(e), 1, "ENGINE_init");
        e
    }
}

/// Load `key_id` through a dynamically loaded azihsm engine, returning the owning
/// `*mut EVP_PKEY`. The engine's own functional ref (taken when the loader builds
/// the key via `EC_KEY_new_method`) keeps it alive after we finish/free our
/// handle, so the returned key stays valid.
#[allow(unsafe_code)]
fn load_via_engine(engine_so: &str, key_id: &str) -> *mut ffi::EVP_PKEY {
    let key = CString::new(key_id).unwrap();
    let e = open_dynamic_engine(engine_so);
    // SAFETY: e is the initialized ENGINE from open_dynamic_engine; the key
    // holds the engine alive via its own ref after we release our handle.
    unsafe {
        let pkey = ffi::ENGINE_load_private_key(
            e,
            key.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
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

/// Generate a key on the HSM through the real C keygen ABI —
/// `EVP_PKEY_CTX_new_id(EVP_PKEY_EC, engine)` + `-pkeyopt`-equivalent control
/// strings + `EVP_PKEY_keygen` — with every engine handle released before the
/// key is used, pinning the lifetime guarantees. The generated key signs via
/// the HSM and verifies in software; the masked blob lands on disk.
#[test]
#[serial]
#[allow(unsafe_code)]
fn keygen_ec_key_via_engine_capi() {
    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");

    let dir = setup_keymat();
    let blob = dir.join("created_ec_key.bin");

    let curve_key = CString::new("ec_paramgen_curve").unwrap();
    let curve_val = CString::new("P-384").unwrap();
    let masked_key = CString::new("azihsm.masked_key").unwrap();
    let blob_arg = CString::new(blob.to_str().unwrap()).unwrap();
    let session_key = CString::new("azihsm.session").unwrap();
    let session_val = CString::new("false").unwrap();
    let usage_key = CString::new("azihsm.key_usage").unwrap();
    let usage_val = CString::new("digitalSignature").unwrap();

    let e = open_dynamic_engine(&engine_so);
    // SAFETY: standard EVP_PKEY keygen sequence; every return code is checked.
    // Our engine handle is deliberately released right after the ctx is
    // created: int_ctx_new (pmeth_lib.c) calls ENGINE_init(e) and the ctx
    // keeps that functional reference until EVP_PKEY_CTX_free, so the early
    // release pins exactly that guarantee. The ctx is then freed before the
    // key is used — the generated key alone must keep the engine and HSM
    // state alive, exactly like a loaded key.
    let raw = unsafe {
        let ctx = ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_EC as std::ffi::c_int, e);
        assert!(!ctx.is_null(), "EVP_PKEY_CTX_new_id(EC, engine)");
        ffi::ENGINE_finish(e);
        ffi::ENGINE_free(e);
        assert_eq!(ffi::EVP_PKEY_keygen_init(ctx), 1, "EVP_PKEY_keygen_init");
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, curve_key.as_ptr(), curve_val.as_ptr()),
            1,
            "ec_paramgen_curve"
        );
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, masked_key.as_ptr(), blob_arg.as_ptr()),
            1,
            "azihsm.masked_key"
        );
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, session_key.as_ptr(), session_val.as_ptr()),
            1,
            "azihsm.session"
        );
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, usage_key.as_ptr(), usage_val.as_ptr()),
            1,
            "azihsm.key_usage"
        );
        let mut pkey = std::ptr::null_mut();
        assert_eq!(ffi::EVP_PKEY_keygen(ctx, &mut pkey), 1, "EVP_PKEY_keygen");
        ffi::EVP_PKEY_CTX_free(ctx);
        pkey
    };
    assert!(!raw.is_null(), "keygen returned a NULL EVP_PKEY");
    assert!(
        blob.is_file() && std::fs::metadata(&blob).unwrap().len() > 0,
        "masked blob not written"
    );

    // Sign through the generated key (HSM sign_sig) and verify in software
    // with the public half on the same EVP_PKEY; a tampered message must fail.
    let msg = b"engine ecdsa signing with a capi-generated key";
    let sig = evp_digest_sign_sha384(raw, msg);
    assert!(!sig.is_empty(), "engine produced an empty signature");
    assert_eq!(
        evp_digest_verify_sha384(raw, msg, &sig),
        1,
        "generated key's signature must verify"
    );
    let tampered = b"engine ecdsa signing with a capi-generated key?";
    assert_eq!(
        evp_digest_verify_sha384(raw, tampered, &sig),
        0,
        "tampered message unexpectedly verified"
    );

    // SAFETY: raw is the owning EVP_PKEY from EVP_PKEY_keygen.
    unsafe { ffi::EVP_PKEY_free(raw) };

    let _ = std::fs::remove_dir_all(&dir);
}

/// ECDH through the real C ABI for one curve: generate a keyAgreement key on
/// `e`, then derive against a software peer through contexts created WITHOUT
/// an engine handle — the ameth-bound key must resolve the engine on its own
/// (the early-release lifetime pin lives in the keygen test). Buffer and
/// output_file modes.
#[allow(unsafe_code)]
fn capi_derive_roundtrip(e: *mut ffi::ENGINE, dir: &std::path::Path, curve: &str) {
    let tag = curve.to_lowercase().replace('-', "");
    let blob = dir.join(format!("agree_ec_key_{tag}.bin"));
    let out = dir.join(format!("derived_secret_{tag}.bin"));

    let cstr = |s: &str| CString::new(s).unwrap();
    let curve_key = cstr("ec_paramgen_curve");
    let curve_val = cstr(curve);
    let masked_key = cstr("azihsm.masked_key");
    let blob_arg = cstr(blob.to_str().unwrap());
    let usage_key = cstr("azihsm.key_usage");
    let usage_val = cstr("keyAgreement");
    let out_key = cstr("output_file");
    let out_val = cstr(out.to_str().unwrap());

    // SAFETY: standard keygen + derive ABI sequences; all return codes
    // checked, every ctx freed.
    unsafe {
        // keyAgreement keygen on the caller's engine handle.
        let ctx = ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_EC as std::ffi::c_int, e);
        assert!(!ctx.is_null(), "EVP_PKEY_CTX_new_id(EC, engine)");
        assert_eq!(ffi::EVP_PKEY_keygen_init(ctx), 1);
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, curve_key.as_ptr(), curve_val.as_ptr()),
            1
        );
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, masked_key.as_ptr(), blob_arg.as_ptr()),
            1
        );
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, usage_key.as_ptr(), usage_val.as_ptr()),
            1
        );
        let mut pkey = std::ptr::null_mut();
        assert_eq!(
            ffi::EVP_PKEY_keygen(ctx, &mut pkey),
            1,
            "EVP_PKEY_keygen {curve}"
        );
        ffi::EVP_PKEY_CTX_free(ctx);
        assert!(!pkey.is_null());
        assert!(
            blob.is_file() && std::fs::metadata(&blob).unwrap().len() > 0,
            "masked blob not written for {curve}"
        );

        // Software peer on the same curve via the built-in keygen.
        let pctx =
            ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_EC as std::ffi::c_int, std::ptr::null_mut());
        assert!(!pctx.is_null());
        assert_eq!(ffi::EVP_PKEY_keygen_init(pctx), 1);
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(pctx, curve_key.as_ptr(), curve_val.as_ptr()),
            1
        );
        let mut peer = std::ptr::null_mut();
        assert_eq!(ffi::EVP_PKEY_keygen(pctx, &mut peer), 1, "peer keygen");
        ffi::EVP_PKEY_CTX_free(pctx);

        // Buffer mode.
        let dctx = ffi::EVP_PKEY_CTX_new(pkey, std::ptr::null_mut());
        assert!(!dctx.is_null(), "EVP_PKEY_CTX_new(pkey, NULL)");
        assert_eq!(ffi::EVP_PKEY_derive_init(dctx), 1);
        assert_eq!(ffi::EVP_PKEY_derive_set_peer(dctx, peer), 1);
        let mut len = 0usize;
        assert_eq!(
            ffi::EVP_PKEY_derive(dctx, std::ptr::null_mut(), &mut len),
            1,
            "derive size query"
        );
        assert_eq!(len, 8192, "size query must report the blob max for {curve}");
        let mut buf = vec![0u8; len];
        assert_eq!(ffi::EVP_PKEY_derive(dctx, buf.as_mut_ptr(), &mut len), 1);
        assert!(len > 0, "empty masked secret for {curve}");
        ffi::EVP_PKEY_CTX_free(dctx);

        // output_file mode: blob to disk, no bytes returned.
        let fctx = ffi::EVP_PKEY_CTX_new(pkey, std::ptr::null_mut());
        assert!(!fctx.is_null());
        assert_eq!(ffi::EVP_PKEY_derive_init(fctx), 1);
        assert_eq!(ffi::EVP_PKEY_derive_set_peer(fctx, peer), 1);
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(fctx, out_key.as_ptr(), out_val.as_ptr()),
            1,
            "output_file"
        );
        let mut n = 0usize;
        assert_eq!(ffi::EVP_PKEY_derive(fctx, std::ptr::null_mut(), &mut n), 1);
        assert_eq!(n, 1, "file-mode size query must report 1");
        let mut one = [0u8; 1];
        assert_eq!(ffi::EVP_PKEY_derive(fctx, one.as_mut_ptr(), &mut n), 1);
        assert_eq!(n, 0, "file mode must return no bytes");
        assert!(
            out.is_file() && std::fs::metadata(&out).unwrap().len() > 0,
            "derived blob not written for {curve}"
        );
        ffi::EVP_PKEY_CTX_free(fctx);

        ffi::EVP_PKEY_free(peer);
        ffi::EVP_PKEY_free(pkey);
    }
}

/// Chained ECDH → HKDF through the C ABI: derive a masked shared secret,
/// then run a NID_hkdf derive on the engine with the blob as IKM, in buffer
/// and output_file modes.
#[test]
#[serial]
#[allow(unsafe_code)]
fn hkdf_via_engine_capi() {
    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");
    let dir = setup_keymat();
    let blob = dir.join("hkdf_agree_ec.bin");
    let ikm = dir.join("hkdf_ikm.bin");
    let out = dir.join("hkdf_derived.bin");

    let cstr = |s: &str| CString::new(s).unwrap();
    let e = open_dynamic_engine(&engine_so);
    // SAFETY: standard keygen/derive/HKDF ABI sequences; all return codes
    // checked, every ctx freed.
    unsafe {
        // keyAgreement keygen + software peer + ECDH (buffer mode).
        let curve_key = cstr("ec_paramgen_curve");
        let curve_val = cstr("P-384");
        let ctx = ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_EC as std::ffi::c_int, e);
        assert!(!ctx.is_null());
        assert_eq!(ffi::EVP_PKEY_keygen_init(ctx), 1);
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, curve_key.as_ptr(), curve_val.as_ptr()),
            1
        );
        let masked_key = cstr("azihsm.masked_key");
        let blob_arg = cstr(blob.to_str().unwrap());
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, masked_key.as_ptr(), blob_arg.as_ptr()),
            1
        );
        let usage_key = cstr("azihsm.key_usage");
        let usage_val = cstr("keyAgreement");
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(ctx, usage_key.as_ptr(), usage_val.as_ptr()),
            1
        );
        let mut pkey = std::ptr::null_mut();
        assert_eq!(ffi::EVP_PKEY_keygen(ctx, &mut pkey), 1, "EVP_PKEY_keygen");
        ffi::EVP_PKEY_CTX_free(ctx);

        let pctx =
            ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_EC as std::ffi::c_int, std::ptr::null_mut());
        assert!(!pctx.is_null());
        assert_eq!(ffi::EVP_PKEY_keygen_init(pctx), 1);
        assert_eq!(
            ffi::EVP_PKEY_CTX_ctrl_str(pctx, curve_key.as_ptr(), curve_val.as_ptr()),
            1
        );
        let mut peer = std::ptr::null_mut();
        assert_eq!(ffi::EVP_PKEY_keygen(pctx, &mut peer), 1, "peer keygen");
        ffi::EVP_PKEY_CTX_free(pctx);

        let dctx = ffi::EVP_PKEY_CTX_new(pkey, std::ptr::null_mut());
        assert!(!dctx.is_null());
        assert_eq!(ffi::EVP_PKEY_derive_init(dctx), 1);
        assert_eq!(ffi::EVP_PKEY_derive_set_peer(dctx, peer), 1);
        let mut len = 0usize;
        assert_eq!(
            ffi::EVP_PKEY_derive(dctx, std::ptr::null_mut(), &mut len),
            1
        );
        let mut secret = vec![0u8; len];
        assert_eq!(ffi::EVP_PKEY_derive(dctx, secret.as_mut_ptr(), &mut len), 1);
        secret.truncate(len);
        ffi::EVP_PKEY_CTX_free(dctx);
        assert!(!secret.is_empty(), "empty shared-secret blob");
        write_secret(&ikm, &secret);

        // HKDF on the blob, buffer mode, across digests (the HMAC kind follows
        // the digest). The armed size query reports the shared masked-blob
        // buffer size (MASKED_KEY_MAX_BUFFER = 8192), which the buffer must fit.
        for (md, bits) in [("SHA256", "256"), ("SHA384", "384"), ("SHA512", "512")] {
            let kctx = ffi::EVP_PKEY_CTX_new_id(ffi::NID_hkdf as std::ffi::c_int, e);
            assert!(!kctx.is_null(), "EVP_PKEY_CTX_new_id(NID_hkdf, engine)");
            assert_eq!(ffi::EVP_PKEY_derive_init(kctx), 1);
            for (k, v) in [
                ("md", md),
                ("azihsm.ikm_file", ikm.to_str().unwrap()),
                ("derived_key_type", "hmac"),
                ("derived_key_bits", bits),
            ] {
                let key = cstr(k);
                let value = cstr(v);
                assert_eq!(
                    ffi::EVP_PKEY_CTX_ctrl_str(kctx, key.as_ptr(), value.as_ptr()),
                    1,
                    "HKDF option {k} ({md})"
                );
            }
            let mut klen = 0usize;
            assert_eq!(
                ffi::EVP_PKEY_derive(kctx, std::ptr::null_mut(), &mut klen),
                1,
                "HKDF size query ({md})"
            );
            assert_eq!(klen, 8192, "size query must report the blob max ({md})");
            let mut kbuf = vec![0u8; klen];
            assert_eq!(
                ffi::EVP_PKEY_derive(kctx, kbuf.as_mut_ptr(), &mut klen),
                1,
                "HKDF derive ({md})"
            );
            assert!(klen > 0, "empty derived-key blob ({md})");
            ffi::EVP_PKEY_CTX_free(kctx);
        }

        // output_file mode on a fresh ctx.
        let fctx = ffi::EVP_PKEY_CTX_new_id(ffi::NID_hkdf as std::ffi::c_int, e);
        assert!(!fctx.is_null());
        assert_eq!(ffi::EVP_PKEY_derive_init(fctx), 1);
        for (k, v) in [
            ("md", "SHA256"),
            ("azihsm.ikm_file", ikm.to_str().unwrap()),
            ("derived_key_type", "aes"),
            ("output_file", out.to_str().unwrap()),
        ] {
            let key = cstr(k);
            let value = cstr(v);
            assert_eq!(
                ffi::EVP_PKEY_CTX_ctrl_str(fctx, key.as_ptr(), value.as_ptr()),
                1,
                "HKDF option {k}"
            );
        }
        let mut n = 0usize;
        assert_eq!(ffi::EVP_PKEY_derive(fctx, std::ptr::null_mut(), &mut n), 1);
        assert_eq!(n, 1, "file-mode size query must report 1");
        let mut one = [0u8; 1];
        assert_eq!(ffi::EVP_PKEY_derive(fctx, one.as_mut_ptr(), &mut n), 1);
        assert_eq!(n, 0, "file mode must return no bytes");
        assert!(
            out.is_file() && std::fs::metadata(&out).unwrap().len() > 0,
            "derived blob not written"
        );
        ffi::EVP_PKEY_CTX_free(fctx);

        ffi::EVP_PKEY_free(peer);
        ffi::EVP_PKEY_free(pkey);
        ffi::ENGINE_finish(e);
        ffi::ENGINE_free(e);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sign `msg` (SHA-256) through `pkey` via `EVP_DigestSign*`, optionally under
/// RSA-PSS (`rsa_padding_mode:pss`, `rsa_pss_saltlen:digest`). The engine is NOT
/// passed to `EVP_DigestSignInit` (that would also try to fetch the digest from
/// the engine, which provides none); the loaded key is bound to the engine via
/// `EVP_PKEY_set1_engine` by the caller, so the pkey ctx resolves to the engine's
/// RSA `EVP_PKEY_METHOD` (reaching the PSS override) while the digest stays
/// software.
#[allow(unsafe_code)]
fn capi_rsa_digest_sign(pkey: *mut ffi::EVP_PKEY, msg: &[u8], pss: bool) -> Vec<u8> {
    let pad_key = CString::new("rsa_padding_mode").unwrap();
    let pad_val = CString::new("pss").unwrap();
    let salt_key = CString::new("rsa_pss_saltlen").unwrap();
    let salt_val = CString::new("digest").unwrap();
    // SAFETY: EVP_DigestSign sequence; pctx is owned by the md ctx (not freed
    // separately), every return code is checked, and the md ctx is freed.
    unsafe {
        let ctx = ffi::EVP_MD_CTX_new();
        assert!(!ctx.is_null());
        let mut pctx: *mut ffi::EVP_PKEY_CTX = std::ptr::null_mut();
        assert_eq!(
            ffi::EVP_DigestSignInit(
                ctx,
                &mut pctx,
                ffi::EVP_sha256(),
                std::ptr::null_mut(),
                pkey,
            ),
            1,
            "EVP_DigestSignInit"
        );
        if pss {
            assert_eq!(
                ffi::EVP_PKEY_CTX_ctrl_str(pctx, pad_key.as_ptr(), pad_val.as_ptr()),
                1,
                "rsa_padding_mode:pss"
            );
            assert_eq!(
                ffi::EVP_PKEY_CTX_ctrl_str(pctx, salt_key.as_ptr(), salt_val.as_ptr()),
                1,
                "rsa_pss_saltlen:digest"
            );
        }
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

/// Software SHA-256 verify of `sig` over `msg` with `pub_der` (SPKI), optionally
/// under RSA-PSS with a digest-length salt. Returns whether it verifies.
fn sw_rsa_verify(pub_der: &[u8], msg: &[u8], sig: &[u8], pss: bool) -> bool {
    let pubkey = PKey::public_key_from_der(pub_der).unwrap();
    let mut v = Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
    if pss {
        v.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        v.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).unwrap();
    }
    v.update(msg).unwrap();
    v.verify(sig).unwrap()
}

/// RSA import + load + sign over the real C ABI: import a software RSA key into
/// the HSM through `EVP_PKEY_CTX_new_id(RSA, engine)` + `azihsm.input_key`
/// control strings + `EVP_PKEY_keygen` (writing the masked blob), load the blob
/// back through `ENGINE_load_private_key` (`azihsm://…;type=rsa`), then sign with
/// it under both PKCS#1 v1.5 (RSA_METHOD sign slot) and PSS (the RSA
/// EVP_PKEY_METHOD sign override) via `EVP_DigestSign`, verifying each in
/// software against the public half. A single engine load covers the whole flow.
#[test]
#[serial]
#[allow(unsafe_code)]
fn sign_rsa_key_via_engine_capi() {
    use std::ffi::c_int;

    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");
    let dir = setup_keymat();

    // Fixture: a software RSA-2048 key as unencrypted PKCS#8 DER, plus its SPKI.
    let sw = Rsa::generate(2048).unwrap();
    let sw_pkey = PKey::from_rsa(sw).unwrap();
    let input_der = sw_pkey.private_key_to_pkcs8().unwrap();
    let pub_der = sw_pkey.public_key_to_der().unwrap();
    let input_path = dir.join("rsa_input.der");
    write_secret(&input_path, &input_der);
    let blob = dir.join("rsa_key.bin");

    let e = open_dynamic_engine(&engine_so);

    // Import into the HSM via the keygen ABI (genpkey-equivalent), discarding the
    // returned key — the point is to exercise the load path next.
    let cstr = |s: &str| CString::new(s).unwrap();
    // SAFETY: standard EVP_PKEY keygen (import) sequence on the engine handle;
    // every return code is checked and both the ctx and the key are freed.
    unsafe {
        let ctx = ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_RSA as c_int, e);
        assert!(!ctx.is_null(), "EVP_PKEY_CTX_new_id(RSA, engine)");
        assert_eq!(ffi::EVP_PKEY_keygen_init(ctx), 1, "EVP_PKEY_keygen_init");
        for (k, v) in [
            ("rsa_keygen_bits", "2048"),
            ("azihsm.input_key", input_path.to_str().unwrap()),
            ("azihsm.masked_key", blob.to_str().unwrap()),
            ("azihsm.key_kind", "RSA-CRT"),
        ] {
            let key = cstr(k);
            let value = cstr(v);
            assert_eq!(
                ffi::EVP_PKEY_CTX_ctrl_str(ctx, key.as_ptr(), value.as_ptr()),
                1,
                "import option {k}"
            );
        }
        let mut imported = std::ptr::null_mut();
        assert_eq!(
            ffi::EVP_PKEY_keygen(ctx, &mut imported),
            1,
            "EVP_PKEY_keygen (import): {}",
            openssl::error::ErrorStack::get()
        );
        ffi::EVP_PKEY_CTX_free(ctx);
        ffi::EVP_PKEY_free(imported);
    }
    assert!(
        blob.is_file() && std::fs::metadata(&blob).unwrap().len() > 0,
        "masked blob not written"
    );

    // Load the masked blob through the real loader on the same engine.
    let uri = cstr(&format!("azihsm://{};type=rsa", blob.display()));
    // SAFETY: e is the initialized engine; uri is a valid NUL-terminated string.
    let raw = unsafe {
        ffi::ENGINE_load_private_key(e, uri.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert!(!raw.is_null(), "ENGINE_load_private_key returned NULL");

    // Bind the loaded key to the engine so a NULL-engine EVP_DigestSignInit still
    // resolves PSS to the engine's RSA EVP_PKEY_METHOD (the digest stays software).
    // SAFETY: raw is a valid EVP_PKEY; e is the initialized engine.
    let bind_rc = unsafe { ffi::EVP_PKEY_set1_engine(raw, e) };
    assert_eq!(bind_rc, 1, "EVP_PKEY_set1_engine");

    let msg = b"engine rsa signing over the capi path";

    // PKCS#1 v1.5 (reaches the RSA_METHOD sign slot) and PSS (reaches the RSA
    // EVP_PKEY_METHOD sign override) — each verified in software.
    let sig_v15 = capi_rsa_digest_sign(raw, msg, false);
    assert!(!sig_v15.is_empty(), "empty v1.5 signature");
    assert!(
        sw_rsa_verify(&pub_der, msg, &sig_v15, false),
        "v1.5 signature must verify against the public key"
    );

    let sig_pss = capi_rsa_digest_sign(raw, msg, true);
    assert!(!sig_pss.is_empty(), "empty PSS signature");
    assert!(
        sw_rsa_verify(&pub_der, msg, &sig_pss, true),
        "PSS signature must verify against the public key"
    );

    // A tampered message must not verify under PSS.
    assert!(
        !sw_rsa_verify(
            &pub_der,
            b"engine rsa signing over the capi path?",
            &sig_pss,
            true
        ),
        "tampered message unexpectedly verified"
    );

    // SAFETY: raw is the owning EVP_PKEY from ENGINE_load_private_key; e is ours.
    unsafe {
        ffi::EVP_PKEY_free(raw);
        ffi::ENGINE_finish(e);
        ffi::ENGINE_free(e);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// One ABI derive round trip per supported curve, under a single engine load:
/// the global ASN1-method registration holds an engine reference until
/// ENGINE_cleanup, so a dynamic engine loads once per process (a second LOAD
/// is refused via its still-listed dynamic_id).
#[test]
#[serial]
#[allow(unsafe_code)]
fn derive_ec_key_via_engine_capi() {
    let engine_so = std::env::var("ENGINE_SO").expect("ENGINE_SO must point to the engine .so");
    let dir = setup_keymat();
    let e = open_dynamic_engine(&engine_so);
    for curve in ["P-256", "P-384", "P-521"] {
        capi_derive_roundtrip(e, &dir, curve);
    }
    // SAFETY: e is the initialized ENGINE from open_dynamic_engine.
    unsafe {
        ffi::ENGINE_finish(e);
        ffi::ENGINE_free(e);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

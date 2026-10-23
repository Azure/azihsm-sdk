// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Custom EC `EVP_PKEY_ASN1_METHOD` for provider-parity serialization of
//! HSM-backed keys.
//!
//! The OpenSSL 3.x provider answers a private-key serialization request for an
//! HSM key with an informational text block instead of key material. On 1.1.x
//! the equivalent hooks are the `EVP_PKEY_ASN1_METHOD` private-key callbacks:
//! `priv_print` carries the `-text` block, and `priv_encode` (which must
//! produce a `PKCS8_PRIV_KEY_INFO`, so free-form text is impossible there)
//! refuses with a single clear error instead of the raw `i2d` failure trail.
//!
//! Reaching those callbacks for EC keys requires **global registration**
//! (`ENGINE_register_pkey_asn1_meths`): OpenSSL resolves the ASN1 method by
//! key type, so our method serves *every* EC `EVP_PKEY` in the process while
//! the engine is loaded. Two consequences shape this module:
//!
//! - **Software keys must behave exactly as before.** 1.1.x offers no getters
//!   on `EVP_PKEY_ASN1_METHOD` (and `EVP_PKEY_asn1_set_private` replaces the
//!   decode/encode/print trio atomically), so the built-in behavior cannot be
//!   delegated to — it is ported here from `ec_ameth.c` using only public API
//!   (`i2d/d2i_ECPrivateKey`, `i2d/d2i_ECParameters`, `PKCS8_pkey_set0/get0`,
//!   `EC_KEY_print`). Byte-exactness against the built-in is pinned by unit
//!   tests.
//! - **Each ENGINE owns its method copy**: like the pkey methods,
//!   `engine_pkey_asn1_meths_free` frees whatever the callback hands out when
//!   that ENGINE is destroyed, so methods live in a per-ENGINE
//!   [`method_table`](crate::method_table) released by the destroy hook.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::ptr::null_mut;

use azihsm_ossl_engine_sys as ffi;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::catch_panic;
use crate::error::result_to_int;
use crate::method_table::MethodTable;

/// Caller-supplied policy for HSM-backed EC keys, dispatched from the ASN1
/// method's private-key callbacks. Implement on a marker type and pass it to
/// [`register_ec_asn1_method`].
pub trait EcAsn1Handler {
    /// Whether `pkey` is one of the handler's keys (e.g. carries an attached
    /// HSM key handle). Keys not owned get the ported built-in behavior.
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool;

    /// Print the `-text` info block for an owned key into `bio` (mirroring
    /// the 3.x provider's text encoder).
    fn print_owned(
        bio: *mut ffi::BIO,
        pkey: *const ffi::EVP_PKEY,
        indent: c_int,
    ) -> EngineResult<()>;

    /// One-line reason recorded on the error queue when a private-key export
    /// of an owned key is requested.
    fn export_refusal() -> &'static str;
}

/// Write `text` to `bio`, failing on a short write.
///
/// # Safety
/// `bio` must be a valid, writable `BIO` for the duration of the call.
#[allow(unsafe_code)]
pub unsafe fn bio_write_all(bio: *mut ffi::BIO, text: &str) -> EngineResult<()> {
    let len = c_int::try_from(text.len())
        .map_err(|_| EngineError::Other("text too large for BIO_write".into()))?;
    // SAFETY: bio is the BIO OpenSSL passed to the print callback; text is
    // valid for len bytes.
    if unsafe { ffi::BIO_write(bio, text.as_ptr().cast::<c_void>(), len) } != len {
        return Err(EngineError::Other("BIO_write failed".into()));
    }
    Ok(())
}

/// Port of `eckey_param2type` (ec_ameth.c): encode the key's domain parameters
/// as either a named-curve OID (`V_ASN1_OBJECT`) or explicit `ECParameters`
/// (`V_ASN1_SEQUENCE`). On success the returned `pval` follows the same
/// ownership rules as the original: the OID is a static object, the
/// `ASN1_STRING` is owned by the caller until handed to `PKCS8_pkey_set0`.
#[allow(unsafe_code)]
fn ec_param2type(ec: *const ffi::EC_KEY) -> EngineResult<(c_int, *mut c_void)> {
    // SAFETY: ec is a valid EC_KEY; get0 returns a borrowed group.
    let group = unsafe { ffi::EC_KEY_get0_group(ec) };
    if group.is_null() {
        return Err(EngineError::Other("EC key has no group".into()));
    }
    // SAFETY: group is valid (checked).
    let (asn1_flag, nid) = unsafe {
        (
            ffi::EC_GROUP_get_asn1_flag(group),
            ffi::EC_GROUP_get_curve_name(group),
        )
    };
    if asn1_flag != 0 && nid != 0 {
        // Named curve: the OID object is a library constant, never freed.
        // SAFETY: nid names a builtin curve.
        let obj = unsafe { ffi::OBJ_nid2obj(nid) };
        // SAFETY: obj is a valid ASN1_OBJECT (or NULL, checked).
        if obj.is_null() || unsafe { ffi::OBJ_length(obj) } == 0 {
            return Err(EngineError::Other("missing curve OID".into()));
        }
        return Ok((ffi::V_ASN1_OBJECT as c_int, obj.cast::<c_void>()));
    }

    // Explicit parameters: DER-encode ECParameters into an ASN1_STRING.
    // SAFETY: fresh ASN1_STRING; i2d allocates the buffer via OPENSSL_malloc
    // when the out-pointer starts NULL; set0 takes ownership of it.
    unsafe {
        let pstr = ffi::ASN1_STRING_new();
        if pstr.is_null() {
            return Err(EngineError::Other("ASN1_STRING_new failed".into()));
        }
        let mut buf: *mut c_uchar = null_mut();
        let len = ffi::i2d_ECParameters(ec.cast_mut(), &mut buf);
        if len <= 0 {
            ffi::ASN1_STRING_free(pstr);
            return Err(EngineError::Other("i2d_ECParameters failed".into()));
        }
        ffi::ASN1_STRING_set0(pstr, buf.cast::<c_void>(), len);
        Ok((ffi::V_ASN1_SEQUENCE as c_int, pstr.cast::<c_void>()))
    }
}

/// Free a `pval` from [`ec_param2type`] that was not consumed.
#[allow(unsafe_code)]
fn free_param_pval(ptype: c_int, pval: *mut c_void) {
    if ptype == ffi::V_ASN1_SEQUENCE as c_int && !pval.is_null() {
        // SAFETY: for V_ASN1_SEQUENCE, pval is the ASN1_STRING we allocated.
        unsafe { ffi::ASN1_STRING_free(pval.cast()) };
    }
}

/// Port of `eckey_priv_encode` (ec_ameth.c) via public API: fill `p8` with the
/// PKCS#8 encoding of a software EC private key. The enc-flags toggle uses an
/// `EC_KEY_dup` instead of the built-in's struct copy (the struct is opaque
/// here).
#[allow(unsafe_code)]
fn sw_priv_encode(
    p8: *mut ffi::PKCS8_PRIV_KEY_INFO,
    pkey: *const ffi::EVP_PKEY,
) -> EngineResult<()> {
    // SAFETY: pkey is a valid EC EVP_PKEY per the ameth contract.
    let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey.cast_mut()) };
    if ec.is_null() {
        return Err(EngineError::Other("EVP_PKEY has no EC_KEY".into()));
    }
    // SAFETY: ec is valid; dup gives us a mutable copy for the enc-flag toggle.
    let dup = unsafe { ffi::EC_KEY_dup(ec) };
    if dup.is_null() {
        return Err(EngineError::Other("EC_KEY_dup failed".into()));
    }

    let result = (|| {
        let (ptype, pval) = ec_param2type(dup)?;

        // Do not include the parameters in the SEC1 private key (PKCS#11
        // 12.11), exactly like the built-in encoder.
        // SAFETY: dup is our own copy; flag mutation does not affect the
        // caller's key.
        unsafe {
            let old = ffi::EC_KEY_get_enc_flags(dup);
            ffi::EC_KEY_set_enc_flags(dup, old | ffi::EC_PKEY_NO_PARAMETERS);
        }

        // SAFETY: i2d allocates via OPENSSL_malloc when the out-pointer starts
        // NULL; PKCS8_pkey_set0 takes ownership of both pval and the buffer on
        // success.
        unsafe {
            let mut ep: *mut c_uchar = null_mut();
            let eplen = ffi::i2d_ECPrivateKey(dup, &mut ep);
            if eplen <= 0 {
                free_param_pval(ptype, pval);
                return Err(EngineError::Other("i2d_ECPrivateKey failed".into()));
            }
            if ffi::PKCS8_pkey_set0(
                p8,
                ffi::OBJ_nid2obj(ffi::NID_X9_62_id_ecPublicKey as c_int),
                0,
                ptype,
                pval,
                ep,
                eplen,
            ) != 1
            {
                free_param_pval(ptype, pval);
                ffi::CRYPTO_free(ep.cast::<c_void>(), c"".as_ptr(), 0);
                return Err(EngineError::Other("PKCS8_pkey_set0 failed".into()));
            }
        }
        Ok(())
    })();

    // SAFETY: dup is our copy.
    unsafe { ffi::EC_KEY_free(dup) };
    result
}

/// Port of `eckey_priv_decode` (ec_ameth.c) via public API: parse the PKCS#8
/// structure into a fresh software EC key assigned to `pkey`.
#[allow(unsafe_code)]
fn sw_priv_decode(
    pkey: *mut ffi::EVP_PKEY,
    p8: *const ffi::PKCS8_PRIV_KEY_INFO,
) -> EngineResult<()> {
    let mut p: *const c_uchar = std::ptr::null();
    let mut pklen: c_int = 0;
    let mut palg: *const ffi::X509_ALGOR = std::ptr::null();
    // SAFETY: p8 is the PKCS8 structure OpenSSL passed us; get0 fills borrowed
    // out-params.
    if unsafe { ffi::PKCS8_pkey_get0(null_mut(), &mut p, &mut pklen, &mut palg, p8) } != 1 {
        return Err(EngineError::Other("PKCS8_pkey_get0 failed".into()));
    }
    let mut ptype: c_int = 0;
    let mut pval: *const c_void = std::ptr::null();
    // SAFETY: palg is the borrowed algorithm identifier.
    unsafe { ffi::X509_ALGOR_get0(null_mut(), &mut ptype, &mut pval, palg) };

    // Port of eckey_type2param: recover the group from the parameters.
    // SAFETY: standard EC construction; every return code is checked and
    // eckey is freed on all failure paths.
    unsafe {
        let mut eckey: *mut ffi::EC_KEY;
        if ptype == ffi::V_ASN1_SEQUENCE as c_int {
            let pstr: *const ffi::ASN1_STRING = pval.cast();
            let mut pm = ffi::ASN1_STRING_get0_data(pstr);
            let pmlen = ffi::ASN1_STRING_length(pstr);
            eckey = ffi::d2i_ECParameters(null_mut(), &mut pm, pmlen.into());
            if eckey.is_null() {
                return Err(EngineError::Other("d2i_ECParameters failed".into()));
            }
        } else if ptype == ffi::V_ASN1_OBJECT as c_int {
            eckey = ffi::EC_KEY_new();
            if eckey.is_null() {
                return Err(EngineError::Other("EC_KEY_new failed".into()));
            }
            let group = ffi::EC_GROUP_new_by_curve_name(ffi::OBJ_obj2nid(pval.cast()));
            if group.is_null() {
                ffi::EC_KEY_free(eckey);
                return Err(EngineError::Other("unknown curve in PKCS#8".into()));
            }
            ffi::EC_GROUP_set_asn1_flag(group, ffi::OPENSSL_EC_NAMED_CURVE as c_int);
            if ffi::EC_KEY_set_group(eckey, group) != 1 {
                ffi::EC_GROUP_free(group);
                ffi::EC_KEY_free(eckey);
                return Err(EngineError::Other("EC_KEY_set_group failed".into()));
            }
            ffi::EC_GROUP_free(group);
        } else {
            return Err(EngineError::Other("bad EC PKCS#8 parameters".into()));
        }

        let mut pp = p;
        if ffi::d2i_ECPrivateKey(&mut eckey, &mut pp, pklen.into()).is_null() {
            ffi::EC_KEY_free(eckey);
            return Err(EngineError::Other("d2i_ECPrivateKey failed".into()));
        }
        if ffi::EVP_PKEY_assign(pkey, ffi::EVP_PKEY_EC as c_int, eckey.cast::<c_void>()) != 1 {
            ffi::EC_KEY_free(eckey);
            return Err(EngineError::Other("EVP_PKEY_assign failed".into()));
        }
    }
    Ok(())
}

/// `priv_encode` override: refuse for owned keys with one clear error, port of
/// the built-in for software keys.
///
/// # Safety
/// Called only by OpenSSL's PKCS#8 encode path; `p8`/`pk` per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_priv_encode<H: EcAsn1Handler>(
    p8: *mut ffi::PKCS8_PRIV_KEY_INFO,
    pk: *const ffi::EVP_PKEY,
) -> c_int {
    catch_panic(
        || {
            if pk.is_null() {
                return 0;
            }
            if H::owns(pk) {
                return result_to_int::<()>(Err(EngineError::Other(H::export_refusal().into())));
            }
            result_to_int(sw_priv_encode(p8, pk))
        },
        0,
    )
}

/// `priv_decode` override: port of the built-in (owned keys are never encoded,
/// so decode only ever sees software keys).
///
/// # Safety
/// Called only by OpenSSL's PKCS#8 decode path; `pk`/`p8` per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_priv_decode(
    pk: *mut ffi::EVP_PKEY,
    p8: *const ffi::PKCS8_PRIV_KEY_INFO,
) -> c_int {
    catch_panic(|| result_to_int(sw_priv_decode(pk, p8)), 0)
}

/// `priv_print` override: provider-style info block for owned keys,
/// `EC_KEY_print` (the built-in behavior) for software keys.
///
/// # Safety
/// Called only by `EVP_PKEY_print_private`; arguments per that contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_priv_print<H: EcAsn1Handler>(
    out: *mut ffi::BIO,
    pkey: *const ffi::EVP_PKEY,
    indent: c_int,
    _pctx: *mut ffi::ASN1_PCTX,
) -> c_int {
    catch_panic(
        || {
            if pkey.is_null() {
                return 0;
            }
            if H::owns(pkey) {
                return result_to_int(H::print_owned(out, pkey, indent));
            }
            // SAFETY: pkey is a valid EC EVP_PKEY; EC_KEY_print writes the
            // built-in text form.
            unsafe {
                let ec = ffi::EVP_PKEY_get0_EC_KEY(pkey.cast_mut());
                if ec.is_null() {
                    return 0;
                }
                ffi::EC_KEY_print(out, ec, indent)
            }
        },
        0,
    )
}

/// Build our EC `EVP_PKEY_ASN1_METHOD`: a copy of the built-in EC method with
/// the private-key trio (`decode`/`encode`/`print`) overridden as described in
/// the module docs.
#[allow(unsafe_code)]
fn new_ec_asn1_method<H: EcAsn1Handler>() -> EngineResult<*mut ffi::EVP_PKEY_ASN1_METHOD> {
    // SAFETY: pe = NULL finds the built-in method without engine lookups.
    let builtin = unsafe { ffi::EVP_PKEY_asn1_find(null_mut(), ffi::EVP_PKEY_EC as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other("built-in EC ASN1 method missing".into()));
    }
    // SAFETY: asn1_new allocates a fresh method (pkey_id EC, standard pem_str);
    // asn1_copy duplicates every callback from the built-in; set_private then
    // installs our trio.
    unsafe {
        let method = ffi::EVP_PKEY_asn1_new(
            ffi::EVP_PKEY_EC as c_int,
            0,
            c"EC".as_ptr(),
            c"azihsm EC".as_ptr(),
        );
        if method.is_null() {
            return Err(EngineError::Other("EVP_PKEY_asn1_new failed".into()));
        }
        ffi::EVP_PKEY_asn1_copy(method, builtin);
        ffi::EVP_PKEY_asn1_set_private(
            method,
            Some(c_priv_decode),
            Some(c_priv_encode::<H>),
            Some(c_priv_print::<H>),
        );
        Ok(method)
    }
}

/// The NIDs this engine's ASN1-method callback serves.
static ASN1_NIDS: [c_int; 1] = [ffi::EVP_PKEY_EC as c_int];

/// Per-`(ENGINE, NID)` method table (see [`method_table`](crate::method_table)
/// for the ownership rules the engine framework imposes).
static ENGINE_METHODS: MethodTable<ffi::EVP_PKEY_ASN1_METHOD> = MethodTable::new(&ASN1_NIDS);

/// `ENGINE_PKEY_ASN1_METHS_PTR` callback: NID enumeration and per-ENGINE
/// method lookup via [`method_table::dispatch`](crate::method_table::dispatch)
/// (no stored-entry hook — only the pkey method needs the requesting ENGINE).
///
/// # Safety
/// Called only by OpenSSL's engine ASN1-method lookup; out-params per that
/// contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_pkey_asn1_meths(
    e: *mut ffi::ENGINE,
    ameth: *mut *mut ffi::EVP_PKEY_ASN1_METHOD,
    nids: *mut *const c_int,
    nid: c_int,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the out-params OpenSSL passed us.
        || unsafe { crate::method_table::dispatch(&ENGINE_METHODS, e, ameth, nids, nid, |_| ()) },
        0,
    )
}

/// Register `H` as `engine`'s EC ASN1 handler and add the engine to OpenSSL's
/// global ASN1-method table, so every EC `EVP_PKEY` in the process resolves to
/// this engine's method (with software keys handled by the ported built-in
/// behavior). Only one handler type can be registered per process (the first
/// wins). Pair with [`release_ec_asn1_method`] when the ENGINE is destroyed.
#[allow(unsafe_code)]
pub fn register_ec_asn1_method<H: EcAsn1Handler>(engine: &Engine) -> EngineResult<()> {
    ENGINE_METHODS.register(engine, ffi::EVP_PKEY_EC as c_int, new_ec_asn1_method::<H>)?;
    // SAFETY: engine's ptr is valid (from NonNull); c_pkey_asn1_meths is a
    // 'static fn item with the ENGINE_PKEY_ASN1_METHS_PTR signature.
    let rc = unsafe { ffi::ENGINE_set_pkey_asn1_meths(engine.as_ptr(), Some(c_pkey_asn1_meths)) };
    crate::error::ossl_check(
        rc,
        EngineError::Other("ENGINE_set_pkey_asn1_meths failed".into()),
    )?;
    // SAFETY: adds the engine to the global per-NID ASN1 table so
    // EVP_PKEY_asn1_find resolves our method for EC.
    let rc = unsafe { ffi::ENGINE_register_pkey_asn1_meths(engine.as_ptr()) };
    crate::error::ossl_check(
        rc,
        EngineError::Other("ENGINE_register_pkey_asn1_meths failed".into()),
    )
}

/// Remove `engine` from the global ASN1 table and drop its method-table entry.
/// Call from the engine's destroy hook (or, in tests, around `ENGINE_free`):
/// the framework frees the method itself (`engine_pkey_asn1_meths_free` runs
/// before the destroy hook), so only the stale pointer is discarded.
#[allow(unsafe_code)]
pub fn release_ec_asn1_method(engine: &Engine) {
    // SAFETY: unregistering only removes table entries keyed by the engine.
    unsafe { ffi::ENGINE_unregister_pkey_asn1_meths(engine.as_ptr()) };
    ENGINE_METHODS.release(engine);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ffi::c_char;

    use super::*;

    struct DisownAsn1;
    impl EcAsn1Handler for DisownAsn1 {
        fn owns(_pkey: *const ffi::EVP_PKEY) -> bool {
            false
        }
        fn print_owned(
            _bio: *mut ffi::BIO,
            _pkey: *const ffi::EVP_PKEY,
            _indent: c_int,
        ) -> EngineResult<()> {
            unreachable!("print_owned must not be called for a key the handler does not own")
        }
        fn export_refusal() -> &'static str {
            "unreachable"
        }
    }

    /// A generated software EC EVP_PKEY on the given curve NID, with the given
    /// parameter encoding flag.
    #[allow(unsafe_code)]
    fn software_ec_pkey(nid: c_int, asn1_flag: c_int) -> *mut ffi::EVP_PKEY {
        // SAFETY: standard EC keygen + EVP_PKEY assembly; every return code is
        // checked. The EVP_PKEY takes ownership of the EC_KEY via assign.
        unsafe {
            let group = ffi::EC_GROUP_new_by_curve_name(nid);
            assert!(!group.is_null());
            ffi::EC_GROUP_set_asn1_flag(group, asn1_flag);
            let ec = ffi::EC_KEY_new();
            assert!(!ec.is_null());
            assert_eq!(ffi::EC_KEY_set_group(ec, group), 1);
            ffi::EC_GROUP_free(group);
            assert_eq!(ffi::EC_KEY_generate_key(ec), 1);
            let pkey = ffi::EVP_PKEY_new();
            assert!(!pkey.is_null());
            assert_eq!(
                ffi::EVP_PKEY_assign(pkey, ffi::EVP_PKEY_EC as c_int, ec.cast::<c_void>()),
                1
            );
            pkey
        }
    }

    /// DER-serialize a PKCS8 structure.
    #[allow(unsafe_code)]
    fn p8_der(p8: *mut ffi::PKCS8_PRIV_KEY_INFO) -> Vec<u8> {
        // SAFETY: p8 is valid; i2d allocates the buffer when the out-pointer
        // starts NULL.
        unsafe {
            let mut buf: *mut c_uchar = null_mut();
            let len = ffi::i2d_PKCS8_PRIV_KEY_INFO(p8, &mut buf);
            assert!(len > 0, "i2d_PKCS8_PRIV_KEY_INFO");
            let out = std::slice::from_raw_parts(buf, usize::try_from(len).unwrap()).to_vec();
            ffi::CRYPTO_free(buf.cast::<c_void>(), c"".as_ptr(), 0);
            out
        }
    }

    // The ported software encoder must produce byte-identical PKCS#8 to the
    // built-in (EVP_PKEY2PKCS8 uses the untouched built-in ameth here — no
    // engine is registered in this test).
    #[test]
    #[allow(unsafe_code)]
    fn sw_priv_encode_matches_builtin_byte_for_byte() {
        for (nid, flag) in [
            (
                ffi::NID_X9_62_prime256v1 as c_int,
                ffi::OPENSSL_EC_NAMED_CURVE as c_int,
            ),
            (
                ffi::NID_secp384r1 as c_int,
                ffi::OPENSSL_EC_NAMED_CURVE as c_int,
            ),
            (
                ffi::NID_secp521r1 as c_int,
                ffi::OPENSSL_EC_NAMED_CURVE as c_int,
            ),
            // explicit parameters exercise the V_ASN1_SEQUENCE branch
            (ffi::NID_X9_62_prime256v1 as c_int, 0),
        ] {
            let pkey = software_ec_pkey(nid, flag);
            // SAFETY: pkey is valid; PKCS8 structures are freed below.
            unsafe {
                let golden_p8 = ffi::EVP_PKEY2PKCS8(pkey);
                assert!(!golden_p8.is_null(), "builtin EVP_PKEY2PKCS8");
                let golden = p8_der(golden_p8);
                ffi::PKCS8_PRIV_KEY_INFO_free(golden_p8);

                let our_p8 = ffi::PKCS8_PRIV_KEY_INFO_new();
                assert!(!our_p8.is_null());
                sw_priv_encode(our_p8, pkey).expect("sw_priv_encode");
                let ours = p8_der(our_p8);
                ffi::PKCS8_PRIV_KEY_INFO_free(our_p8);

                assert_eq!(ours, golden, "PKCS#8 mismatch for nid {nid} flag {flag}");
                ffi::EVP_PKEY_free(pkey);
            }
        }
    }

    // The ported software decoder must accept the built-in's PKCS#8 output and
    // reconstruct an equivalent key.
    #[test]
    #[allow(unsafe_code)]
    fn sw_priv_decode_round_trips_builtin_pkcs8() {
        for (nid, flag) in [
            (
                ffi::NID_secp384r1 as c_int,
                ffi::OPENSSL_EC_NAMED_CURVE as c_int,
            ),
            (ffi::NID_X9_62_prime256v1 as c_int, 0),
        ] {
            let pkey = software_ec_pkey(nid, flag);
            // SAFETY: pkey is valid; every structure is freed on all paths.
            unsafe {
                let p8 = ffi::EVP_PKEY2PKCS8(pkey);
                assert!(!p8.is_null());

                let decoded = ffi::EVP_PKEY_new();
                assert!(!decoded.is_null());
                sw_priv_decode(decoded, p8).expect("sw_priv_decode");
                ffi::PKCS8_PRIV_KEY_INFO_free(p8);

                assert_eq!(
                    ffi::EVP_PKEY_cmp(pkey, decoded),
                    1,
                    "decoded key differs for nid {nid} flag {flag}"
                );
                ffi::EVP_PKEY_free(decoded);
                ffi::EVP_PKEY_free(pkey);
            }
        }
    }

    // A software key must be routed to the ported built-in print, not the
    // handler.
    #[test]
    #[allow(unsafe_code)]
    fn priv_print_delegates_software_key() {
        let pkey = software_ec_pkey(
            ffi::NID_secp384r1 as c_int,
            ffi::OPENSSL_EC_NAMED_CURVE as c_int,
        );
        // SAFETY: mem BIO + valid pkey; the trampoline writes the builtin text.
        unsafe {
            let bio = ffi::BIO_new(ffi::BIO_s_mem());
            assert!(!bio.is_null());
            assert_eq!(c_priv_print::<DisownAsn1>(bio, pkey, 0, null_mut()), 1);
            let mut data: *mut c_char = null_mut();
            let len = ffi::BIO_ctrl(
                bio,
                ffi::BIO_CTRL_INFO as c_int,
                0,
                (&raw mut data).cast::<c_void>(),
            );
            assert!(len > 0);
            let text = std::slice::from_raw_parts(data.cast::<u8>(), usize::try_from(len).unwrap());
            let text = std::str::from_utf8(text).unwrap();
            assert!(
                text.contains("Private-Key:"),
                "builtin print output missing: {text}"
            );
            ffi::BIO_free(bio);
            ffi::EVP_PKEY_free(pkey);
        }
    }
}

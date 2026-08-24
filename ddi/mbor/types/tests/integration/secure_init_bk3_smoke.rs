// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SecureInitBk3 / SetInitBk3Pin smoke test for mock and hardware backends.
//!
//! A single adaptive provision-and-seal flow (`test_secure_init_bk3_smoke`):
//! - Skips when a sealed BK3 is already present (secure provisioning is
//!   one-shot and persistent, so a re-run must be a no-op).
//! - Otherwise provisions and seals, preferring secure provisioning
//!   (`set_init_bk3_pin` + `secure_init_bk3`) and falling back to legacy
//!   `init_bk3` when the firmware lacks secure BK3 (`InvalidArg`/`UnsupportedCmd`).
//! - Seals the resulting masked BK3 (MOBK) and verifies the seal round-trips.

#![cfg(not(feature = "emu"))]
#![cfg(test)]

use azihsm_cred_encrypt::Bk3EncryptionKey;
use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto::Rng;
use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(_dev: &mut <DdiTest as Ddi>::Dev, _ddi: &DdiTest, _path: &str) -> u16 {
    0
}

pub fn cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    _ddi: &DdiTest,
    _path: &str,
    _setup_session_id: Option<u16>,
) {
}

const API_REV: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

/// Full secure provisioning (set_init_bk3_pin + secure_init_bk3), each over its
/// own fresh ECDH tunnel.
fn secure_provision_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    bk3: &[u8; 48],
) -> Result<DdiSecureInitBk3CmdResp, DdiError> {
    let rev = Some(API_REV);

    // set_init_bk3_pin
    let resp1 = helper_get_establish_cred_encryption_key(dev, None, rev)?;
    let nonce1 = resp1.data.nonce;
    let dev_key1 = DeviceCredKey::new(&resp1.data.pub_key, nonce1);
    assert!(dev_key1.is_ok(), "DeviceCredKey::new failed: {dev_key1:?}");
    let cred = dev_key1
        .unwrap()
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY);
    assert!(
        cred.is_ok(),
        "create_credential_key_from_der failed: {:?}",
        cred.as_ref().err()
    );
    let (cred_key, pub_key1) = cred.unwrap();
    let encrypted_credential = cred_key.encrypt_establish_credential(id, pin, nonce1);
    assert!(
        encrypted_credential.is_ok(),
        "encrypt_establish_credential failed: {encrypted_credential:?}"
    );
    helper_set_init_bk3_pin(dev, encrypted_credential.unwrap(), pub_key1)?;

    // secure_init_bk3
    let resp2 = helper_get_establish_cred_encryption_key(dev, None, rev)?;
    let nonce2 = resp2.data.nonce;
    let dev_key2 = DeviceCredKey::new(&resp2.data.pub_key, nonce2);
    assert!(dev_key2.is_ok(), "DeviceCredKey::new failed: {dev_key2:?}");
    let bk3_res = dev_key2
        .unwrap()
        .create_bk3_key_from_der(&TEST_ECC_384_PRIVATE_KEY);
    assert!(
        bk3_res.is_ok(),
        "create_bk3_key_from_der failed: {:?}",
        bk3_res.as_ref().err()
    );
    let (bk3_key, pub_key2): (Bk3EncryptionKey, DdiDerPublicKey) = bk3_res.unwrap();
    let encrypted_bk3 = bk3_key.encrypt_bk3(bk3, id, pin, nonce2);
    assert!(
        encrypted_bk3.is_ok(),
        "encrypt_bk3 failed: {encrypted_bk3:?}"
    );
    helper_secure_init_bk3(dev, encrypted_bk3.unwrap(), pub_key2)
}

/// True when a provisioning attempt was rejected because the partition is
/// already provisioned -- i.e. the caller hit the provisioned-but-unsealed
/// dead-end. Firmware reports this as `Bk3AlreadyInitialized` (from
/// `secure_init_bk3`/`init_bk3`) and the mock's re-`set_init_bk3_pin` reports
/// `Bk3PinAlreadySet`; both mean "cannot (re)provision".
fn is_already_provisioned<T>(res: &Result<T, DdiError>) -> bool {
    matches!(
        res,
        Err(DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized))
            | Err(DdiError::DdiStatus(DdiStatus::Bk3PinAlreadySet))
    )
}

/// True when a secure-provisioning attempt was rejected because the firmware
/// does not implement the secure BK3 ops -- the signal to fall back to legacy
/// `init_bk3`. Two firmware responses both mean "secure BK3 unsupported":
///
/// * `InvalidArg` -- the real signal on hardware. `SetInitBk3Pin` (op 1114) is a
///   no-session op, but firmware that doesn't know it defaults it to *in-session*
///   while the host tags the SQE *no-session*; the header's session-control
///   hijack check rejects that mismatch with `InvalidArg` *before* dispatch, so
///   `UnsupportedCmd` is never reached for this op.
/// * `UnsupportedCmd` -- the dispatch-table equivalent (an unrecognized
///   *in-session* op; also how the mock signals it).
///
/// CAVEAT: `InvalidArg` is ambiguous -- a secure-*capable* firmware with a
/// request-encoding bug returns it too, so the caller logs loudly when it falls
/// back on this status. There is no clean capability probe today (API rev is
/// pinned at 1.0, device-info has no secure-BK3 bit); prefer a positive probe
/// once firmware exposes one.
fn is_secure_bk3_unsupported(err: &DdiError) -> bool {
    matches!(
        err,
        DdiError::DdiStatus(DdiStatus::UnsupportedCmd) | DdiError::DdiStatus(DdiStatus::InvalidArg)
    )
}

/// Provision and seal the partition, adapting to prior device state and to the
/// firmware's capability. Intended for hardware, where the partition may already
/// be provisioned/sealed from an earlier run and where older firmware may not
/// implement the secure BK3 ops.
///
/// The seal-read status alone can't classify the device on every backend: gated
/// firmware/mock returns `Bk3NotSecurelyProvisioned` for a fresh partition and
/// `SealedBk3NotPresent` for a provisioned-but-unsealed one, but gate-less
/// legacy firmware returns `SealedBk3NotPresent` for BOTH. So "not sealed" is
/// disambiguated by attempting to provision:
///
/// 1. `get_sealed_bk3` == `Ok` (already sealed): return silently -- provisioning
///    is one-shot and persistent, so a re-run is a clean no-op.
/// 2. Not sealed (`SealedBk3NotPresent` or `Bk3NotSecurelyProvisioned`): attempt
///    provisioning, preferring secure and falling back to legacy `init_bk3` when
///    the firmware lacks secure BK3 (see `is_secure_bk3_unsupported`), then seal.
///    The provision result resolves the ambiguity:
///      * success -> partition was fresh; seal it.
///      * `Bk3AlreadyInitialized` / `Bk3PinAlreadySet` -> the
///        provisioned-but-unsealed dead-end: fail via `assert!`. It is
///        unrecoverable (the one-shot MOBK is not persisted), so it can neither
///        be re-provisioned nor re-sealed. This flow always seals right after
///        provisioning, so it never creates that state; hitting it means a prior
///        run was interrupted and the partition must be reset out-of-band.
/// 3. Any other `get_sealed_bk3` error is unexpected and fails via `assert!`.
///
/// Returns the sealed MOBK so callers can assert on it.
fn ensure_bk3_provisioned_and_sealed(dev: &<DdiTest as Ddi>::Dev) -> Vec<u8> {
    // (1) Already sealed -> nothing to do; hand back the sealed MOBK.
    match helper_get_sealed_bk3(dev) {
        Ok(get_resp) => return get_resp.data.sealed_bk3.as_slice().to_vec(),
        // Not sealed: SealedBk3NotPresent (unsealed, or fresh on legacy) or
        // Bk3NotSecurelyProvisioned (fresh on gated firmware/mock). The provision
        // attempt below disambiguates fresh from the dead-end; anything else is
        // an unexpected device/transport error.
        Err(err) => {
            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::SealedBk3NotPresent)
                        | DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned)
                ),
                "unexpected get_sealed_bk3 error while classifying device state: {err:?}"
            )
        }
    }

    let mut bk3 = [0u8; 48];
    let rng = Rng::rand_bytes(&mut bk3);
    assert!(rng.is_ok(), "rand_bytes failed: {rng:?}");

    // Attempt secure provisioning first. The result disambiguates the
    // "not sealed" state (see the doc comment).
    let prov = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);

    // Dead-end guard: an already-provisioned partition that is not sealed is
    // unrecoverable and fails the test.
    assert!(
        !is_already_provisioned(&prov),
        "BK3 is provisioned but not sealed; this state is unrecoverable \
         (one-shot provisioning, MOBK not persisted) and must be reset \
         out-of-band"
    );

    let masked_bk3 = match prov {
        Ok(resp) => {
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(resp.hdr.fips_approved);
            resp.data.masked_bk3.as_slice().to_vec()
        }
        Err(err) => {
            // Only "secure BK3 unsupported" (see `is_secure_bk3_unsupported`) is
            // a recoverable failure: fall back to legacy InitBk3. The rejection
            // happens before any BK3 state is written, so the legacy path starts
            // clean. Any other error is a real failure and must not be masked.
            assert!(
                is_secure_bk3_unsupported(&err),
                "secure BK3 provisioning failed unexpectedly: {err:?}"
            );
            if matches!(err, DdiError::DdiStatus(DdiStatus::InvalidArg)) {
                // InvalidArg is ambiguous (also a real request-bug on secure
                // firmware), so surface the fallback for a human/CI reviewer.
                println!(
                    "[bk3-smoke] WARNING: secure provisioning returned InvalidArg. \
                     Treating as 'secure BK3 unsupported (legacy firmware)' and \
                     falling back to init_bk3. NOTE: InvalidArg can also indicate \
                     a REAL secure-path request bug on secure-capable firmware -- \
                     verify the flashed firmware genuinely lacks secure BK3."
                );
            }
            let legacy = helper_init_bk3(dev, bk3.to_vec());
            // Same dead-end guard for the legacy path.
            assert!(
                !is_already_provisioned(&legacy),
                "BK3 is provisioned but not sealed; this state is unrecoverable \
                 (one-shot provisioning, MOBK not persisted) and must be reset \
                 out-of-band"
            );
            let resp = legacy.expect("InitBk3 must succeed when secure BK3 is unsupported");
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            resp.data.masked_bk3.as_slice().to_vec()
        }
    };

    assert!(
        (MIN_MASKED_BK3_LEN..=MAX_MASKED_BK3_LEN).contains(&masked_bk3.len()),
        "masked_bk3 length {} is outside the expected range",
        masked_bk3.len()
    );

    // Seal the MOBK immediately after provisioning so the provision->seal pair
    // is effectively atomic for this flow (never leaving the unrecoverable
    // provisioned-but-unsealed state), and so subsequent runs short-circuit at
    // step (1).
    let set_resp = helper_set_sealed_bk3(dev, masked_bk3.clone())
        .expect("set_sealed_bk3 must succeed after provisioning");
    assert_eq!(set_resp.hdr.status, DdiStatus::Success);

    // Confirm the seal round-trips.
    let get_resp = helper_get_sealed_bk3(dev).expect("get_sealed_bk3 must succeed after sealing");
    assert_eq!(get_resp.data.sealed_bk3.as_slice(), masked_bk3.as_slice());

    masked_bk3
}

// Adaptive smoke: provision + seal, skipping if already sealed and falling
// back to legacy InitBk3 on firmware that lacks the secure BK3 ops.
#[test]
fn test_secure_init_bk3_smoke() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned_and_sealed(dev);
    });
}

// Copyright (C) Microsoft Corporation. All rights reserved.

pub mod callback;
pub mod init;

#[cfg(test)]
mod tests {

    use std::ffi::c_int;
    use std::ffi::CString;
    use std::ptr::null_mut;

    use api_interface::REPORT_DATA_SIZE;
    use openssl_rust::safeapi::ec::ecdsa_sig::Ecdsa_Sig;
    use openssl_rust::safeapi::ec::key::EcKey;
    use openssl_rust::safeapi::engine::Engine;
    use openssl_rust::NID_X9_62_prime256v1;
    use openssl_rust::NID_secp384r1;
    use openssl_rust::NID_secp521r1;
    use openssl_rust::NID_sect113r1;
    use openssl_rust::EC_FLAG_COFACTOR_ECDH;

    use super::callback::compute_key_cb;
    use super::callback::copy_cb;
    use super::callback::ec_attest_key;
    use super::callback::keygen_cb;
    use super::callback::sign_cb;
    use super::callback::sign_sig_cb;
    use super::callback::verify_cb;
    use super::callback::verify_sig_cb;
    use crate::bind_helper;
    use crate::common::ec_key::EcKeyData;
    type TestResult<T> = Result<T, &'static str>;

    #[test]
    fn test_keygen() {
        let _e = load_engine();
        //for ECDSA - This will allocate the new key. So we need to free it.
        let mut ec_p256_ecdsa = ec_key_keygen(NID_X9_62_prime256v1, false);
        let mut ec_p384_ecdsa = ec_key_keygen(NID_secp384r1, false);
        let mut ec_p521_ecdsa = ec_key_keygen(NID_secp521r1, false);

        // For ECDH
        let mut ec_p256_ecdh = ec_key_keygen(NID_X9_62_prime256v1, true);
        let mut ec_p384_ecdh = ec_key_keygen(NID_secp384r1, true);
        let mut ec_p521_ecdh = ec_key_keygen(NID_secp521r1, true);

        // Free keys
        ec_p256_ecdsa.free();
        ec_p384_ecdsa.free();
        ec_p521_ecdsa.free();
        ec_p256_ecdh.free();
        ec_p384_ecdh.free();
        ec_p521_ecdh.free();
    }

    #[test]
    fn test_keygen_invalid() {
        let _e = load_engine();
        // Call OpenSSL new key API
        let mut key: EcKey<EcKeyData> = EcKey::new().expect("Could not create ECKey object");
        assert!(key.set_key_group_by_name(NID_sect113r1 as c_int).is_ok());
        let key_ptr = key.as_mut_ptr();
        assert!(keygen_cb(key_ptr).is_err());

        // Should not have data
        assert!(key.get_data().unwrap().is_none());

        // Free key
        key.free();
    }

    #[test]
    fn test_ec_key_ecdsa() {
        let _e = load_engine();
        assert!(ec_key_ecdsa(NID_X9_62_prime256v1, 20, 64).is_ok());
        assert!(ec_key_ecdsa(NID_X9_62_prime256v1, 32, 64).is_ok());
        assert!(ec_key_ecdsa(NID_secp384r1, 20, 96).is_ok());
        assert!(ec_key_ecdsa(NID_secp384r1, 32, 96).is_ok());
        assert!(ec_key_ecdsa(NID_secp384r1, 48, 96).is_ok());
        assert!(ec_key_ecdsa(NID_secp521r1, 20, 132).is_ok());
        assert!(ec_key_ecdsa(NID_secp521r1, 32, 132).is_ok());
        assert!(ec_key_ecdsa(NID_secp521r1, 48, 132).is_ok());
        assert!(ec_key_ecdsa(NID_secp521r1, 64, 132).is_ok());
    }

    #[test]
    fn test_ec_key_copy_ecdsa() {
        let _e = load_engine();
        assert!(ec_key_copy_ecdsa(NID_X9_62_prime256v1, 20, 64).is_ok());
        assert!(ec_key_copy_ecdsa(NID_X9_62_prime256v1, 32, 64).is_ok());
        assert!(ec_key_copy_ecdsa(NID_secp384r1, 20, 96).is_ok());
        assert!(ec_key_copy_ecdsa(NID_secp384r1, 32, 96).is_ok());
        assert!(ec_key_copy_ecdsa(NID_secp384r1, 48, 96).is_ok());
        assert!(ec_key_copy_ecdsa(NID_secp521r1, 20, 132).is_ok());
        assert!(ec_key_copy_ecdsa(NID_secp521r1, 32, 132).is_ok());
        assert!(ec_key_copy_ecdsa(NID_secp521r1, 48, 132).is_ok());
    }

    #[test]
    fn test_ec_key_ecdh() {
        let _e = load_engine();
        assert!(ec_key_ecdh(NID_X9_62_prime256v1).is_ok());
        assert!(ec_key_ecdh(NID_secp384r1).is_ok());
        assert!(ec_key_ecdh(NID_secp521r1).is_ok());
    }

    #[test]
    fn test_ec_key_copy_ecdh() {
        let _e = load_engine();
        assert!(ec_key_copy_ecdh(NID_X9_62_prime256v1).is_ok());
        assert!(ec_key_copy_ecdh(NID_secp384r1).is_ok());
        assert!(ec_key_copy_ecdh(NID_secp521r1).is_ok());
    }

    #[test]
    fn test_attest_key() {
        let _e = load_engine();

        let report_data = [1u8; REPORT_DATA_SIZE as usize];

        let mut key_p256: EcKey<EcKeyData> = ec_key_keygen(NID_X9_62_prime256v1, false);
        let claim =
            ec_attest_key(key_p256.as_mut_ptr(), &report_data).expect("Could not attest key");
        assert!(!claim.is_empty());
        key_p256.free();

        let mut key_p384: EcKey<EcKeyData> = ec_key_keygen(NID_secp384r1, false);
        let claim =
            ec_attest_key(key_p384.as_mut_ptr(), &report_data).expect("Could not attest key");
        assert!(!claim.is_empty());
        key_p384.free();

        let mut key_p521: EcKey<EcKeyData> = ec_key_keygen(NID_secp521r1, false);
        let claim =
            ec_attest_key(key_p521.as_mut_ptr(), &report_data).expect("Could not attest key");
        assert!(!claim.is_empty());
        key_p521.free();
    }

    // Helper function for tests
    fn ec_key_ecdsa(curve_name: u32, dgst_len: usize, sig_len: u32) -> TestResult<()> {
        let mut ec_key = ec_key_keygen(curve_name, false);
        let dgst = vec![1u8; dgst_len];

        let sig = sign_cb(
            0,
            dgst.clone(),
            std::ptr::null(),
            std::ptr::null_mut(),
            ec_key.as_mut_ptr(),
        );
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert!(sig.clone().len() == sig_len as usize);

        let verify = verify_cb(0, dgst.clone(), sig, ec_key.as_mut_ptr());
        assert!(verify.is_ok());

        let sign_sig = sign_sig_cb(
            dgst.clone(),
            std::ptr::null(),
            std::ptr::null(),
            ec_key.as_mut_ptr(),
        )
        .expect("Could not sign data");

        let result = verify_sig_cb(dgst, sign_sig, ec_key.as_mut_ptr());
        assert!(result.is_ok());

        ec_key.free();
        Ecdsa_Sig::new_from_ptr(sign_sig).free();

        Ok(())
    }

    fn ec_key_copy_ecdsa(curve_name: u32, dgst_len: usize, sig_len: u32) -> TestResult<()> {
        let mut ec_key = ec_key_keygen(curve_name, false);
        let dgst = vec![1u8; dgst_len];

        // Sign with original key
        let sig = sign_cb(
            0,
            dgst.clone(),
            std::ptr::null(),
            std::ptr::null_mut(),
            ec_key.as_mut_ptr(),
        );
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert!(sig.clone().len() == sig_len as usize);

        let mut ec_key_copy: EcKey<EcKeyData> =
            EcKey::new().expect("could not create eckey object");
        assert!(ec_key_copy
            .set_key_group_by_name(curve_name as c_int)
            .is_ok());

        // Copy the private key data
        let result = copy_cb(ec_key_copy.as_mut_ptr(), ec_key.as_mut_ptr());
        assert!(result.is_ok());

        // Verify the copied key
        let verify = verify_cb(0, dgst.clone(), sig, ec_key_copy.as_mut_ptr());
        assert!(verify.is_ok());

        // Sign with original key
        let sign_sig = sign_sig_cb(
            dgst.clone(),
            std::ptr::null(),
            std::ptr::null(),
            ec_key.as_mut_ptr(),
        )
        .expect("Could not sign data");

        ec_key.free();

        // Verify with copied key
        let result = verify_sig_cb(dgst, sign_sig, ec_key_copy.as_mut_ptr());
        assert!(result.is_ok());

        // Free keys and Ecdsa sig
        ec_key_copy.free();
        Ecdsa_Sig::new_from_ptr(sign_sig).free();

        Ok(())
    }

    fn ec_key_keygen(curve_name: u32, ecdh: bool) -> EcKey<EcKeyData> {
        let key: EcKey<EcKeyData> = EcKey::new().expect("Could not create ECKey object");
        assert!(key.set_key_group_by_name(curve_name as c_int).is_ok());
        if ecdh {
            key.set_flags(key.flags() | EC_FLAG_COFACTOR_ECDH as i32)
        }
        let key_ptr = key.as_mut_ptr();
        assert!(keygen_cb(key_ptr).is_ok());
        key
    }

    fn ec_key_ecdh(curve_name: u32) -> TestResult<()> {
        let mut key1: EcKey<EcKeyData> = ec_key_keygen(curve_name, true);
        let mut key2: EcKey<EcKeyData> = ec_key_keygen(curve_name, true);

        let pubkey1 = key1.ec_point().expect("Could not get public key");
        let pubkey2 = key2.ec_point().expect("Could not get public key");

        let secret1 = compute_key_cb(&mut null_mut(), null_mut(), pubkey2, key1.as_mut_ptr())
            .expect("Could not derive secret2");
        assert!(secret1 != 0);

        let secret2 = compute_key_cb(&mut null_mut(), null_mut(), pubkey1, key2.as_mut_ptr())
            .expect("Could not derive secret2");
        assert!(secret2 != 0);

        assert_ne!(secret1, secret2);

        key1.free();
        key2.free();
        Ok(())
    }

    fn ec_key_copy_ecdh(curve_name: u32) -> TestResult<()> {
        let mut key1: EcKey<EcKeyData> = ec_key_keygen(curve_name, true);
        let mut key2: EcKey<EcKeyData> = ec_key_keygen(curve_name, true);

        // Retrieve the public key from the original key1.
        // Note: In OpenSSL, the public key is copied automatically when copying the private key.
        // Since we are not using OpenSSL's copy mechanism directly, the public key is not set
        // in the copied key in the private data copy (copy_cb) routine.
        let pubkey1 = key1.ec_point().expect("Could not get public key");
        let pubkey2 = key2.ec_point().expect("Could not get public key");

        // Copy key1 private key data to key1_copy
        let mut key1_copy: EcKey<EcKeyData> = EcKey::new().expect("could not create eckey object");
        assert!(key1_copy.set_key_group_by_name(curve_name as c_int).is_ok());
        copy_cb(key1_copy.as_mut_ptr(), key1.as_mut_ptr()).expect("Could not copy key");

        // Derive secret with key1_copy private key data and key2 public key
        let secret1 = compute_key_cb(&mut null_mut(), null_mut(), pubkey2, key1_copy.as_mut_ptr())
            .expect("Could not derive secret2");
        assert!(secret1 != 0);

        // Derive secret with key2 private key data and key1_copy (key1) public key
        let secret2 = compute_key_cb(&mut null_mut(), null_mut(), pubkey1, key2.as_mut_ptr())
            .expect("Could not derive secret2");
        assert!(secret2 != 0);

        assert_ne!(secret1, secret2);

        // Free keys and check refcount of hsm key handle
        let keydata = key1_copy
            .get_data()
            .expect("Could not get key data")
            .unwrap();
        assert_eq!(keydata.key_refcount(), 2);

        key1.free();
        assert_eq!(keydata.key_refcount(), 1);
        key1_copy.free();
        key2.free();
        Ok(())
    }

    fn load_engine() -> Engine {
        let engine = Engine::new_engine().expect("Could not make engine");
        let id = CString::new("azihsmengine").expect("Could not make id");
        let result = bind_helper(&engine, id.as_ref());
        assert!(result.is_ok());
        engine
    }
}

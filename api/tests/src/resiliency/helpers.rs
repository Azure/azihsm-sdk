// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared key-creation and crypto-operation helpers used by resiliency
//! test modules (fault-injection tests, stress tests).

use azihsm_api::*;

use crate::utils::partition::*;
use crate::utils::resiliency::*;

// Partition-init helpers

/// Open and init a partition with resiliency enabled, open a session,
/// and return all handles plus the RAII cleanup context.
pub(crate) fn init_with_resiliency_and_session() -> (HsmPartition, HsmSession, ResiliencyTestCtx) {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    let (resiliency_config, ctx) = make_resiliency_config(&part);
    part.init(
        creds,
        None,
        None,
        obk_info,
        pota_endorsement,
        Some(resiliency_config),
    )
    .expect("Partition init failed");

    let rev = part.api_rev_range().max();
    let session = part
        .open_session(rev, &creds, None)
        .expect("Failed to open session");

    (part, session, ctx)
}

/// Open and init a partition without resiliency, open a session.
#[cfg(feature = "res-test")]
pub(crate) fn init_without_resiliency_and_session() -> (HsmPartition, HsmSession) {
    let list = HsmPartitionManager::partition_info_list();
    assert!(!list.is_empty(), "No partitions found.");
    let part =
        HsmPartitionManager::open_partition(&list[0].path).expect("Failed to open partition");
    part.reset().expect("Partition reset failed");

    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (obk_info, pota_endorsement) = make_init_params(&part);
    part.init(creds, None, None, obk_info, pota_endorsement, None)
        .expect("Partition init failed");

    let rev = part.api_rev_range().max();
    let session = part
        .open_session(rev, &creds, None)
        .expect("Failed to open session");

    (part, session)
}

// Key-generation helpers

/// Generate an AES-256 session key for encryption/decryption tests.
pub(crate) fn generate_aes_key(session: &HsmSession) -> HsmAesKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES key props");
    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key")
}

/// Generate an ECC P-256 key pair for signing tests.
pub(crate) fn generate_ecc_sign_key_pair(
    session: &HsmSession,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair")
}

/// Generate an ECC key pair with derive capability for ECDH.
pub(crate) fn generate_ecc_derive_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair for ECDH")
}

/// Perform ECDH key derivation and return the shared secret.
pub(crate) fn ecdh_derive(
    session: &HsmSession,
    priv_key: &HsmEccPrivateKey,
    peer_pub_key: &HsmEccPublicKey,
) -> HsmResult<HsmGenericSecretKey> {
    let pub_key_der = peer_pub_key
        .pub_key_der_vec()
        .expect("Failed to get peer public key DER");
    let mut algo = EcdhAlgo::new(&pub_key_der);
    let bits = priv_key
        .ecc_curve()
        .expect("ECC curve missing")
        .key_size_bits() as u32;
    let secret_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build secret key props");
    HsmKeyManager::derive_key(session, &mut algo, priv_key, secret_props)
}

// Crypto-operation helpers

/// Hash data with SHA-256.
pub(crate) fn hash_data(session: &HsmSession, data: &[u8]) -> Vec<u8> {
    let mut hash_algo = HsmHashAlgo::Sha256;
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

/// AES-CBC encrypt with output buffer (length query + actual encrypt).
pub(crate) fn cbc_encrypt(key: &HsmAesKey, iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    let cipher_len = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; cipher_len];
    let written = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// AES-CBC decrypt with output buffer (length query + actual decrypt).
pub(crate) fn cbc_decrypt(key: &HsmAesKey, iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    let plain_len = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0u8; plain_len];
    let written = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// AES-CBC streaming encrypt: sends data in multiple chunks.
#[cfg(feature = "res-test")]
pub(crate) fn cbc_streaming_encrypt(
    key: &HsmAesKey,
    iv: &[u8],
    chunks: &[&[u8]],
) -> HsmResult<Vec<u8>> {
    let algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
    let mut ctx =
        HsmEncrypter::encrypt_init(algo, key.clone()).expect("Failed to init streaming encrypt");
    let mut out = Vec::new();
    for chunk in chunks {
        let needed = ctx.update(chunk, None)?;
        let mut buf = vec![0u8; needed];
        let written = ctx.update(chunk, Some(&mut buf))?;
        out.extend_from_slice(&buf[..written]);
    }
    let needed = ctx.finish(None)?;
    let mut buf = vec![0u8; needed];
    let written = ctx.finish(Some(&mut buf))?;
    out.extend_from_slice(&buf[..written]);
    Ok(out)
}

/// AES-CBC streaming decrypt: sends data in multiple chunks.
#[cfg(feature = "res-test")]
pub(crate) fn cbc_streaming_decrypt(
    key: &HsmAesKey,
    iv: &[u8],
    chunks: &[&[u8]],
) -> HsmResult<Vec<u8>> {
    let algo = HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
    let mut ctx =
        HsmDecrypter::decrypt_init(algo, key.clone()).expect("Failed to init streaming decrypt");
    let mut out = Vec::new();
    for chunk in chunks {
        let needed = ctx.update(chunk, None)?;
        let mut buf = vec![0u8; needed];
        let written = ctx.update(chunk, Some(&mut buf))?;
        out.extend_from_slice(&buf[..written]);
    }
    let needed = ctx.finish(None)?;
    let mut buf = vec![0u8; needed];
    let written = ctx.finish(Some(&mut buf))?;
    out.extend_from_slice(&buf[..written]);
    Ok(out)
}

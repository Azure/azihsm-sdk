// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use azihsmengine::common::rsa_key::RsaKeyData;
use azihsmengine::pkey::rsa::callback::rsa_sign_cb;
use azihsmengine::pkey::rsa::callback::rsa_sign_verify_ctx_init_cb;
use azihsmengine::pkey::rsa::callback::rsa_sign_verify_init_cb;
use azihsmengine::pkey::rsa::callback::rsa_signctx_cb;
use azihsmengine::pkey::rsa::callback::rsa_verify_cb;
use azihsmengine::pkey::rsa::callback::rsa_verifyctx_cb;
use common::import_key_wrapped;
use common::TEST_RSA_2K_PRIVATE_KEY;
use common::TEST_RSA_3K_PRIVATE_KEY;
use common::TEST_RSA_4K_PRIVATE_KEY;
use mcr_api::DigestKind;
use mcr_api::KeyUsage;
use mcr_api::RsaSignaturePadding;
use openssl_rust::safeapi::evp_md::ctx::EvpMdCtx;
use openssl_rust::safeapi::evp_md::md::EvpMd;
use openssl_rust::safeapi::evp_md::md::EvpMdType;
use openssl_rust::safeapi::evp_pkey::callback::common::SignCtxResult;
use openssl_rust::safeapi::rsa::RsaKey;

#[test]
fn test_sign_verify_2k_key_no_pad() {
    test_sign_verify(&TEST_RSA_2K_PRIVATE_KEY, None, None, None, 32, false, false);
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_2k_key_pkcs1_5() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_2k_key_pss() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_2k_key_no_pad_tampered_sig() {
    test_sign_verify(&TEST_RSA_2K_PRIVATE_KEY, None, None, None, 32, true, false);
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_2k_key_pkcs1_5_tampered_sig() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_2k_key_pss_tampered_sig() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_2k_key_no_pad_tampered_digest() {
    test_sign_verify(&TEST_RSA_2K_PRIVATE_KEY, None, None, None, 32, false, true);
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_2k_key_pkcs1_5_tampered_digest() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_2k_key_pss_tampered_digest() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_2k_key_no_pad_tampered_sig_digest() {
    test_sign_verify(&TEST_RSA_2K_PRIVATE_KEY, None, None, None, 32, true, true);
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_2k_key_pkcs1_5_tampered_sig_digest() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_2k_key_pss_tampered_sig_digest() {
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_2K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_2k_wrong_key_usage() {
    test_sign_verify_wrong_key_usage(&TEST_RSA_2K_PRIVATE_KEY);
}

#[test]
fn test_sign_verify_3k_key_no_pad() {
    test_sign_verify(&TEST_RSA_3K_PRIVATE_KEY, None, None, None, 32, false, false);
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_3k_key_pkcs1_5() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_3k_key_pss() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_3k_key_no_pad_tampered_sig() {
    test_sign_verify(&TEST_RSA_3K_PRIVATE_KEY, None, None, None, 32, true, false);
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_3k_key_pkcs1_5_tampered_sig() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_3k_key_pss_tampered_sig() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_3k_key_no_pad_tampered_digest() {
    test_sign_verify(&TEST_RSA_3K_PRIVATE_KEY, None, None, None, 32, false, true);
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_3k_key_pkcs1_5_tampered_digest() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_3k_key_pss_tampered_digest() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_3k_key_no_pad_tampered_sig_digest() {
    test_sign_verify(&TEST_RSA_3K_PRIVATE_KEY, None, None, None, 32, true, true);
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_3k_key_pkcs1_5_tampered_sig_digest() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_3k_key_pss_tampered_sig_digest() {
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_3K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_3k_wrong_key_usage() {
    test_sign_verify_wrong_key_usage(&TEST_RSA_3K_PRIVATE_KEY);
}

#[test]
fn test_sign_verify_4k_key_no_pad() {
    test_sign_verify(&TEST_RSA_4K_PRIVATE_KEY, None, None, None, 32, false, false);
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_4k_key_pkcs1_5() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_4k_key_pss() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_4k_key_no_pad_tampered_sig() {
    test_sign_verify(&TEST_RSA_4K_PRIVATE_KEY, None, None, None, 32, true, false);
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_4k_key_pkcs1_5_tampered_sig() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_4k_key_pss_tampered_sig() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        false,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_4k_key_no_pad_tampered_digest() {
    test_sign_verify(&TEST_RSA_4K_PRIVATE_KEY, None, None, None, 32, false, true);
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_4k_key_pkcs_1_5_tampered_digest() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_4k_key_pss_tampered_digest() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        false,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_4k_key_no_pad_tampered_sig_digest() {
    test_sign_verify(&TEST_RSA_4K_PRIVATE_KEY, None, None, None, 32, true, true);
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        None,
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_4k_key_pkcs1_5_tampered_sig_digest() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pkcs1_5),
        Some(u16::MAX),
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_4k_key_pss_tampered_sig_digest() {
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        None,
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha256),
        32,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha384),
        48,
        true,
        true,
    );
    test_sign_verify(
        &TEST_RSA_4K_PRIVATE_KEY,
        Some(RsaSignaturePadding::Pss),
        None,
        Some(DigestKind::Sha512),
        64,
        true,
        true,
    );
}

#[test]
fn test_sign_verify_4k_wrong_key_usage() {
    test_sign_verify_wrong_key_usage(&TEST_RSA_4K_PRIVATE_KEY);
}

#[test]
fn test_sign_verify_ctx_2k_key() {
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha256,
        256,
        false,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha384,
        256,
        false,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha512,
        256,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_ctx_2k_key_tampered_sig() {
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha256,
        256,
        true,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha384,
        256,
        true,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha512,
        256,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_ctx_2k_key_tampered_digest() {
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha256,
        256,
        false,
        true,
    );
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha384,
        256,
        false,
        true,
    );
    test_sign_verify_ctx(
        &TEST_RSA_2K_PRIVATE_KEY,
        EvpMdType::Sha512,
        256,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_ctx_2k_key_tampered_sig_digest() {
    test_sign_verify_ctx(&TEST_RSA_2K_PRIVATE_KEY, EvpMdType::Sha256, 256, true, true);
    test_sign_verify_ctx(&TEST_RSA_2K_PRIVATE_KEY, EvpMdType::Sha384, 256, true, true);
    test_sign_verify_ctx(&TEST_RSA_2K_PRIVATE_KEY, EvpMdType::Sha512, 256, true, true);
}

#[test]
fn test_sign_verify_ctx_2k_wrong_key_usage() {
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_2K_PRIVATE_KEY, EvpMdType::Sha256);
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_2K_PRIVATE_KEY, EvpMdType::Sha384);
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_2K_PRIVATE_KEY, EvpMdType::Sha512);
}

#[test]
fn test_sign_verify_ctx_3k_key() {
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha256,
        384,
        false,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha384,
        384,
        false,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha512,
        384,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_ctx_3k_key_tampered_sig() {
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha256,
        384,
        true,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha384,
        384,
        true,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha512,
        384,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_ctx_3k_key_tampered_digest() {
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha256,
        384,
        false,
        true,
    );
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha384,
        384,
        false,
        true,
    );
    test_sign_verify_ctx(
        &TEST_RSA_3K_PRIVATE_KEY,
        EvpMdType::Sha512,
        384,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_ctx_3k_key_tampered_sig_digest() {
    test_sign_verify_ctx(&TEST_RSA_3K_PRIVATE_KEY, EvpMdType::Sha256, 384, true, true);
    test_sign_verify_ctx(&TEST_RSA_3K_PRIVATE_KEY, EvpMdType::Sha384, 384, true, true);
    test_sign_verify_ctx(&TEST_RSA_3K_PRIVATE_KEY, EvpMdType::Sha512, 384, true, true);
}

#[test]
fn test_sign_verify_ctx_3k_wrong_key_usage() {
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_3K_PRIVATE_KEY, EvpMdType::Sha256);
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_3K_PRIVATE_KEY, EvpMdType::Sha384);
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_3K_PRIVATE_KEY, EvpMdType::Sha512);
}

#[test]
fn test_sign_verify_ctx_4k_key() {
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha256,
        512,
        false,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha384,
        512,
        false,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha512,
        512,
        false,
        false,
    );
}

#[test]
fn test_sign_verify_ctx_4k_key_tampered_sig() {
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha256,
        512,
        true,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha384,
        512,
        true,
        false,
    );
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha512,
        512,
        true,
        false,
    );
}

#[test]
fn test_sign_verify_ctx_4k_key_tampered_digest() {
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha256,
        512,
        false,
        true,
    );
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha384,
        512,
        false,
        true,
    );
    test_sign_verify_ctx(
        &TEST_RSA_4K_PRIVATE_KEY,
        EvpMdType::Sha512,
        512,
        false,
        true,
    );
}

#[test]
fn test_sign_verify_ctx_4k_key_tampered_sig_digest() {
    test_sign_verify_ctx(&TEST_RSA_4K_PRIVATE_KEY, EvpMdType::Sha256, 512, true, true);
    test_sign_verify_ctx(&TEST_RSA_4K_PRIVATE_KEY, EvpMdType::Sha384, 512, true, true);
    test_sign_verify_ctx(&TEST_RSA_4K_PRIVATE_KEY, EvpMdType::Sha512, 512, true, true);
}

#[test]
fn test_sign_verify_ctx_4k_wrong_key_usage() {
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_4K_PRIVATE_KEY, EvpMdType::Sha256);
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_4K_PRIVATE_KEY, EvpMdType::Sha384);
    test_sign_verify_ctx_wrong_key_usage(&TEST_RSA_4K_PRIVATE_KEY, EvpMdType::Sha512);
}

fn test_sign_verify(
    key: &[u8],
    padding_type: Option<RsaSignaturePadding>,
    salt_len: Option<u16>,
    hash_type: Option<DigestKind>,
    digest_len: usize,
    tamper_sig: bool,
    tamper_digest: bool,
) {
    let ctx = import_key_wrapped(key, KeyUsage::SignVerify);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().unwrap();
    let rsa_keydata = rsa.get_data().unwrap().unwrap();

    if let Some(padding) = padding_type {
        rsa_keydata.set_sig_padding(padding);
    }

    rsa_keydata.set_sig_salt_len(salt_len);
    rsa_keydata.set_hash_type(hash_type);

    rsa_sign_verify_init_cb(ctx.as_mut_ptr()).unwrap();

    let mut digest = vec![0xaau8; digest_len];
    let mut signature = rsa_sign_cb(ctx.as_mut_ptr(), &digest).unwrap();

    if tamper_sig {
        signature[0] ^= 0x1;
    }

    if tamper_digest {
        digest[0] ^= 0x1;
    }

    let result = rsa_verify_cb(ctx.as_mut_ptr(), &signature, &digest);
    if tamper_sig || tamper_digest {
        assert!(result.is_err(), "result {:?}", result);
    } else {
        assert!(result.is_ok());
    }
}

fn test_sign_verify_wrong_key_usage(key: &[u8]) {
    let ctx = import_key_wrapped(key, KeyUsage::EncryptDecrypt);

    rsa_sign_verify_init_cb(ctx.as_mut_ptr()).unwrap();

    let digest: [u8; 20] = [0xaa; 20];
    assert!(rsa_sign_cb(ctx.as_mut_ptr(), &digest).is_err());
}

fn test_sign_verify_ctx(
    key: &[u8],
    md_type: EvpMdType,
    digest_len: usize,
    tamper_sig: bool,
    tamper_digest: bool,
) {
    const TEST_DATA: &[u8] = b"All work and no play makes Jack a dull boy.";
    const TEST_DATA_TAMPER: &[u8] = b"All work and no play makes Jack a dull boy?";

    let ctx = import_key_wrapped(key, KeyUsage::SignVerify);

    let md = EvpMd::new(md_type);
    let md_ctx = EvpMdCtx::new().unwrap();

    md_ctx.digest_init(&md).unwrap();
    md_ctx.digest_update(TEST_DATA).unwrap();

    rsa_sign_verify_ctx_init_cb(ctx.as_mut_ptr(), md_ctx.as_mut_ptr()).unwrap();

    let expected_len = match rsa_signctx_cb(ctx.as_mut_ptr(), md_ctx.as_mut_ptr(), true).unwrap() {
        SignCtxResult::SigLen(len) => len,
        _ => panic!("Unexpected signctx result"),
    };
    assert_eq!(expected_len, digest_len);

    let mut signature = match rsa_signctx_cb(ctx.as_mut_ptr(), md_ctx.as_mut_ptr(), false).unwrap()
    {
        SignCtxResult::Sig(sig) => sig,
        _ => panic!("Unexpected signctx result"),
    };
    assert_eq!(signature.len(), expected_len);

    if tamper_sig {
        signature[0] ^= 0x1;
    }

    md_ctx.digest_init(&md).unwrap();
    if tamper_digest {
        md_ctx.digest_update(TEST_DATA_TAMPER).unwrap();
    } else {
        md_ctx.digest_update(TEST_DATA).unwrap();
    }

    rsa_sign_verify_ctx_init_cb(ctx.as_mut_ptr(), md_ctx.as_mut_ptr()).unwrap();
    let result = rsa_verifyctx_cb(ctx.as_mut_ptr(), &signature, md_ctx.as_mut_ptr());
    if tamper_digest || tamper_sig {
        assert!(result.is_err(), "result {:?}", result);
    } else {
        assert!(result.is_ok());
    }
}

fn test_sign_verify_ctx_wrong_key_usage(key: &[u8], md_type: EvpMdType) {
    const TEST_DATA: &[u8] = b"All work and no play makes Jack a dull boy.";

    let ctx = import_key_wrapped(key, KeyUsage::EncryptDecrypt);

    let md = EvpMd::new(md_type);
    let md_ctx = EvpMdCtx::new().unwrap();

    md_ctx.digest_init(&md).unwrap();
    md_ctx.digest_update(TEST_DATA).unwrap();

    rsa_sign_verify_ctx_init_cb(ctx.as_mut_ptr(), md_ctx.as_mut_ptr()).unwrap();

    // Signing should not work
    assert!(rsa_signctx_cb(ctx.as_mut_ptr(), md_ctx.as_mut_ptr(), false).is_err());
}

// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::safeapi::error::*;
use crate::safeapi::evp_pkey::callback::ec::*;
use crate::safeapi::evp_pkey::callback::hkdf::*;
use crate::safeapi::evp_pkey::callback::rsa::*;
use crate::EVP_PKEY_CTX;

pub type PKeyCtrlStrFn = fn(*mut EVP_PKEY_CTX, Vec<u8>) -> OpenSSLResult<()>;

pub enum PKeyInitFn {
    Ec(EcInitFn),
}

pub enum PKeyCopyFn {
    Ec(EcCopyFn),
    Rsa(RsaCopyFn),
}

pub enum PKeyCleanupFn {
    Rsa(RsaCleanupFn),
    Hkdf(HkdfCleanupFn),
    Ec(EcCleanupFn),
}

pub enum PKeyParamgenInitFn {
    Rsa(RsaParamGenInitFn),
    Ec(EcParamGenInitFn),
}

pub enum PKeyParamGenFn {
    Rsa(RsaParamGenFn),
    Ec(EcParamGenFn),
}

pub enum PKeyGenInitFn {
    Rsa(RsaKeyGenInitFn),
    Ec(EcKeyGenInitFn),
}

pub enum PKeyGenFn {
    Rsa(RsaKeyGenFn),
    Ec(EcKeyGenFn),
}

pub enum PKeyEncDecInitFn {
    Rsa(RsaEncDecInitFn),
}

pub enum PKeyEncDecFn {
    Rsa(RsaEncDecFn),
}

pub enum PKeySignVerifyInitFn {
    Rsa(RsaSignVerifyInitFn),
    Ec(EcSignVerifyInitFn),
}

pub enum PKeySignCtxInitFn {
    Rsa(RsaSignCtxInitFn),
    Ec(EcSignCtxInitFn),
}

pub enum PKeyVerifyCtxInitFn {
    Rsa(RsaVerifyCtxInitFn),
    Ec(EcVerifyCtxInitFn),
}

pub enum PKeySignFn {
    Rsa(RsaSignFn),
    Ec(EcSignFn),
}

pub enum PKeySignCtxFn {
    Rsa(RsaSignCtxFn),
    Ec(EcSignCtxFn),
}

pub enum PKeyVerifyFn {
    Rsa(RsaVerifyFn),
    Ec(EcVerifyFn),
}

pub enum PKeyVerifyCtxFn {
    Rsa(RsaVerifyCtxFn),
    Ec(EcVerifyCtxFn),
}

pub enum PKeyDeriveInitFn {
    Hkdf(HkdfDeriveInitFn),
    Ec(EcDeriveInitFn),
}

pub enum PKeyDeriveFn {
    Hkdf(HkdfDeriveFn),
    Ec(EcDeriveFn),
}

pub enum PKeyCtrlFn {
    Rsa(RsaCtrlFn),
    Hkdf(HkdfCtrlFn),
    Ec(EcCtrlFn),
}

pub enum SignCtxResult {
    SigLen(usize),
    Sig(Vec<u8>),
}

//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#pragma once

#include <openssl/obj_mac.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Provider algorithm names
//

// Digests
#define AZIHSM_OSSL_ALG_NAME_SHA1 SN_sha1":SHA-1:SSL3-SHA1:1.3.14.3.2.26"
#define AZIHSM_OSSL_ALG_NAME_SHA256 SN_sha256":SHA2-256:SHA-256:2.16.840.1.101.3.4.2.1"
#define AZIHSM_OSSL_ALG_NAME_SHA384 SN_sha384":SHA2-384:SHA-384:2.16.840.1.101.3.4.2.2"
#define AZIHSM_OSSL_ALG_NAME_SHA512 SN_sha512":SHA2-512:SHA-512:2.16.840.1.101.3.4.2.3"

// Ciphers
#define AZIHSM_OSSL_ALG_NAME_AES_128_CBC SN_aes_128_cbc":AES-128-CBC:2.16.840.1.101.3.4.1.2"
#define AZIHSM_OSSL_ALG_NAME_AES_192_CBC SN_aes_192_cbc":AES-192-CBC:2.16.840.1.101.3.4.1.22"
#define AZIHSM_OSSL_ALG_NAME_AES_256_CBC SN_aes_256_cbc":AES-256-CBC:2.16.840.1.101.3.4.1.42"
#define AZIHSM_OSSL_ALG_NAME_AES_128_XTS SN_aes_128_xts":AES-128-XTS:1.3.111.2.1619.0.1.1"
#define AZIHSM_OSSL_ALG_NAME_AES_256_XTS SN_aes_256_xts":AES-256-XTS:1.3.111.2.1619.0.1.2"

// MAC
#define AZIHSM_OSSL_ALG_NAME_HMAC SN_hmac":HMAC"

// KDF
#define AZIHSM_OSSL_ALG_NAME_HKDF "HKDF:" SN_hkdf
#define AZIHSM_OSSL_ALG_NAME_KBKDF "KBKDF"

// Key Management
#define AZIHSM_OSSL_ALG_NAME_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define AZIHSM_OSSL_ALG_NAME_RSA_PSS "RSA-PSS:" SN_rsassaPss ":1.2.840.113549.1.1.10"
#define AZIHSM_OSSL_ALG_NAME_EC "EC:" SN_X9_62_id_ecPublicKey ":1.2.840.10045.2.1"

// Key Exchange
#define AZIHSM_OSSL_ALG_NAME_ECDH "ECDH"

// Signature
#define AZIHSM_OSSL_ALG_NAME_ECDSA "ECDSA"

#ifdef __cplusplus
}
#endif

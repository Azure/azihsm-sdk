/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>

/* Constants defined as macros that bindgen cannot discover automatically. */
/* Re-export them as typed C constants so bindgen emits them.              */
static const unsigned long OSSL_DYNAMIC_VERSION_CONST = OSSL_DYNAMIC_VERSION;
static const unsigned long OSSL_DYNAMIC_OLDEST_CONST  = OSSL_DYNAMIC_OLDEST;
static const int EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID_CONST =
    EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID;
static const int EVP_PKEY_CTRL_HKDF_MD_CONST   = EVP_PKEY_CTRL_HKDF_MD;
static const int EVP_PKEY_CTRL_HKDF_SALT_CONST = EVP_PKEY_CTRL_HKDF_SALT;
static const int EVP_PKEY_CTRL_HKDF_KEY_CONST  = EVP_PKEY_CTRL_HKDF_KEY;
static const int EVP_PKEY_CTRL_HKDF_INFO_CONST = EVP_PKEY_CTRL_HKDF_INFO;
static const int EVP_PKEY_CTRL_HKDF_MODE_CONST = EVP_PKEY_CTRL_HKDF_MODE;

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
static const int EVP_PKEY_CTRL_RSA_KEYGEN_BITS_CONST =
    EVP_PKEY_CTRL_RSA_KEYGEN_BITS;
static const int EVP_PKEY_OP_KEYGEN_CONST = EVP_PKEY_OP_KEYGEN;
static const int EVP_PKEY_FLAG_AUTOARGLEN_CONST = EVP_PKEY_FLAG_AUTOARGLEN;
static const int EVP_PKEY_CTRL_MD_CONST = EVP_PKEY_CTRL_MD;
static const int EVP_PKEY_OP_TYPE_SIG_CONST = EVP_PKEY_OP_TYPE_SIG;
static const int RSA_FLAG_FIPS_METHOD_CONST = RSA_FLAG_FIPS_METHOD;
/* RSA signature ctx getters (macros) used by the PSS sign path. */
static const int EVP_PKEY_CTRL_GET_MD_CONST = EVP_PKEY_CTRL_GET_MD;
static const int EVP_PKEY_CTRL_GET_RSA_PADDING_CONST = EVP_PKEY_CTRL_GET_RSA_PADDING;
static const int EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN_CONST =
    EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN;
static const int EVP_PKEY_CTRL_GET_RSA_MGF1_MD_CONST = EVP_PKEY_CTRL_GET_RSA_MGF1_MD;
static const int EVP_PKEY_CTRL_RSA_PSS_SALTLEN_CONST = EVP_PKEY_CTRL_RSA_PSS_SALTLEN;
static const int RSA_PKCS1_PSS_PADDING_CONST = RSA_PKCS1_PSS_PADDING;
/* RSA asym-cipher (decrypt) ctx getters and padding constants. */
static const int EVP_PKEY_OP_TYPE_CRYPT_CONST = EVP_PKEY_OP_TYPE_CRYPT;
static const int EVP_PKEY_CTRL_GET_RSA_OAEP_MD_CONST = EVP_PKEY_CTRL_GET_RSA_OAEP_MD;
static const int EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL_CONST =
    EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL;
static const int RSA_PKCS1_PADDING_CONST = RSA_PKCS1_PADDING;
static const int RSA_PKCS1_OAEP_PADDING_CONST = RSA_PKCS1_OAEP_PADDING;

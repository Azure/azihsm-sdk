// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#include "azihsm_ossl_helpers.h"

#ifdef __cplusplus
extern "C"
{
#endif

// Value provided by CMake, defined in top level CMakeLists.txt
#define AZIHSM_OSSL_VERSION ""
#define AZIHSM_OSSL_NAME "azihsm"

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

typedef _Return_type_success_(return == 1) int OSSL_STATUS;
#define OSSL_SUCCESS (1)
#define OSSL_FAILURE (0)

typedef struct
{
    azihsm_handle priv;
} AZIHSM_KEY_OBJ;

typedef struct
{
    azihsm_handle pub;
    azihsm_handle priv;
} AZIHSM_KEY_PAIR_OBJ;

/* Default file paths for partition keys */
#define AZIHSM_DEFAULT_BMK_PATH "/var/lib/azihsm/bmk.bin"
#define AZIHSM_DEFAULT_MUK_PATH "/var/lib/azihsm/muk.bin"
#define AZIHSM_DEFAULT_OBK_PATH "/var/lib/azihsm/obk.bin"

typedef struct
{
    char bmk_path[4096];
    char muk_path[4096];
    char obk_path[4096];
} AZIHSM_CONFIG;

typedef struct
{
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *handle;
    azihsm_handle device;
    azihsm_handle session;
    AZIHSM_CONFIG config;
    struct
    {
        CRYPTO_RWLOCK *lock;
        azihsm_handle pub;
        azihsm_handle priv;
    } unwrapping_key; /* Cached MUK handles (thread-safe) */
} AZIHSM_OSSL_PROV_CTX;

static const OSSL_PARAM azihsm_ossl_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END
};

// EVP_MD_CTX_dup is a helpful function for the provider, but was not added until OpenSSL 3.1
// This function is copied from 3.1 to allow its use when the provider is built against 3.0
#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0
EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in);

#endif // OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0

#ifdef __cplusplus
}
#endif

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <stdbool.h>
#include <stdint.h>

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

/* Maximum file path length for key and config file paths */
#define AZIHSM_MAX_FILE_PATH 4096

/* Default file paths for partition keys, credentials, and POTA keys */
#define AZIHSM_DEFAULT_BMK_PATH "/var/lib/azihsm/bmk.bin"
#define AZIHSM_DEFAULT_MUK_PATH "/var/lib/azihsm/muk.bin"
#define AZIHSM_DEFAULT_OBK_PATH "/var/lib/azihsm/obk.bin"
#define AZIHSM_DEFAULT_CREDENTIALS_ID_PATH "/var/lib/azihsm/credentials_id.bin"
#define AZIHSM_DEFAULT_CREDENTIALS_PIN_PATH "/var/lib/azihsm/credentials_pin.bin"
#define AZIHSM_DEFAULT_POTA_PRIVATE_KEY_PATH "/var/lib/azihsm/pota_private_key.der"
#define AZIHSM_DEFAULT_POTA_PUBLIC_KEY_PATH "/var/lib/azihsm/pota_public_key.der"

/* Size of binary credential files (ID and PIN) in bytes */
#define AZIHSM_CREDENTIALS_SIZE 16

/* Configuration parameter names for openssl.cnf */
#define AZIHSM_CFG_BMK_PATH "azihsm-bmk-path"
#define AZIHSM_CFG_MUK_PATH "azihsm-muk-path"
#define AZIHSM_CFG_OBK_PATH "azihsm-obk-path"
#define AZIHSM_CFG_OBK_SOURCE "azihsm-obk-source"
#define AZIHSM_CFG_POTA_SOURCE "azihsm-pota-source"
#define AZIHSM_CFG_POTA_PRIVATE_KEY_PATH "azihsm-pota-private-key-path"
#define AZIHSM_CFG_POTA_PUBLIC_KEY_PATH "azihsm-pota-public-key-path"
#define AZIHSM_CFG_API_REVISION "azihsm-api-revision"

/* Environment variable names for credentials (not in openssl.cnf for security) */
#define AZIHSM_ENV_CREDENTIALS_ID_PATH "AZIHSM_CREDENTIALS_ID_PATH"
#define AZIHSM_ENV_CREDENTIALS_PIN_PATH "AZIHSM_CREDENTIALS_PIN_PATH"

/* Supported API revision range */
#define AZIHSM_API_REVISION_MIN_MAJOR 1
#define AZIHSM_API_REVISION_MIN_MINOR 0
#define AZIHSM_API_REVISION_MAX_MAJOR 1
#define AZIHSM_API_REVISION_MAX_MINOR 0
#define AZIHSM_API_REVISION_DEFAULT_MAJOR 1
#define AZIHSM_API_REVISION_DEFAULT_MINOR 0

typedef struct
{
    char bmk_path[AZIHSM_MAX_FILE_PATH];
    char muk_path[AZIHSM_MAX_FILE_PATH];
    char obk_path[AZIHSM_MAX_FILE_PATH];
    char credentials_id_path[AZIHSM_MAX_FILE_PATH];
    char credentials_pin_path[AZIHSM_MAX_FILE_PATH];
    char pota_private_key_path[AZIHSM_MAX_FILE_PATH];
    char pota_public_key_path[AZIHSM_MAX_FILE_PATH];
    uint16_t api_revision_major;
    uint16_t api_revision_minor;
    bool use_tpm_obk;
    bool use_tpm_pota;
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
    } unwrapping_key; /* Cached UK handles (thread-safe) */
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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

typedef _Return_type_success_(return == 1) int OSSL_STATUS;

// Macros giving readable name to return values in functions returning OSSL_STATUS
#define OSSL_SUCCESS (1)
#define OSSL_FAILURE (0)

/* Helper function: Convert OpenSSL EVP_MD to AZIHSM bare hash algorithm ID */
static inline azihsm_algo_id azihsm_ossl_evp_md_to_algo_id(const EVP_MD *md)
{
    int type;

    if (md == NULL)
        return 0;

    type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        return AZIHSM_ALGO_ID_SHA1;
    case NID_sha256:
        return AZIHSM_ALGO_ID_SHA256;
    case NID_sha384:
        return AZIHSM_ALGO_ID_SHA384;
    case NID_sha512:
        return AZIHSM_ALGO_ID_SHA512;
    default:
        return 0;
    }
}

/* Helper function: Convert OpenSSL EVP_MD to ECDSA+Hash combined algorithm ID */
static inline azihsm_algo_id azihsm_ossl_evp_md_to_ecdsa_algo_id(const EVP_MD *md)
{
    int type;

    if (md == NULL)
        return 0;

    type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        return AZIHSM_ALGO_ID_ECDSA_SHA1;
    case NID_sha256:
        return AZIHSM_ALGO_ID_ECDSA_SHA256;
    case NID_sha384:
        return AZIHSM_ALGO_ID_ECDSA_SHA384;
    case NID_sha512:
        return AZIHSM_ALGO_ID_ECDSA_SHA512;
    default:
        return 0;
    }
}

/* Helper function: Convert OpenSSL EVP_MD to RSA PKCS#1 v1.5 + Hash combined algorithm ID */
static inline azihsm_algo_id azihsm_ossl_evp_md_to_rsa_pkcs_algo_id(const EVP_MD *md)
{
    int type;

    if (md == NULL)
        return 0;

    type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        return AZIHSM_ALGO_ID_RSA_PKCS_SHA1;
    case NID_sha256:
        return AZIHSM_ALGO_ID_RSA_PKCS_SHA256;
    case NID_sha384:
        return AZIHSM_ALGO_ID_RSA_PKCS_SHA384;
    case NID_sha512:
        return AZIHSM_ALGO_ID_RSA_PKCS_SHA512;
    default:
        return 0;
    }
}

/* Helper function: Convert OpenSSL EVP_MD to RSA-PSS + Hash combined algorithm ID */
static inline azihsm_algo_id azihsm_ossl_evp_md_to_rsa_pss_algo_id(const EVP_MD *md)
{
    int type;

    if (md == NULL)
        return 0;

    type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        return AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1;
    case NID_sha256:
        return AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256;
    case NID_sha384:
        return AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384;
    case NID_sha512:
        return AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512;
    default:
        return 0;
    }
}

/* Helper function: Convert OpenSSL EVP_MD to MGF1 ID for PSS/OAEP */
static inline azihsm_mgf1_id azihsm_ossl_evp_md_to_mgf1_id(const EVP_MD *md)
{
    int type;

    if (md == NULL)
        return 0;

    type = EVP_MD_type(md);

    switch (type)
    {
    case NID_sha1:
        return AZIHSM_MGF1_ID_SHA1;
    case NID_sha256:
        return AZIHSM_MGF1_ID_SHA256;
    case NID_sha384:
        return AZIHSM_MGF1_ID_SHA384;
    case NID_sha512:
        return AZIHSM_MGF1_ID_SHA512;
    default:
        return 0;
    }
}

/* Helper function: Get default salt length for a hash algorithm (equals hash output size) */
static inline uint32_t azihsm_ossl_evp_md_to_salt_len(const EVP_MD *md)
{
    if (md == NULL)
        return 0;

    return (uint32_t)EVP_MD_size(md);
}

/*
 * Release a streaming HSM operation context handle if active, then
 * clear the caller's copy.  Safe to call when *handle_ptr == 0 (no-op).
 *
 * This wraps the AZIHSM API function azihsm_free_ctx_handle(), which
 * frees HSM-internal resources for streaming crypto operations (digest,
 * sign, verify, encrypt, decrypt).  It does NOT apply to provider-level
 * context structs (AZIHSM_OSSL_PROV_CTX) or key handles.
 */
static inline void azihsm_ossl_release_hsm_ctx(azihsm_handle *handle_ptr)
{
    if (*handle_ptr != 0)
    {
        azihsm_free_ctx_handle(*handle_ptr);
        *handle_ptr = 0;
    }
}

/*
 * Normalize a private key DER blob to PKCS#8 format.
 *
 * The HSM expects PKCS#8 (PrivateKeyInfo) DER encoding. Users may provide
 * keys in traditional format (e.g. SEC1 for EC, PKCS#1 for RSA) or PKCS#8.
 * This function auto-detects the format and re-encodes as PKCS#8 DER if needed.
 *
 * @in_buf     Input DER bytes (traditional or PKCS#8)
 * @in_len     Length of input
 * @out_buf    Output PKCS#8 DER buffer (caller must OPENSSL_free)
 * @out_len    Output length
 *
 * @returns OSSL_SUCCESS (1) on success, OSSL_FAILURE (0) on failure
 */
OSSL_STATUS azihsm_ossl_normalize_der_to_pkcs8(
    const uint8_t *in_buf,
    long in_len,
    uint8_t **out_buf,
    int *out_len
);

#ifdef __cplusplus
}
#endif

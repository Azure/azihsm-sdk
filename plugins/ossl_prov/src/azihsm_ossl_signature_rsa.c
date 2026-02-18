// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <limits.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_signature_rsa.h"

/**
 * Get the RSA signature size based on key bit length.
 * RSA signature size equals the key size in bytes.
 *
 * @param key_bits The RSA key size in bits
 * @return Signature size in bytes
 */
static size_t azihsm_ossl_rsa_signature_size(uint32_t key_bits)
{
    return key_bits / 8;
}

/* ═══════════════════════════════════════════════════════════════════════════
   RSA SIGNATURE CONTEXT LIFECYCLE
   ═══════════════════════════════════════════════════════════════════════════ */

static void *azihsm_ossl_rsa_newctx(void *provctx, ossl_unused const char *propq)
{
    azihsm_rsa_sig_ctx *ctx;
    AZIHSM_OSSL_PROV_CTX *prov = (AZIHSM_OSSL_PROV_CTX *)provctx;

    if (prov == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = prov;
    ctx->sign_ctx = 0; /* No streaming context yet */

    /* Default to PKCS#1 v1.5 padding */
    ctx->pad_mode = AZIHSM_RSA_PAD_MODE_PKCSV15;
    ctx->mgf1_md = NULL;                           /* Will default to same as md */
    ctx->salt_len = AZIHSM_RSA_PSS_SALTLEN_DIGEST; /* Default: salt = hash length */

    return ctx;
}

static void azihsm_ossl_rsa_freectx(void *sctx)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;

    if (ctx == NULL)
        return;

    /* Note: Don't free key - caller owns it */
    OPENSSL_free(ctx);
}

static void *azihsm_ossl_rsa_dupctx(void *sctx)
{
    azihsm_rsa_sig_ctx *src_ctx = (azihsm_rsa_sig_ctx *)sctx;
    azihsm_rsa_sig_ctx *dst_ctx;

    if (src_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    dst_ctx = OPENSSL_zalloc(sizeof(*dst_ctx));
    if (dst_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy all fields INCLUDING sign_ctx handle */
    *dst_ctx = *src_ctx;

    return dst_ctx;
}

/* ═══════════════════════════════════════════════════════════════════════════
   RSA ONE-SHOT OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_rsa_sign_init(void *sctx, void *provkey, const OSSL_PARAM params[])
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_RSA_KEY *)provkey;

    /* Verify the key has a private component for signing */
    if (!ctx->key->has_private)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return OSSL_FAILURE;
    }

    ctx->operation = 1; /* Sign */

    /* Set default hash algorithm if not already set */
    if (ctx->md == NULL)
    {
        ctx->md = EVP_sha256();
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_sign(
    void *sctx,
    unsigned char *sig,
    size_t *siglen,
    size_t sigsize,
    const unsigned char *tbs,
    size_t tbslen
)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_algo_rsa_pkcs_pss_params pss_params;
    struct azihsm_buffer data_buf, sig_buf;
    azihsm_status status;
    int use_pss;

    if (ctx == NULL || ctx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (tbslen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Determine if PSS mode: either key type is RSA-PSS or pad_mode is PSS */
    use_pss = (ctx->key->genctx.key_type == AIHSM_KEY_TYPE_RSA_PSS) ||
              (ctx->pad_mode == AZIHSM_RSA_PAD_MODE_PSS);

    if (use_pss)
    {
        /* Build PSS parameters - input is raw hash, not DigestInfo */
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->md;

        pss_params.hash_algo_id = azihsm_ossl_evp_md_to_algo_id(ctx->md);
        pss_params.mgf_id = azihsm_ossl_evp_md_to_mgf1_id(mgf1_md);

        /* Resolve salt length */
        if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_DIGEST)
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }
        else if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_MAX)
        {
            uint32_t key_bytes = ctx->key->genctx.pubkey_bits / 8;
            uint32_t hash_size = (uint32_t)EVP_MD_size(ctx->md);
            pss_params.salt_len = key_bytes - hash_size - 2;
        }
        else if (ctx->salt_len >= 0)
        {
            pss_params.salt_len = (uint32_t)ctx->salt_len;
        }
        else
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }

        algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS;
        algo.params = &pss_params;
        algo.len = sizeof(pss_params);
    }
    else
    {
        /*
         * One-shot signing with PKCS#1 v1.5 padding is not supported by the HSM.
         * The HSM API only supports pre-hashed input for RSA-PSS (AZIHSM_ALGO_ID_RSA_PKCS_PSS).
         * For PKCS#1 v1.5, use streaming sign (dgst -sign) which passes raw message data
         * to hash-specific algorithms like AZIHSM_ALGO_ID_RSA_PKCS_SHA256.
         */
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            "one-shot PKCS#1 v1.5 signing not supported; use dgst -sign or RSA-PSS key"
        );
        return OSSL_FAILURE;
    }

    /* Set up data buffer */
    data_buf.ptr = (uint8_t *)tbs;
    data_buf.len = (uint32_t)tbslen;

    /* Size query: ask the HSM for the required signature buffer size */
    if (sig == NULL)
    {
        sig_buf.ptr = NULL;
        sig_buf.len = 0;
        status = azihsm_crypt_sign(&algo, ctx->key->key.priv, &data_buf, &sig_buf);
        if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || sig_buf.len == 0)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }
        *siglen = sig_buf.len;
        return OSSL_SUCCESS;
    }

    /* Bounds check for signature buffer size */
    if (sigsize > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Set up signature buffer and sign */
    sig_buf.ptr = sig;
    sig_buf.len = (uint32_t)sigsize;

    status = azihsm_crypt_sign(&algo, ctx->key->key.priv, &data_buf, &sig_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    *siglen = sig_buf.len;
    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_verify_init(void *sctx, void *provkey, const OSSL_PARAM params[])
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_RSA_KEY *)provkey;
    ctx->operation = 0; /* Verify */

    /* Set default hash algorithm if not already set */
    if (ctx->md == NULL)
    {
        ctx->md = EVP_sha256();
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_verify(
    void *sctx,
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *tbs,
    size_t tbslen
)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_algo_rsa_pkcs_pss_params pss_params;
    struct azihsm_buffer data_buf, sig_buf;
    azihsm_status status;
    int use_pss;

    if (ctx == NULL || ctx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (tbslen > UINT32_MAX || siglen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Determine if PSS mode: either key type is RSA-PSS or pad_mode is PSS */
    use_pss = (ctx->key->genctx.key_type == AIHSM_KEY_TYPE_RSA_PSS) ||
              (ctx->pad_mode == AZIHSM_RSA_PAD_MODE_PSS);

    if (use_pss)
    {
        /* Build PSS parameters */
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->md;

        pss_params.hash_algo_id = azihsm_ossl_evp_md_to_algo_id(ctx->md);
        pss_params.mgf_id = azihsm_ossl_evp_md_to_mgf1_id(mgf1_md);

        /* Resolve salt length for verify */
        if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_DIGEST ||
            ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_AUTO)
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }
        else if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_MAX)
        {
            uint32_t key_bytes = ctx->key->genctx.pubkey_bits / 8;
            uint32_t hash_size = (uint32_t)EVP_MD_size(ctx->md);
            pss_params.salt_len = key_bytes - hash_size - 2;
        }
        else if (ctx->salt_len >= 0)
        {
            pss_params.salt_len = (uint32_t)ctx->salt_len;
        }
        else
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }

        algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS;
        algo.params = &pss_params;
        algo.len = sizeof(pss_params);
    }
    else
    {
        /* Use raw RSA PKCS#1 */
        algo.id = AZIHSM_ALGO_ID_RSA_PKCS;
        algo.params = NULL;
        algo.len = 0;
    }

    /* Set up buffers */
    data_buf.ptr = (uint8_t *)tbs;
    data_buf.len = (uint32_t)tbslen;
    sig_buf.ptr = (uint8_t *)sig;
    sig_buf.len = (uint32_t)siglen;

    status = azihsm_crypt_verify(&algo, ctx->key->key.pub, &data_buf, &sig_buf);

    if (status == AZIHSM_STATUS_SUCCESS)
    {
        return OSSL_SUCCESS;
    }
    else if (status == AZIHSM_STATUS_INVALID_SIGNATURE)
    {
        return OSSL_FAILURE;
    }

    ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
    return OSSL_FAILURE;
}

/* ═══════════════════════════════════════════════════════════════════════════
   RSA STREAMING OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_rsa_digest_sign_init(
    void *sctx,
    const char *mdname,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_algo_rsa_pkcs_pss_params pss_params;
    azihsm_status status;
    int use_pss;

    if (provkey == NULL)
    {
        /* Silently succeed - this is a cleanup/reset operation */
        return OSSL_SUCCESS;
    }

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_RSA_KEY *)provkey;

    /* Verify the key has a private component for signing */
    if (!ctx->key->has_private)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return OSSL_FAILURE;
    }

    ctx->operation = 1; /* Sign */

    /* Get hash algorithm by name */
    ctx->md = EVP_get_digestbyname(mdname);
    if (ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Determine if PSS mode: either key type is RSA-PSS or pad_mode is PSS */
    use_pss = (ctx->key->genctx.key_type == AIHSM_KEY_TYPE_RSA_PSS) ||
              (ctx->pad_mode == AZIHSM_RSA_PAD_MODE_PSS);

    if (use_pss)
    {
        /* Build PSS parameters */
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->md;

        pss_params.hash_algo_id = azihsm_ossl_evp_md_to_algo_id(ctx->md);
        pss_params.mgf_id = azihsm_ossl_evp_md_to_mgf1_id(mgf1_md);

        /* Resolve salt length */
        if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_DIGEST)
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }
        else if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_MAX)
        {
            /* Max salt = key_size - hash_size - 2 */
            uint32_t key_bytes = ctx->key->genctx.pubkey_bits / 8;
            uint32_t hash_size = (uint32_t)EVP_MD_size(ctx->md);
            pss_params.salt_len = key_bytes - hash_size - 2;
        }
        else if (ctx->salt_len >= 0)
        {
            pss_params.salt_len = (uint32_t)ctx->salt_len;
        }
        else
        {
            /* Default to hash size for other special values */
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }

        algo.id = azihsm_ossl_evp_md_to_rsa_pss_algo_id(ctx->md);
        algo.params = &pss_params;
        algo.len = sizeof(pss_params);
    }
    else
    {
        /* PKCS#1 v1.5 mode */
        algo.id = azihsm_ossl_evp_md_to_rsa_pkcs_algo_id(ctx->md);
        algo.params = NULL;
        algo.len = 0;
    }

    if (algo.id == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    status = azihsm_crypt_sign_init(&algo, ctx->key->key.priv, &ctx->sign_ctx);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_digest_sign_update(void *sctx, const unsigned char *data, size_t datalen)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (datalen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Set up buffer */
    data_buf.ptr = (uint8_t *)data;
    data_buf.len = (uint32_t)datalen;

    /* Update streaming sign with raw data */
    status = azihsm_crypt_sign_update(ctx->sign_ctx, &data_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_digest_sign_final(
    void *sctx,
    unsigned char *sig,
    size_t *siglen,
    size_t sigsize
)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_buffer sig_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* If sig is NULL, caller is querying for signature size */
    if (sig == NULL)
    {
        /* Return exact size for this key if known, otherwise max size */
        if (ctx->key == NULL)
        {
            *siglen = 512; /* Max size for RSA-4096 */
        }
        else
        {
            *siglen = azihsm_ossl_rsa_signature_size(ctx->key->genctx.pubkey_bits);
        }
        return OSSL_SUCCESS;
    }

    /* Query the HSM for the exact signature size */
    sig_buf.ptr = NULL;
    sig_buf.len = 0;
    status = azihsm_crypt_sign_finish(ctx->sign_ctx, &sig_buf);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || sig_buf.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ctx->sign_ctx = 0;
        return OSSL_FAILURE;
    }

    /* Verify OpenSSL provided enough space */
    if (sigsize < sig_buf.len)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        ctx->sign_ctx = 0;
        return OSSL_FAILURE;
    }

    /* Finish streaming sign with exact size required by HSM */
    sig_buf.ptr = sig;
    status = azihsm_crypt_sign_finish(ctx->sign_ctx, &sig_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        ctx->sign_ctx = 0;
        return OSSL_FAILURE;
    }

    *siglen = sig_buf.len;
    ctx->sign_ctx = 0; /* Context consumed */
    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_digest_verify_init(
    void *sctx,
    const char *mdname,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_algo_rsa_pkcs_pss_params pss_params;
    azihsm_status status;
    int use_pss;

    if (provkey == NULL)
    {
        /* Silently succeed - this is a cleanup/reset operation */
        return OSSL_SUCCESS;
    }

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_RSA_KEY *)provkey;
    ctx->operation = 0; /* Verify */

    /* Get hash algorithm by name */
    ctx->md = EVP_get_digestbyname(mdname);
    if (ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Determine if PSS mode: either key type is RSA-PSS or pad_mode is PSS */
    use_pss = (ctx->key->genctx.key_type == AIHSM_KEY_TYPE_RSA_PSS) ||
              (ctx->pad_mode == AZIHSM_RSA_PAD_MODE_PSS);

    if (use_pss)
    {
        /* Build PSS parameters */
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->md;

        pss_params.hash_algo_id = azihsm_ossl_evp_md_to_algo_id(ctx->md);
        pss_params.mgf_id = azihsm_ossl_evp_md_to_mgf1_id(mgf1_md);

        /* Resolve salt length for verify (auto-detect if SALTLEN_AUTO) */
        if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_DIGEST ||
            ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_AUTO)
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }
        else if (ctx->salt_len == AZIHSM_RSA_PSS_SALTLEN_MAX)
        {
            uint32_t key_bytes = ctx->key->genctx.pubkey_bits / 8;
            uint32_t hash_size = (uint32_t)EVP_MD_size(ctx->md);
            pss_params.salt_len = key_bytes - hash_size - 2;
        }
        else if (ctx->salt_len >= 0)
        {
            pss_params.salt_len = (uint32_t)ctx->salt_len;
        }
        else
        {
            pss_params.salt_len = (uint32_t)EVP_MD_size(ctx->md);
        }

        algo.id = azihsm_ossl_evp_md_to_rsa_pss_algo_id(ctx->md);
        algo.params = &pss_params;
        algo.len = sizeof(pss_params);
    }
    else
    {
        /* PKCS#1 v1.5 mode */
        algo.id = azihsm_ossl_evp_md_to_rsa_pkcs_algo_id(ctx->md);
        algo.params = NULL;
        algo.len = 0;
    }

    if (algo.id == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Initialize streaming verify context */
    status = azihsm_crypt_verify_init(&algo, ctx->key->key.pub, &ctx->sign_ctx);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_digest_verify_update(
    void *sctx,
    const unsigned char *data,
    size_t datalen
)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (datalen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Set up buffer */
    data_buf.ptr = (uint8_t *)data;
    data_buf.len = (uint32_t)datalen;

    /* Update streaming verify with raw data */
    status = azihsm_crypt_verify_update(ctx->sign_ctx, &data_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_digest_verify_final(void *sctx, const unsigned char *sig, size_t siglen)
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    struct azihsm_buffer sig_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (siglen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Set up buffer */
    sig_buf.ptr = (uint8_t *)sig;
    sig_buf.len = (uint32_t)siglen;

    /* Finish streaming verify */
    status = azihsm_crypt_verify_finish(ctx->sign_ctx, &sig_buf);
    ctx->sign_ctx = 0;

    if (status == AZIHSM_STATUS_SUCCESS)
    {
        return OSSL_SUCCESS;
    }
    else if (status == AZIHSM_STATUS_INVALID_SIGNATURE)
    {
        return OSSL_FAILURE;
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   RSA PARAMETER HANDLING
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_rsa_set_ctx_params(void *sctx, const OSSL_PARAM params[])
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    /* Parse digest algorithm */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname) || mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        ctx->md = EVP_get_digestbyname(mdname);
        if (ctx->md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    /* Parse padding mode */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL)
    {
        const char *pad_mode_str = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &pad_mode_str) || pad_mode_str == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        if (strcmp(pad_mode_str, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
        {
            ctx->pad_mode = AZIHSM_RSA_PAD_MODE_PKCSV15;
        }
        else if (strcmp(pad_mode_str, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
        {
            ctx->pad_mode = AZIHSM_RSA_PAD_MODE_PSS;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    /* Parse PSS salt length */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL)
    {
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            const char *saltlen_str = NULL;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &saltlen_str) || saltlen_str == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                return OSSL_FAILURE;
            }

            if (strcmp(saltlen_str, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
            {
                ctx->salt_len = AZIHSM_RSA_PSS_SALTLEN_DIGEST;
            }
            else if (strcmp(saltlen_str, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
            {
                ctx->salt_len = AZIHSM_RSA_PSS_SALTLEN_AUTO;
            }
            else if (strcmp(saltlen_str, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
            {
                ctx->salt_len = AZIHSM_RSA_PSS_SALTLEN_MAX;
            }
            else
            {
                /* Parse as integer with validation */
                char *endptr = NULL;
                long val = strtol(saltlen_str, &endptr, 10);
                if (endptr == saltlen_str || *endptr != '\0' || val < 0 || val > INT_MAX)
                {
                    ERR_raise_data(
                        ERR_LIB_PROV,
                        ERR_R_PASSED_INVALID_ARGUMENT,
                        "invalid PSS salt length: %s",
                        saltlen_str
                    );
                    return OSSL_FAILURE;
                }
                ctx->salt_len = (int)val;
            }
        }
        else
        {
            int salt_len_int = 0;
            if (!OSSL_PARAM_get_int(p, &salt_len_int))
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                return OSSL_FAILURE;
            }
            ctx->salt_len = salt_len_int;
        }
    }

    /* Parse MGF1 digest */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const char *mgf1_mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mgf1_mdname) || mgf1_mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        ctx->mgf1_md = EVP_get_digestbyname(mgf1_mdname);
        if (ctx->mgf1_md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_rsa_get_ctx_params(void *sctx, OSSL_PARAM params[])
{
    azihsm_rsa_sig_ctx *ctx = (azihsm_rsa_sig_ctx *)sctx;
    OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = (ctx->md != NULL) ? EVP_MD_name(ctx->md) : NULL;
        if (!OSSL_PARAM_set_utf8_string(p, mdname))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL)
    {
        const char *pad_mode_str = (ctx->pad_mode == AZIHSM_RSA_PAD_MODE_PSS)
                                       ? OSSL_PKEY_RSA_PAD_MODE_PSS
                                       : OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
        if (!OSSL_PARAM_set_utf8_string(p, pad_mode_str))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL)
    {
        if (!OSSL_PARAM_set_int(p, ctx->salt_len))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->md;
        const char *mgf1_mdname = (mgf1_md != NULL) ? EVP_MD_name(mgf1_md) : NULL;
        if (!OSSL_PARAM_set_utf8_string(p, mgf1_mdname))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_ossl_rsa_settable_ctx_params(void *sctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return settable;
}

static const OSSL_PARAM *azihsm_ossl_rsa_gettable_ctx_params(void *sctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return gettable;
}

const OSSL_DISPATCH azihsm_ossl_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))azihsm_ossl_rsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))azihsm_ossl_rsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))azihsm_ossl_rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))azihsm_ossl_rsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))azihsm_ossl_rsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))azihsm_ossl_rsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))azihsm_ossl_rsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))azihsm_ossl_rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))azihsm_ossl_rsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))azihsm_ossl_rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))azihsm_ossl_rsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))azihsm_ossl_rsa_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))azihsm_ossl_rsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_rsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_rsa_gettable_ctx_params },
    { 0, NULL },
};

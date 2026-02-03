// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <stdint.h>
#include <string.h>

#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_signature_ec.h"

/* ═══════════════════════════════════════════════════════════════════════════
   ECDSA CONTEXT LIFECYCLE
   ═══════════════════════════════════════════════════════════════════════════ */

static void *azihsm_ossl_ecdsa_newctx(void *provctx, ossl_unused const char *propq)
{
    azihsm_ec_sig_ctx *ctx;
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

    return ctx;
}

static void azihsm_ossl_ecdsa_freectx(void *sctx)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;

    if (ctx == NULL)
        return;

    /* Note: Don't free key - caller owns it */
    OPENSSL_free(ctx);
}

static void *azihsm_ossl_ecdsa_dupctx(void *sctx)
{
    azihsm_ec_sig_ctx *src_ctx = (azihsm_ec_sig_ctx *)sctx;
    azihsm_ec_sig_ctx *dst_ctx;

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
   ECDSA ONE-SHOT OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_ecdsa_sign_init(void *sctx, void *provkey, const OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;

    ctx->operation = 1; /* Sign */

    /* Set default hash algorithm if not already set */
    if (ctx->md == NULL)
    {
        ctx->md = EVP_sha256();
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_sign(
    void *sctx,
    unsigned char *sig,
    size_t *siglen,
    size_t sigsize,
    const unsigned char *tbs,
    size_t tbslen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_buffer data_buf, sig_buf;
    azihsm_status status;

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

    /* Use raw ECDSA algorithm — data has to come in already hashed by the user */
    algo.id = AZIHSM_ALGO_ID_ECDSA;
    algo.params = NULL;
    algo.len = 0;

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

static int azihsm_ossl_ecdsa_verify_init(void *sctx, void *provkey, const OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;
    ctx->operation = 0; /* Verify */

    /* Set default hash algorithm if not already set */
    if (ctx->md == NULL)
    {
        ctx->md = EVP_sha256();
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_verify(
    void *sctx,
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *tbs,
    size_t tbslen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_buffer data_buf, sig_buf;
    azihsm_status status;

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

    algo.id = AZIHSM_ALGO_ID_ECDSA;
    algo.params = NULL;
    algo.len = 0;

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
   ECDSA STREAMING OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_ecdsa_digest_sign_init(
    void *sctx,
    const char *mdname,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    azihsm_algo_id algo_id;
    struct azihsm_algo algo = { 0 };
    azihsm_status status;

    if (provkey == NULL)
    {
        /* Silently succeed - this is a cleanup/reset operation, not an active signing operation */
        return OSSL_SUCCESS;
    }

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;

    ctx->operation = 1; /* Sign */

    /* Get hash algorithm by name */
    ctx->md = EVP_get_digestbyname(mdname);
    if (ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Map hash algorithm to EcdsaSha* combined algorithm ID */
    algo_id = azihsm_ossl_evp_md_to_ecdsa_algo_id(ctx->md);

    if (algo_id == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Create algorithm structure */
    algo.id = algo_id;

    status = azihsm_crypt_sign_init(&algo, ctx->key->key.priv, &ctx->sign_ctx);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_digest_sign_update(
    void *sctx,
    const unsigned char *data,
    size_t datalen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
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

static int azihsm_ossl_ecdsa_digest_sign_final(
    void *sctx,
    unsigned char *sig,
    size_t *siglen,
    size_t sigsize
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
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
        /* Ask the HSM for the required signature buffer size */
        sig_buf.ptr = NULL;
        sig_buf.len = 0;
        status = azihsm_crypt_sign_final(ctx->sign_ctx, &sig_buf);
        if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || sig_buf.len == 0)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }
        *siglen = sig_buf.len;
        return OSSL_SUCCESS;
    }

    /* Query the HSM for the exact signature size */
    sig_buf.ptr = NULL;
    sig_buf.len = 0;
    status = azihsm_crypt_sign_final(ctx->sign_ctx, &sig_buf);
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

    /* Finalize streaming sign with exact size required by HSM */
    sig_buf.ptr = sig;
    status = azihsm_crypt_sign_final(ctx->sign_ctx, &sig_buf);

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

static int azihsm_ossl_ecdsa_digest_verify_init(
    void *sctx,
    const char *mdname,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    azihsm_status status;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;
    ctx->operation = 0; /* Verify */

    /* Get hash algorithm by name */
    ctx->md = EVP_get_digestbyname(mdname);
    if (ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Map hash algorithm to EcdsaSha* combined algorithm ID */
    algo.id = azihsm_ossl_evp_md_to_ecdsa_algo_id(ctx->md);
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

static int azihsm_ossl_ecdsa_digest_verify_update(
    void *sctx,
    const unsigned char *data,
    size_t datalen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
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

static int azihsm_ossl_ecdsa_digest_verify_final(
    void *sctx,
    const unsigned char *sig,
    size_t siglen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
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

    /* Finalize streaming verify */
    status = azihsm_crypt_verify_final(ctx->sign_ctx, &sig_buf);
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
   ECDSA PARAMETER HANDLING
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_ecdsa_set_ctx_params(void *sctx, const OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        /* Get digest algorithm by name */
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

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_get_ctx_params(void *sctx, OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
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

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_ossl_ecdsa_settable_ctx_params(void *sctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return settable;
}

static const OSSL_PARAM *azihsm_ossl_ecdsa_gettable_ctx_params(void *sctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return gettable;
}

const OSSL_DISPATCH azihsm_ossl_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))azihsm_ossl_ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))azihsm_ossl_ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))azihsm_ossl_ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))azihsm_ossl_ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))azihsm_ossl_ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))azihsm_ossl_ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))azihsm_ossl_ecdsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))azihsm_ossl_ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))azihsm_ossl_ecdsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))azihsm_ossl_ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))azihsm_ossl_ecdsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))azihsm_ossl_ecdsa_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))azihsm_ossl_ecdsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_ecdsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_ecdsa_gettable_ctx_params },
    { 0, NULL },
};

// Copyright (C) Microsoft Corporation. All rights reserved.
#include <azihsm.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"

/* Maximum digest output size (SHA512 = 64 bytes) */
#define MAX_DIGEST_SIZE_BYTES 64

#define AZIHSM_OSSL_SHA1_DIGEST_SIZE 20
#define AZIHSM_OSSL_SHA1_BLOCK_SIZE 64
#define AZIHSM_OSSL_SHA256_DIGEST_SIZE 32
#define AZIHSM_OSSL_SHA256_BLOCK_SIZE 64
#define AZIHSM_OSSL_SHA384_DIGEST_SIZE 48
#define AZIHSM_OSSL_SHA384_BLOCK_SIZE 128
#define AZIHSM_OSSL_SHA512_DIGEST_SIZE 64
#define AZIHSM_OSSL_SHA512_BLOCK_SIZE 128

/* Digest Context Structure for streaming operations */
typedef struct
{
    azihsm_handle ctx_handle;     /* HSM digest context handle */
    azihsm_handle session_handle; /* HSM session handle (from provider context) */
    uint32_t digest_size;         /* Size of digest output in bytes */
    int algo_id;                  /* Algorithm ID (AZIHSM_ALGO_ID_*) */
} AZIHSM_HSM_DIGEST_CTX;

/* Context Management Functions */

static void *azihsm_ossl_digest_newctx_algo(void *provctx, int algo_id, uint32_t digest_size)
{
    AZIHSM_HSM_DIGEST_CTX *dctx = NULL;
    AZIHSM_OSSL_PROV_CTX *prov_ctx = (AZIHSM_OSSL_PROV_CTX *)provctx;

    if (provctx == NULL)
    {
        return NULL;
    }

    if ((dctx = OPENSSL_malloc(sizeof(AZIHSM_HSM_DIGEST_CTX))) == NULL)
    {
        return NULL;
    }

    dctx->ctx_handle = 0;
    dctx->session_handle = prov_ctx->session;
    dctx->digest_size = digest_size;
    dctx->algo_id = algo_id;

    return (void *)dctx;
}

static void *azihsm_ossl_newctx(ossl_unused void *provctx)
{
    /* This is called for SHA1, SHA256, etc. - we need the specific MD */
    return NULL;
}

static void azihsm_ossl_digest_freectx(void *dctx)
{
    AZIHSM_HSM_DIGEST_CTX *ctx = (AZIHSM_HSM_DIGEST_CTX *)dctx;

    if (ctx != NULL)
    {
        OPENSSL_free(ctx);
    }
}

static void *azihsm_ossl_digest_dupctx(ossl_unused void *dctx)
{
    return NULL;
}

/* Digest Generation Functions */

static int azihsm_ossl_digest_init(void *dctx, ossl_unused const OSSL_PARAM params[])
{
    AZIHSM_HSM_DIGEST_CTX *ctx = (AZIHSM_HSM_DIGEST_CTX *)dctx;
    azihsm_status status;
    struct azihsm_algo algo = { 0 };

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    if (ctx->session_handle == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    /* Set up algorithm structure */
    algo.id = ctx->algo_id;

    status = azihsm_crypt_digest_init(ctx->session_handle, &algo, &ctx->ctx_handle);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    AZIHSM_HSM_DIGEST_CTX *ctx = (AZIHSM_HSM_DIGEST_CTX *)dctx;
    azihsm_status status;
    struct azihsm_buffer data_buf = { 0 };

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    if (in == NULL || inl == 0)
    {
        return OSSL_SUCCESS;
    }

    if (inl > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return OSSL_FAILURE;
    }

    if (ctx->ctx_handle == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    data_buf.ptr = (unsigned char *)in;
    data_buf.len = (uint32_t)inl;

    status = azihsm_crypt_digest_update(ctx->ctx_handle, &data_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_digest_generic_final(
    void *dctx,
    unsigned char *out,
    size_t *outl,
    size_t outsz
)
{
    AZIHSM_HSM_DIGEST_CTX *ctx = (AZIHSM_HSM_DIGEST_CTX *)dctx;
    azihsm_status status;
    struct azihsm_buffer digest_buf = { 0 };
    unsigned char digest_data[MAX_DIGEST_SIZE_BYTES] = { 0 };

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    if (out == NULL || outl == NULL)
    {
        return OSSL_FAILURE;
    }

    if (outsz < ctx->digest_size)
    {
        return OSSL_FAILURE;
    }

    if (ctx->ctx_handle == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    digest_buf.ptr = digest_data;
    digest_buf.len = MAX_DIGEST_SIZE_BYTES;

    status = azihsm_crypt_digest_final(ctx->ctx_handle, &digest_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return OSSL_FAILURE;
    }

    if (digest_buf.len != ctx->digest_size)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        OPENSSL_cleanse(digest_data, sizeof(digest_data));
        ctx->ctx_handle = 0;
        return OSSL_FAILURE;
    }

    memcpy(out, digest_buf.ptr, ctx->digest_size);
    *outl = ctx->digest_size;

    OPENSSL_cleanse(digest_data, sizeof(digest_data));

    ctx->ctx_handle = 0;

    return OSSL_SUCCESS;
}

static int azihsm_ossl_digest(
    void *provctx,
    const unsigned char *in,
    size_t inl,
    unsigned char *out,
    size_t *outl,
    size_t outsz
)
{
    /* One-shot digest operations are not supported by this provider implementation. */
    ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
}

/* Digest Parameter Functions */

static int azihsm_ossl_digest_get_params(OSSL_PARAM params[], size_t blksize, size_t dgstsize)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksize))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, dgstsize))
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

/* Algorithm-specific context creation functions */

static void *azihsm_ossl_sha1_newctx(void *provctx)
{
    return azihsm_ossl_digest_newctx_algo(
        provctx,
        AZIHSM_ALGO_ID_SHA1,
        AZIHSM_OSSL_SHA1_DIGEST_SIZE
    );
}

static void *azihsm_ossl_sha256_newctx(void *provctx)
{
    return azihsm_ossl_digest_newctx_algo(
        provctx,
        AZIHSM_ALGO_ID_SHA256,
        AZIHSM_OSSL_SHA256_DIGEST_SIZE
    );
}

static void *azihsm_ossl_sha384_newctx(void *provctx)
{
    return azihsm_ossl_digest_newctx_algo(
        provctx,
        AZIHSM_ALGO_ID_SHA384,
        AZIHSM_OSSL_SHA384_DIGEST_SIZE
    );
}

static void *azihsm_ossl_sha512_newctx(void *provctx)
{
    return azihsm_ossl_digest_newctx_algo(
        provctx,
        AZIHSM_ALGO_ID_SHA512,
        AZIHSM_OSSL_SHA512_DIGEST_SIZE
    );
}

/* SHA1 */
static int azihsm_ossl_sha1_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(
        params,
        AZIHSM_OSSL_SHA1_BLOCK_SIZE,
        AZIHSM_OSSL_SHA1_DIGEST_SIZE
    );
}

/* SHA256 */
static int azihsm_ossl_sha256_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(
        params,
        AZIHSM_OSSL_SHA256_BLOCK_SIZE,
        AZIHSM_OSSL_SHA256_DIGEST_SIZE
    );
}

/* SHA384 */
static int azihsm_ossl_sha384_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(
        params,
        AZIHSM_OSSL_SHA384_BLOCK_SIZE,
        AZIHSM_OSSL_SHA384_DIGEST_SIZE
    );
}

/* SHA512 */
static int azihsm_ossl_sha512_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(
        params,
        AZIHSM_OSSL_SHA512_BLOCK_SIZE,
        AZIHSM_OSSL_SHA512_DIGEST_SIZE
    );
}

static int azihsm_ossl_digest_set_state(
    ossl_unused void *dctx,
    ossl_unused const OSSL_PARAM params[]
)
{
    /* Not implemented for HSM-based digest */
    return OSSL_FAILURE;
}

static int azihsm_ossl_digest_get_state(ossl_unused void *dctx, ossl_unused OSSL_PARAM params[])
{
    /* Not implemented for HSM-based digest */
    return OSSL_FAILURE;
}

/* Digest Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_digest_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
                                         OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
                                         OSSL_PARAM_END };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_digest_export_gettable_ctx_params(
    ossl_unused void *dctx,
    ossl_unused void *provctx
)
{
    return NULL;
}

static const OSSL_PARAM *azihsm_ossl_digest_export_settable_ctx_params(
    ossl_unused void *dctx,
    ossl_unused void *provctx
)
{
    return NULL;
}

#define IMPLEMENT_AZIHSM_OSSL_DIGEST(alg)                                                          \
    const OSSL_DISPATCH azihsm_ossl_##alg##_functions[] = {                                        \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))azihsm_ossl_##alg##_newctx },                   \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))azihsm_ossl_digest_freectx },                  \
        { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))azihsm_ossl_digest_dupctx },                    \
                                                                                                   \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))azihsm_ossl_digest_init },                        \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))azihsm_ossl_digest_update },                    \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))azihsm_ossl_digest_generic_final },              \
        { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))azihsm_ossl_digest },                           \
                                                                                                   \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))azihsm_ossl_##alg##_get_params },           \
        { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_digest_get_state },         \
        { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_digest_set_state },         \
                                                                                                   \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_digest_gettable_params },  \
        { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,                                                    \
          (void (*)(void))azihsm_ossl_digest_export_gettable_ctx_params },                         \
        { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                                    \
          (void (*)(void))azihsm_ossl_digest_export_settable_ctx_params },                         \
        { 0, NULL }                                                                                \
    };

IMPLEMENT_AZIHSM_OSSL_DIGEST(sha1)
IMPLEMENT_AZIHSM_OSSL_DIGEST(sha256)
IMPLEMENT_AZIHSM_OSSL_DIGEST(sha384)
IMPLEMENT_AZIHSM_OSSL_DIGEST(sha512)

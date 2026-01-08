//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/prov_ssl.h>

#include "azihsm_ossl_helpers.h"

/* Context Management Functions */

static void *azihsm_ossl_newctx(ossl_unused void *provctx)
{
    return NULL;
}

static void azihsm_ossl_digest_freectx(ossl_unused void *dctx)
{
    // TODO: Free resources associated with digest context
}

static void *azihsm_ossl_digest_dupctx(ossl_unused void *dctx)
{
    // TODO: Duplicate the digest context
    return NULL;
}

/* Digest Generation Functions */

static int azihsm_ossl_digest_init(ossl_unused void *dctx, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize digest operation
    return 0;
}

static int azihsm_ossl_digest_update(ossl_unused void *dctx, ossl_unused const unsigned char *in, ossl_unused size_t inl)
{
    // TODO: Update digest with input data
    return 0;
}

static int azihsm_ossl_digest_generic_final(ossl_unused void *dctx, ossl_unused unsigned char *out, ossl_unused size_t *outl, ossl_unused size_t outsz)
{
    // TODO: Finalize digest and write output
    return 0;
}

static int azihsm_ossl_digest(ossl_unused void *provctx, ossl_unused const unsigned char *in, ossl_unused size_t inl,
                             ossl_unused unsigned char *out, ossl_unused size_t *outl, ossl_unused size_t outsz)
{
    // TODO: One-shot digest operation
    return 0;
}

/* Digest Parameter Functions */

static int azihsm_ossl_digest_get_params(OSSL_PARAM params[], size_t blksize, size_t dgstsize)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksize))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, dgstsize))
    {
        return 0;
    }

    return 1;
}

/* SHA1 */
static int azihsm_ossl_sha1_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(params, 64, 20);
}

/* SHA256 */
static int azihsm_ossl_sha256_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(params, 64, 32);
}

/* SHA384 */
static int azihsm_ossl_sha384_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(params, 128, 48);
}

/* SHA512 */
static int azihsm_ossl_sha512_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_digest_get_params(params, 128, 64);
}

static int azihsm_ossl_digest_set_state(ossl_unused void *dctx, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Set digest context parameters
    return 0;
}

static int azihsm_ossl_digest_get_state(ossl_unused void *dctx, ossl_unused OSSL_PARAM params[])
{
    // TODO: Get digest context parameters
    return 0;
}

/* Digest Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_digest_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_digest_export_gettable_ctx_params(ossl_unused void *dctx, ossl_unused void *provctx)
{
    // TODO: Return array of gettable context parameter descriptors
    return NULL;
}

static const OSSL_PARAM *azihsm_ossl_digest_export_settable_ctx_params(ossl_unused void *dctx, ossl_unused void *provctx)
{
    // TODO: Return array of settable context parameter descriptors
    return NULL;
}

#define IMPLEMENT_AZIHSM_OSSL_DIGEST(alg)                                                                  \
    const OSSL_DISPATCH azihsm_ossl_##alg##_functions[] = {                                                \
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))azihsm_ossl_newctx},                                         \
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))azihsm_ossl_digest_freectx},                                \
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))azihsm_ossl_digest_dupctx},                                  \
                                                                                                          \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))azihsm_ossl_digest_init},                                      \
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))azihsm_ossl_digest_update},                                  \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))azihsm_ossl_digest_generic_final},                            \
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))azihsm_ossl_digest},                                         \
                                                                                                          \
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))azihsm_ossl_##alg##_get_params},                         \
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_digest_get_state},                       \
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_digest_set_state},                       \
                                                                                                          \
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_digest_gettable_params},                \
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_digest_export_gettable_ctx_params}, \
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_digest_export_settable_ctx_params}, \
    {0, NULL}};

IMPLEMENT_AZIHSM_OSSL_DIGEST(sha1)
IMPLEMENT_AZIHSM_OSSL_DIGEST(sha256)
IMPLEMENT_AZIHSM_OSSL_DIGEST(sha384)
IMPLEMENT_AZIHSM_OSSL_DIGEST(sha512)

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"

/* Context Management Functions */

static void *azihsm_ossl_kdf_newctx(ossl_unused void *provctx)
{
    // TODO: Allocate and return KDF context
    return NULL;
}

static void azihsm_ossl_kdf_freectx(ossl_unused void *kctx)
{
    // TODO: Free KDF context resources
}

static void *azihsm_ossl_kdf_dupctx(ossl_unused void *kctx)
{
    // TODO: Duplicate KDF context
    return NULL;
}

static void azihsm_ossl_kdf_reset(ossl_unused void *kctx)
{
    // TODO: Reset KDF context
}

/* KDF Derivation Functions */

static int azihsm_ossl_kdf_derive(
    ossl_unused void *kctx,
    ossl_unused unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Derive key material
    return 0;
}

/* KDF Parameter Functions */

static int azihsm_ossl_kdf_get_params(ossl_unused OSSL_PARAM params[])
{
    // TODO: Get KDF algorithm parameters
    return 1;
}

static int azihsm_ossl_kdf_get_ctx_params(ossl_unused void *kctx, ossl_unused OSSL_PARAM params[])
{
    // TODO: Get KDF context parameters
    return 0;
}

static int azihsm_ossl_kdf_set_ctx_params(
    ossl_unused void *kctx,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Set KDF context parameters
    return 0;
}

/* KDF Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_kdf_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_kdf_gettable_ctx_params(
    ossl_unused void *kctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_kdf_settable_ctx_params(
    ossl_unused void *kctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

/* HKDF */
const OSSL_DISPATCH azihsm_ossl_hkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))azihsm_ossl_kdf_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))azihsm_ossl_kdf_freectx },
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void))azihsm_ossl_kdf_dupctx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void))azihsm_ossl_kdf_reset },

    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))azihsm_ossl_kdf_derive },

    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void))azihsm_ossl_kdf_get_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_get_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_set_ctx_params },

    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_kdf_gettable_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_settable_ctx_params },
    { 0, NULL }
};

/* KBKDF */
const OSSL_DISPATCH azihsm_ossl_kbkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))azihsm_ossl_kdf_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))azihsm_ossl_kdf_freectx },
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void))azihsm_ossl_kdf_dupctx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void))azihsm_ossl_kdf_reset },

    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))azihsm_ossl_kdf_derive },

    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void))azihsm_ossl_kdf_get_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_get_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_set_ctx_params },

    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_kdf_gettable_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_kdf_settable_ctx_params },
    { 0, NULL }
};

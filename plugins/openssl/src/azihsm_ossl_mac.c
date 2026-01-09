// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"

/* Context Management Functions */

static void *azihsm_ossl_mac_newctx(ossl_unused void *provctx)
{
    // TODO: Allocate and return MAC context
    return NULL;
}

static void azihsm_ossl_mac_freectx(ossl_unused void *mctx)
{
    // TODO: Free MAC context resources
}

static void *azihsm_ossl_mac_dupctx(ossl_unused void *mctx)
{
    // TODO: Duplicate MAC context
    return NULL;
}

/* MAC Generation Functions */

static int azihsm_ossl_mac_init(ossl_unused void *mctx, ossl_unused const unsigned char *key,
                               ossl_unused size_t keylen, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize MAC operation
    return 0;
}

static int azihsm_ossl_mac_update(ossl_unused void *mctx, ossl_unused const unsigned char *in, ossl_unused size_t inl)
{
    // TODO: Update MAC with input data
    return 0;
}

static int azihsm_ossl_mac_final(ossl_unused void *mctx, ossl_unused unsigned char *out,
                                ossl_unused size_t *outl, ossl_unused size_t outsize)
{
    // TODO: Finalize MAC and write output
    return 0;
}

/* MAC Parameter Functions */

static int azihsm_ossl_mac_get_params(OSSL_PARAM params[], size_t macsize)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, macsize))
    {
        return 0;
    }

    return 1;
}

static int azihsm_ossl_hmac_get_params(OSSL_PARAM params[])
{
    // HMAC size is variable, depends on underlying digest
    return azihsm_ossl_mac_get_params(params, 64);
}

static int azihsm_ossl_mac_get_ctx_params(ossl_unused void *mctx, ossl_unused OSSL_PARAM params[])
{
    // TODO: Get MAC context parameters
    return 0;
}

static int azihsm_ossl_mac_set_ctx_params(ossl_unused void *mctx, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Set MAC context parameters (e.g., digest for HMAC)
    return 0;
}

/* MAC Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_mac_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_mac_gettable_ctx_params(ossl_unused void *mctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_mac_settable_ctx_params(ossl_unused void *mctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

const OSSL_DISPATCH azihsm_ossl_hmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))azihsm_ossl_mac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))azihsm_ossl_mac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))azihsm_ossl_mac_dupctx},

    {OSSL_FUNC_MAC_INIT, (void (*)(void))azihsm_ossl_mac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))azihsm_ossl_mac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))azihsm_ossl_mac_final},

    {OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))azihsm_ossl_hmac_get_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_set_ctx_params},

    {OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_mac_gettable_params},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_settable_ctx_params},
    {0, NULL}};

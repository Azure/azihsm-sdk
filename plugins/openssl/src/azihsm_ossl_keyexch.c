//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"

/* Key Exchange Functions */

static void *azihsm_ossl_keyexch_newctx(ossl_unused void *provctx)
{
    // TODO: Create new key exchange context
    return NULL;
}

static void azihsm_ossl_keyexch_freectx(ossl_unused void *kectx)
{
    // TODO: Free key exchange context
}

static void *azihsm_ossl_keyexch_dupctx(ossl_unused void *kectx)
{
    // TODO: Duplicate key exchange context
    return NULL;
}

static int azihsm_ossl_keyexch_init(ossl_unused void *kectx, ossl_unused void *provkey,
                                   ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize key exchange with private key
    return 0;
}

static int azihsm_ossl_keyexch_set_peer(ossl_unused void *kectx, ossl_unused void *provkey)
{
    // TODO: Set peer public key
    return 0;
}

static int azihsm_ossl_keyexch_derive(ossl_unused void *kectx, ossl_unused unsigned char *secret,
                                     ossl_unused size_t *secretlen, ossl_unused size_t outlen)
{
    // TODO: Derive shared secret
    return 0;
}

static int azihsm_ossl_keyexch_set_ctx_params(ossl_unused void *kectx, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Set key exchange context parameters
    return 0;
}

static const OSSL_PARAM *azihsm_ossl_keyexch_settable_ctx_params(ossl_unused void *kectx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

/* ECDH Key Exchange */
const OSSL_DISPATCH azihsm_ossl_ecdh_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))azihsm_ossl_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))azihsm_ossl_keyexch_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))azihsm_ossl_keyexch_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))azihsm_ossl_keyexch_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))azihsm_ossl_keyexch_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))azihsm_ossl_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_keyexch_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_keyexch_settable_ctx_params},
    {0, NULL}};

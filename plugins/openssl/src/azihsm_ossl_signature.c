// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"

/* Signature Functions */

static void *azihsm_ossl_signature_newctx(ossl_unused void *provctx, ossl_unused const char *propq)
{
    // TODO: Create new signature context
    return NULL;
}

static void azihsm_ossl_signature_freectx(ossl_unused void *sctx)
{
    // TODO: Free signature context
}

static void *azihsm_ossl_signature_dupctx(ossl_unused void *sctx)
{
    // TODO: Duplicate signature context
    return NULL;
}

static int azihsm_ossl_signature_sign_init(ossl_unused void *sctx, ossl_unused void *provkey,
                                          ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize signature signing
    return 0;
}

static int azihsm_ossl_signature_sign(ossl_unused void *sctx, ossl_unused unsigned char *sig,
                                     ossl_unused size_t *siglen, ossl_unused size_t sigsize,
                                     ossl_unused const unsigned char *tbs, ossl_unused size_t tbslen)
{
    // TODO: Sign data
    return 0;
}

static int azihsm_ossl_signature_verify_init(ossl_unused void *sctx, ossl_unused void *provkey,
                                            ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize signature verification
    return 0;
}

static int azihsm_ossl_signature_verify(ossl_unused void *sctx, ossl_unused const unsigned char *sig,
                                       ossl_unused size_t siglen, ossl_unused const unsigned char *tbs,
                                       ossl_unused size_t tbslen)
{
    // TODO: Verify signature
    return 0;
}

static int azihsm_ossl_signature_digest_sign_init(ossl_unused void *sctx, ossl_unused const char *mdname,
                                                 ossl_unused void *provkey, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize digest and signature signing
    return 0;
}

static int azihsm_ossl_signature_digest_sign_update(ossl_unused void *sctx, ossl_unused const unsigned char *data,
                                                   ossl_unused size_t datalen)
{
    // TODO: Update digest for signature
    return 0;
}

static int azihsm_ossl_signature_digest_sign_final(ossl_unused void *sctx, ossl_unused unsigned char *sig,
                                                  ossl_unused size_t *siglen, ossl_unused size_t sigsize)
{
    // TODO: Finalize digest and sign
    return 0;
}

static int azihsm_ossl_signature_digest_verify_init(ossl_unused void *sctx, ossl_unused const char *mdname,
                                                   ossl_unused void *provkey, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Initialize digest and signature verification
    return 0;
}

static int azihsm_ossl_signature_digest_verify_update(ossl_unused void *sctx, ossl_unused const unsigned char *data,
                                                     ossl_unused size_t datalen)
{
    // TODO: Update digest for verification
    return 0;
}

static int azihsm_ossl_signature_digest_verify_final(ossl_unused void *sctx, ossl_unused const unsigned char *sig,
                                                    ossl_unused size_t siglen)
{
    // TODO: Finalize digest and verify signature
    return 0;
}

static int azihsm_ossl_signature_get_ctx_params(ossl_unused void *sctx, ossl_unused OSSL_PARAM params[])
{
    // TODO: Get signature context parameters
    return 0;
}

static int azihsm_ossl_signature_set_ctx_params(ossl_unused void *sctx, ossl_unused const OSSL_PARAM params[])
{
    // TODO: Set signature context parameters
    return 0;
}

static const OSSL_PARAM *azihsm_ossl_signature_gettable_ctx_params(ossl_unused void *sctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_signature_settable_ctx_params(ossl_unused void *sctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
        OSSL_PARAM_END
    };
    return params;
}

/* RSA Signature */
const OSSL_DISPATCH azihsm_ossl_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))azihsm_ossl_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))azihsm_ossl_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))azihsm_ossl_signature_dupctx},

    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))azihsm_ossl_signature_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))azihsm_ossl_signature_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))azihsm_ossl_signature_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))azihsm_ossl_signature_verify},

    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))azihsm_ossl_signature_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))azihsm_ossl_signature_digest_sign_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))azihsm_ossl_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))azihsm_ossl_signature_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))azihsm_ossl_signature_digest_verify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))azihsm_ossl_signature_digest_verify_final},

    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_settable_ctx_params},
    {0, NULL}};

/* ECDSA Signature */
const OSSL_DISPATCH azihsm_ossl_ecdsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))azihsm_ossl_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))azihsm_ossl_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))azihsm_ossl_signature_dupctx},

    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))azihsm_ossl_signature_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))azihsm_ossl_signature_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))azihsm_ossl_signature_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))azihsm_ossl_signature_verify},

    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))azihsm_ossl_signature_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))azihsm_ossl_signature_digest_sign_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))azihsm_ossl_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))azihsm_ossl_signature_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))azihsm_ossl_signature_digest_verify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))azihsm_ossl_signature_digest_verify_final},

    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_signature_settable_ctx_params},
    {0, NULL}};

// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"

/* Asymmetric Cipher Functions */

static void *azihsm_ossl_asym_cipher_newctx(ossl_unused void *provctx)
{
    // TODO: Create new asymmetric cipher context
    return NULL;
}

static void azihsm_ossl_asym_cipher_freectx(ossl_unused void *cctx)
{
    // TODO: Free asymmetric cipher context
}

static void *azihsm_ossl_asym_cipher_dupctx(ossl_unused void *cctx)
{
    // TODO: Duplicate asymmetric cipher context
    return NULL;
}

static int azihsm_ossl_asym_cipher_encrypt_init(
    ossl_unused void *cctx,
    ossl_unused void *provkey,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Initialize encryption
    return 0;
}

static int azihsm_ossl_asym_cipher_encrypt(
    ossl_unused void *cctx,
    ossl_unused unsigned char *out,
    ossl_unused size_t *outlen,
    ossl_unused size_t outsize,
    ossl_unused const unsigned char *in,
    ossl_unused size_t inlen
)
{
    // TODO: Encrypt data
    return 0;
}

static int azihsm_ossl_asym_cipher_decrypt_init(
    ossl_unused void *cctx,
    ossl_unused void *provkey,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Initialize decryption
    return 0;
}

static int azihsm_ossl_asym_cipher_decrypt(
    ossl_unused void *cctx,
    ossl_unused unsigned char *out,
    ossl_unused size_t *outlen,
    ossl_unused size_t outsize,
    ossl_unused const unsigned char *in,
    ossl_unused size_t inlen
)
{
    // TODO: Decrypt data
    return 0;
}

static int azihsm_ossl_asym_cipher_get_ctx_params(
    ossl_unused void *cctx,
    ossl_unused OSSL_PARAM params[]
)
{
    // TODO: Get asymmetric cipher context parameters
    return 0;
}

static int azihsm_ossl_asym_cipher_set_ctx_params(
    ossl_unused void *cctx,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Set asymmetric cipher context parameters
    return 0;
}

static const OSSL_PARAM *azihsm_ossl_asym_cipher_gettable_ctx_params(
    ossl_unused void *cctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_asym_cipher_settable_ctx_params(
    ossl_unused void *cctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

/* RSA Asymmetric Cipher */
const OSSL_DISPATCH azihsm_ossl_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))azihsm_ossl_asym_cipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))azihsm_ossl_asym_cipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))azihsm_ossl_asym_cipher_dupctx },

    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))azihsm_ossl_asym_cipher_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))azihsm_ossl_asym_cipher_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))azihsm_ossl_asym_cipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))azihsm_ossl_asym_cipher_decrypt },

    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_asym_cipher_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_asym_cipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_asym_cipher_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_asym_cipher_settable_ctx_params },
    { 0, NULL }
};

// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"

/* Context Management Functions */

static void *azihsm_ossl_cipher_newctx(ossl_unused void *provctx)
{
    // TODO: Allocate and return cipher context
    return NULL;
}

static void azihsm_ossl_cipher_freectx(ossl_unused void *cctx)
{
    // TODO: Free cipher context resources
}

static void *azihsm_ossl_cipher_dupctx(ossl_unused void *cctx)
{
    // TODO: Duplicate cipher context
    return NULL;
}

/* Cipher Encrypt/Decrypt Functions */

static int azihsm_ossl_cipher_encrypt_init(
    ossl_unused void *cctx,
    ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Initialize encryption
    return 0;
}

static int azihsm_ossl_cipher_decrypt_init(
    ossl_unused void *cctx,
    ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Initialize decryption
    return 0;
}

static int azihsm_ossl_cipher_update(
    ossl_unused void *cctx,
    ossl_unused unsigned char *out,
    ossl_unused size_t *outl,
    ossl_unused size_t outsize,
    ossl_unused const unsigned char *in,
    ossl_unused size_t inl
)
{
    // TODO: Process cipher update
    return 0;
}

static int azihsm_ossl_cipher_final(
    ossl_unused void *cctx,
    ossl_unused unsigned char *out,
    ossl_unused size_t *outl,
    ossl_unused size_t outsize
)
{
    // TODO: Finalize cipher operation
    return 0;
}

static int azihsm_ossl_cipher_cipher(
    ossl_unused void *cctx,
    ossl_unused unsigned char *out,
    ossl_unused size_t *outl,
    ossl_unused size_t outsize,
    ossl_unused const unsigned char *in,
    ossl_unused size_t inl
)
{
    // TODO: One-shot cipher operation
    return 0;
}

/* Cipher Parameter Functions */

static int azihsm_ossl_cipher_get_params(
    OSSL_PARAM params[],
    unsigned int mode,
    size_t keylen,
    size_t blksize,
    size_t ivlen,
    ossl_unused unsigned long flags
)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksize))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
    {
        return 0;
    }

    return 1;
}

/* AES-128-CBC */
static int azihsm_ossl_aes128cbc_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_CBC_MODE, 16, 16, 16, 0);
}

/* AES-192-CBC */
static int azihsm_ossl_aes192cbc_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_CBC_MODE, 24, 16, 16, 0);
}

/* AES-256-CBC */
static int azihsm_ossl_aes256cbc_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_CBC_MODE, 32, 16, 16, 0);
}

/* AES-128-XTS */
static int azihsm_ossl_aes128xts_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_XTS_MODE, 32, 16, 16, 0);
}

/* AES-256-XTS */
static int azihsm_ossl_aes256xts_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_XTS_MODE, 64, 16, 16, 0);
}

static int azihsm_ossl_cipher_get_ctx_params(
    ossl_unused void *cctx,
    ossl_unused OSSL_PARAM params[]
)
{
    // TODO: Get cipher context parameters
    return 0;
}

static int azihsm_ossl_cipher_set_ctx_params(
    ossl_unused void *cctx,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Set cipher context parameters
    return 0;
}

/* Cipher Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_cipher_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_cipher_gettable_ctx_params(
    ossl_unused void *cctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_cipher_settable_ctx_params(
    ossl_unused void *cctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

#define IMPLEMENT_AZIHSM_OSSL_CIPHER(alg)                                                          \
    const OSSL_DISPATCH azihsm_ossl_##alg##_functions[] = {                                        \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))azihsm_ossl_cipher_newctx },                    \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))azihsm_ossl_cipher_freectx },                  \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))azihsm_ossl_cipher_dupctx },                    \
                                                                                                   \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))azihsm_ossl_cipher_encrypt_init },        \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))azihsm_ossl_cipher_decrypt_init },        \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))azihsm_ossl_cipher_update },                    \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))azihsm_ossl_cipher_final },                      \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))azihsm_ossl_cipher_cipher },                    \
                                                                                                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))azihsm_ossl_##alg##_get_params },           \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_cipher_get_ctx_params },    \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_cipher_set_ctx_params },    \
                                                                                                   \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_cipher_gettable_params },  \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                                    \
          (void (*)(void))azihsm_ossl_cipher_gettable_ctx_params },                                \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                                    \
          (void (*)(void))azihsm_ossl_cipher_settable_ctx_params },                                \
        { 0, NULL }                                                                                \
    };

IMPLEMENT_AZIHSM_OSSL_CIPHER(aes128cbc)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes192cbc)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes256cbc)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes128xts)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes256xts)

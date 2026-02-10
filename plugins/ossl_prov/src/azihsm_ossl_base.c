// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _DEFAULT_SOURCE
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/prov_ssl.h>
#include <openssl/proverr.h>
#include <strings.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_names.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ALG(names, funcs)                                                                          \
    {                                                                                              \
        names, "provider=" AZIHSM_OSSL_NAME ",fips=yes", funcs, NULL                               \
    }

#define ALG_TABLE_END                                                                              \
    {                                                                                              \
        NULL, NULL, NULL, NULL                                                                     \
    }

static OSSL_FUNC_core_get_params_fn *core_get_params;

// Digest
extern const OSSL_DISPATCH azihsm_ossl_sha1_functions[];
extern const OSSL_DISPATCH azihsm_ossl_sha256_functions[];
extern const OSSL_DISPATCH azihsm_ossl_sha384_functions[];
extern const OSSL_DISPATCH azihsm_ossl_sha512_functions[];

static const OSSL_ALGORITHM azihsm_ossl_digest[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_SHA1, azihsm_ossl_sha1_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_SHA256, azihsm_ossl_sha256_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_SHA384, azihsm_ossl_sha384_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_SHA512, azihsm_ossl_sha512_functions),
    ALG_TABLE_END
};

// Cipher
extern const OSSL_DISPATCH azihsm_ossl_aes128cbc_functions[];
extern const OSSL_DISPATCH azihsm_ossl_aes192cbc_functions[];
extern const OSSL_DISPATCH azihsm_ossl_aes256cbc_functions[];
extern const OSSL_DISPATCH azihsm_ossl_aes128xts_functions[];
extern const OSSL_DISPATCH azihsm_ossl_aes256xts_functions[];

static const OSSL_ALGORITHM azihsm_ossl_cipher[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_AES_128_CBC, azihsm_ossl_aes128cbc_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_192_CBC, azihsm_ossl_aes192cbc_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_256_CBC, azihsm_ossl_aes256cbc_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_128_XTS, azihsm_ossl_aes128xts_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_256_XTS, azihsm_ossl_aes256xts_functions),
    ALG_TABLE_END
};

// MAC
extern const OSSL_DISPATCH azihsm_ossl_hmac_functions[];

static const OSSL_ALGORITHM azihsm_ossl_mac[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_HMAC, azihsm_ossl_hmac_functions),
    ALG_TABLE_END,
};

// KDF
extern const OSSL_DISPATCH azihsm_ossl_hkdf_functions[];
extern const OSSL_DISPATCH azihsm_ossl_kbkdf_functions[];

static const OSSL_ALGORITHM azihsm_ossl_kdf[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_HKDF, azihsm_ossl_hkdf_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_KBKDF, azihsm_ossl_kbkdf_functions),
    ALG_TABLE_END
};

static const OSSL_ALGORITHM azihsm_ossl_rand[] = { ALG_TABLE_END };

// Key Management
extern const OSSL_DISPATCH azihsm_ossl_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH azihsm_ossl_rsa_pss_keymgmt_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_keymgmt_functions[];

static const OSSL_ALGORITHM azihsm_ossl_keymgmt[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_RSA, azihsm_ossl_rsa_keymgmt_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_RSA_PSS, azihsm_ossl_rsa_pss_keymgmt_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_EC, azihsm_ossl_ec_keymgmt_functions),
    ALG_TABLE_END,
};

// Key Exchange
extern const OSSL_DISPATCH azihsm_ossl_ecdh_functions[];

static const OSSL_ALGORITHM azihsm_ossl_keyexch[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_ECDH, azihsm_ossl_ecdh_functions),
    ALG_TABLE_END,
};

// Signature
extern const OSSL_DISPATCH azihsm_ossl_rsa_signature_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ecdsa_signature_functions[];

static const OSSL_ALGORITHM azihsm_ossl_signature[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_RSA, azihsm_ossl_rsa_signature_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_EC, azihsm_ossl_ecdsa_signature_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_ECDSA, azihsm_ossl_ecdsa_signature_functions),
    ALG_TABLE_END
};

// Asymmetric Cipher
extern const OSSL_DISPATCH azihsm_ossl_rsa_asym_cipher_functions[];

static const OSSL_ALGORITHM azihsm_ossl_asym_cipher[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_RSA, azihsm_ossl_rsa_asym_cipher_functions),
    ALG_TABLE_END
};

// Encoders
extern const OSSL_DISPATCH azihsm_ossl_rsa_text_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_rsa_der_spki_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_rsa_der_pki_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_text_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_der_spki_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_der_pki_encoder_functions[];

// Store
extern const OSSL_DISPATCH azihsm_ossl_store_functions[];

static const OSSL_ALGORITHM azihsm_ossl_encoders[] = {
    {
        "RSA",
        "provider=azihsm,output=text",
        azihsm_ossl_rsa_text_encoder_functions,
        NULL,
    },
    {
        "RSA",
        "provider=azihsm,output=der,structure=type-specific",
        azihsm_ossl_rsa_der_spki_encoder_functions,
        NULL,
    },
    {
        "RSA",
        "provider=azihsm,output=der,structure=PrivateKeyInfo",
        azihsm_ossl_rsa_der_pki_encoder_functions,
        NULL,
    },
    {
        "RSA-PSS",
        "provider=azihsm,output=text",
        azihsm_ossl_rsa_text_encoder_functions,
        NULL,
    },
    {
        "RSA-PSS",
        "provider=azihsm,output=der,structure=type-specific",
        azihsm_ossl_rsa_der_spki_encoder_functions,
        NULL,
    },
    {
        "RSA-PSS",
        "provider=azihsm,output=der,structure=PrivateKeyInfo",
        azihsm_ossl_rsa_der_pki_encoder_functions,
        NULL,
    },
    {
        "EC",
        "provider=azihsm,output=text",
        azihsm_ossl_ec_text_encoder_functions,
        NULL,
    },
    {
        "EC",
        "provider=azihsm,output=der,structure=type-specific",
        azihsm_ossl_ec_der_spki_encoder_functions,
        NULL,
    },
    {
        "EC",
        "provider=azihsm,output=der,structure=PrivateKeyInfo",
        azihsm_ossl_ec_der_pki_encoder_functions,
        NULL,
    },
    { NULL, NULL, NULL, NULL },
};

// Store
static const OSSL_ALGORITHM azihsm_ossl_store[] = {
    { "azihsm", "provider=azihsm", azihsm_ossl_store_functions, NULL },
    ALG_TABLE_END
};

static void azihsm_ossl_teardown(AZIHSM_OSSL_PROV_CTX *provctx)
{
    if (provctx == NULL)
    {
        return;
    }

    if (provctx->libctx != NULL)
    {
        OSSL_LIB_CTX_free(provctx->libctx);
    }

    /* Delete cached unwrapping key handles before closing session */
    if (provctx->unwrapping_key.pub != 0)
    {
        azihsm_key_delete(provctx->unwrapping_key.pub);
        provctx->unwrapping_key.pub = 0;
    }
    if (provctx->unwrapping_key.priv != 0)
    {
        azihsm_key_delete(provctx->unwrapping_key.priv);
        provctx->unwrapping_key.priv = 0;
    }
    CRYPTO_THREAD_lock_free(provctx->unwrapping_key.lock);

    azihsm_close_device_and_session(provctx->device, provctx->session);
    OPENSSL_free(provctx);
}

static const OSSL_PARAM *azihsm_ossl_gettable_params(ossl_unused void *provctx)
{
    return azihsm_ossl_param_types;
}

static OSSL_STATUS azihsm_ossl_get_params(ossl_unused void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, AZIHSM_OSSL_NAME))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return OSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, AZIHSM_OSSL_VERSION))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return OSSL_FAILURE;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, AZIHSM_OSSL_VERSION))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static const OSSL_ALGORITHM *azihsm_ossl_query_operation(
    ossl_unused void *provctx,
    int operation_id,
    int *no_store
)
{
    // Dispatch tables do not change and may be cached
    *no_store = 0;
    switch (operation_id)
    {
    case OSSL_OP_DIGEST:
        return azihsm_ossl_digest;
    case OSSL_OP_CIPHER:
        return azihsm_ossl_cipher;
    case OSSL_OP_MAC:
        return azihsm_ossl_mac;
    case OSSL_OP_KDF:
        return azihsm_ossl_kdf;
    case OSSL_OP_RAND:
        return azihsm_ossl_rand;
    case OSSL_OP_KEYMGMT:
        return azihsm_ossl_keymgmt;
    case OSSL_OP_KEYEXCH:
        return azihsm_ossl_keyexch;
    case OSSL_OP_SIGNATURE:
        return azihsm_ossl_signature;
    case OSSL_OP_ASYM_CIPHER:
        return azihsm_ossl_asym_cipher;
    case OSSL_OP_ENCODER:
        return azihsm_ossl_encoders;
    case OSSL_OP_STORE:
        return azihsm_ossl_store;
    }

    return NULL;
}

static OSSL_STATUS azihsm_ossl_get_capabilities(
    ossl_unused void *provctx,
    ossl_unused const char *capability,
    ossl_unused OSSL_CALLBACK *cb,
    ossl_unused void *arg
)
{
    return OSSL_FAILURE;
}

static const OSSL_DISPATCH azihsm_ossl_base_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))azihsm_ossl_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))azihsm_ossl_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))azihsm_ossl_query_operation },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))azihsm_ossl_get_capabilities },
    { 0, NULL },
};

OSSL_STATUS OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx
)
{
    AZIHSM_OSSL_PROV_CTX *ctx;
    azihsm_status status;

    if ((ctx = OPENSSL_zalloc(sizeof(AZIHSM_OSSL_PROV_CTX))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return OSSL_FAILURE;
    }

    ctx->handle = handle;
    ctx->libctx = OSSL_LIB_CTX_new_child(handle, in);

    if (ctx->libctx == NULL)
    {
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
    }

    ctx->unwrapping_key.lock = CRYPTO_THREAD_lock_new();
    if (ctx->unwrapping_key.lock == NULL)
    {
        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
    }

    /* Initialize config with hardcoded default paths */
    snprintf(ctx->config.bmk_path, sizeof(ctx->config.bmk_path), "%s", AZIHSM_DEFAULT_BMK_PATH);
    snprintf(ctx->config.muk_path, sizeof(ctx->config.muk_path), "%s", AZIHSM_DEFAULT_MUK_PATH);
    snprintf(ctx->config.obk_path, sizeof(ctx->config.obk_path), "%s", AZIHSM_DEFAULT_OBK_PATH);

    status = azihsm_open_device_and_session(&ctx->config, &ctx->device, &ctx->session);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INIT_FAIL);

        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
    }

    for (; in->function_id != 0; in++)
    {

        switch (in->function_id)
        {

        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(in);
            break;
        }
    }

    *provctx = ctx;
    *out = azihsm_ossl_base_dispatch;

    return OSSL_SUCCESS;
}

#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0
EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in)
{
    EVP_MD_CTX *out = EVP_MD_CTX_new();

    if (out != NULL && !EVP_MD_CTX_copy_ex(out, in))
    {
        EVP_MD_CTX_free(out);
        out = NULL;
    }
    return out;
}

#if OPENSSL_VERSION_PATCH < 4
int OPENSSL_strcasecmp(const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}
#endif // OPENSSL_VERSION_PATCH < 4

#endif // OPENSSL_VERSION_MINOR == 0

#ifdef __cplusplus
}
#endif

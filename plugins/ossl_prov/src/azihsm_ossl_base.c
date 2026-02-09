// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _DEFAULT_SOURCE
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/prov_ssl.h>
#include <openssl/proverr.h>
#include <stdlib.h>
#include <string.h>
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

/*
 * Helper to strip "file:" prefix from path if present.
 * Returns pointer to the actual path (may be the original string or offset by 5).
 */
static const char *strip_file_prefix(const char *path)
{
    if (path == NULL)
    {
        return NULL;
    }
    if (strncmp(path, "file:", 5) == 0)
    {
        return path + 5;
    }
    return path;
}

/*
 * Validate that all required config fields are non-NULL.
 * Returns 1 if valid, 0 if any required field is NULL.
 */
static int azihsm_config_is_valid(const AZIHSM_CONFIG *config)
{
    if (config == NULL)
    {
        return 0;
    }
    return config->credentials_id_path != NULL && config->credentials_pin_path != NULL &&
           config->bmk_path != NULL && config->muk_path != NULL && config->mobk_path != NULL;
}

/*
 * Validate that the API revision is within the supported range.
 * Returns 1 if valid, 0 if out of range.
 */
static int azihsm_api_revision_is_valid(const AZIHSM_CONFIG *config)
{
    uint32_t version;
    uint32_t min_version;
    uint32_t max_version;

    if (config == NULL)
    {
        return 0;
    }

    /* Combine major.minor into a single comparable value */
    version = ((uint32_t)config->api_revision_major << 16) | config->api_revision_minor;
    min_version = ((uint32_t)AZIHSM_API_REVISION_MIN_MAJOR << 16) | AZIHSM_API_REVISION_MIN_MINOR;
    max_version = ((uint32_t)AZIHSM_API_REVISION_MAX_MAJOR << 16) | AZIHSM_API_REVISION_MAX_MINOR;

    return version >= min_version && version <= max_version;
}

/*
 * Get path from environment variable, falling back to default if not set.
 * Returns a newly allocated string that must be freed with OPENSSL_free.
 */
static char *get_path_from_env_or_default(const char *env_var, const char *default_path)
{
    const char *env_value = getenv(env_var);
    if (env_value != NULL && env_value[0] != '\0')
    {
        return OPENSSL_strdup(env_value);
    }
    return OPENSSL_strdup(default_path);
}

/*
 * Parse configuration parameters from OpenSSL config file.
 * Returns a populated AZIHSM_CONFIG structure with all path fields set.
 *
 * If OPENSSL_strdup fails for any allocation, the corresponding field will be NULL.
 * Caller MUST check azihsm_config_is_valid() after this call to detect allocation
 * failures before using the config. On validation failure, caller should call
 * azihsm_config_free() to clean up any partially allocated fields.
 */
static AZIHSM_CONFIG parse_provider_config(
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_get_params_fn *get_params
)
{
    AZIHSM_CONFIG config = {
        NULL, NULL, NULL, NULL, NULL,
        AZIHSM_API_REVISION_DEFAULT_MAJOR,
        AZIHSM_API_REVISION_DEFAULT_MINOR
    };
    const char *bmk_path = NULL;
    const char *muk_path = NULL;
    const char *mobk_path = NULL;
    const char *api_revision = NULL;

    OSSL_PARAM core_params[] = {
        OSSL_PARAM_construct_utf8_ptr(AZIHSM_CFG_BMK_PATH, (char **)&bmk_path, sizeof(void *)),
        OSSL_PARAM_construct_utf8_ptr(AZIHSM_CFG_MUK_PATH, (char **)&muk_path, sizeof(void *)),
        OSSL_PARAM_construct_utf8_ptr(AZIHSM_CFG_MOBK_PATH, (char **)&mobk_path, sizeof(void *)),
        OSSL_PARAM_construct_utf8_ptr(
            AZIHSM_CFG_API_REVISION,
            (char **)&api_revision,
            sizeof(void *)
        ),
        OSSL_PARAM_construct_end()
    };

    /* Fetch parameters from OpenSSL core (returns 1 on success, 0 on failure) */
    if (get_params != NULL && get_params(handle, core_params) == 1)
    {
        /* Copy values with file: prefix handling for key paths */
        if (bmk_path != NULL)
        {
            config.bmk_path = OPENSSL_strdup(strip_file_prefix(bmk_path));
        }
        if (muk_path != NULL)
        {
            config.muk_path = OPENSSL_strdup(strip_file_prefix(muk_path));
        }
        if (mobk_path != NULL)
        {
            config.mobk_path = OPENSSL_strdup(strip_file_prefix(mobk_path));
        }
        if (api_revision != NULL)
        {
            unsigned int major = 0, minor = 0;
            if (sscanf(api_revision, "%u.%u", &major, &minor) == 2)
            {
                config.api_revision_major = (uint16_t)major;
                config.api_revision_minor = (uint16_t)minor;
            }
        }
    }

    /* Apply defaults for any paths not provided in config.
     * Credentials: environment variable > hardcoded default (not in openssl.cnf)
     * Key paths: openssl.cnf > hardcoded default */
    config.credentials_id_path = get_path_from_env_or_default(
        AZIHSM_ENV_CREDENTIALS_ID_PATH, AZIHSM_DEFAULT_CREDENTIALS_ID_PATH);
    config.credentials_pin_path = get_path_from_env_or_default(
        AZIHSM_ENV_CREDENTIALS_PIN_PATH, AZIHSM_DEFAULT_CREDENTIALS_PIN_PATH);
    if (config.bmk_path == NULL)
    {
        config.bmk_path = OPENSSL_strdup(AZIHSM_DEFAULT_BMK_PATH);
    }
    if (config.muk_path == NULL)
    {
        config.muk_path = OPENSSL_strdup(AZIHSM_DEFAULT_MUK_PATH);
    }
    if (config.mobk_path == NULL)
    {
        config.mobk_path = OPENSSL_strdup(AZIHSM_DEFAULT_MOBK_PATH);
    }

    return config;
}

OSSL_STATUS OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx
)
{
    AZIHSM_OSSL_PROV_CTX *ctx;
    AZIHSM_CONFIG config = { NULL, NULL, NULL, NULL, NULL };
    azihsm_status status;
    const OSSL_DISPATCH *in_iter;

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

    /* First pass: find core_get_params function */
    for (in_iter = in; in_iter->function_id != 0; in_iter++)
    {
        if (in_iter->function_id == OSSL_FUNC_CORE_GET_PARAMS)
        {
            core_get_params = OSSL_FUNC_core_get_params(in_iter);
            break;
        }
    }

    /* Parse configuration from openssl.cnf */
    config = parse_provider_config(handle, core_get_params);

    /* Validate configuration (check for allocation failures) */
    if (!azihsm_config_is_valid(&config))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        azihsm_config_free(&config);
        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
    }

    /* Validate API revision is within supported range */
    if (!azihsm_api_revision_is_valid(&config))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
        azihsm_config_free(&config);
        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
    }

    /* Open device and session with configuration */
    status = azihsm_open_device_and_session(&config, &ctx->device, &ctx->session);

    /* Free configuration (no longer needed) */
    azihsm_config_free(&config);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INIT_FAIL);

        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
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

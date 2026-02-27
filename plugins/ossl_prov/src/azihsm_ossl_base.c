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
// KBKDF not yet implemented - empty dispatch table would cause OpenSSL to reject all KDFs
// extern const OSSL_DISPATCH azihsm_ossl_kbkdf_functions[];

static const OSSL_ALGORITHM azihsm_ossl_kdf[] = { ALG(AZIHSM_OSSL_ALG_NAME_HKDF,
                                                      azihsm_ossl_hkdf_functions),
                                                  ALG_TABLE_END };

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
    ALG(AZIHSM_OSSL_ALG_NAME_RSA_PSS, azihsm_ossl_rsa_signature_functions),
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
extern const OSSL_DISPATCH azihsm_ossl_rsa_pem_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_text_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_der_spki_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_der_pki_encoder_functions[];
extern const OSSL_DISPATCH azihsm_ossl_ec_pem_encoder_functions[];

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
        "provider=azihsm,output=der,structure=SubjectPublicKeyInfo",
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
        "RSA",
        "provider=azihsm,output=pem,structure=PrivateKeyInfo",
        azihsm_ossl_rsa_pem_encoder_functions,
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
        "provider=azihsm,output=der,structure=SubjectPublicKeyInfo",
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
        "RSA-PSS",
        "provider=azihsm,output=pem,structure=PrivateKeyInfo",
        azihsm_ossl_rsa_pem_encoder_functions,
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
        "provider=azihsm,output=der,structure=SubjectPublicKeyInfo",
        azihsm_ossl_ec_der_spki_encoder_functions,
        NULL,
    },
    {
        "EC",
        "provider=azihsm,output=der,structure=PrivateKeyInfo",
        azihsm_ossl_ec_der_pki_encoder_functions,
        NULL,
    },
    {
        "EC",
        "provider=azihsm,output=pem,structure=PrivateKeyInfo",
        azihsm_ossl_ec_pem_encoder_functions,
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

    /* Delete cached unwrapping key handles before closing session.
     * No lock needed: OpenSSL guarantees no operations are in flight at teardown. */
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
    /* Return SUCCESS to indicate "no capabilities to report" rather than
     * FAILURE which signals an error.  Returning FAILURE breaks SSL_CTX_new()
     * because OpenSSL interprets it as a TLS-GROUP query error and aborts
     * cipher suite setup. */
    return OSSL_SUCCESS;
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
 * Strips the "file:" prefix that OpenSSL prepends to config file path values.
 * Returns a pointer into the original string (no allocation).
 */
static const char *strip_file_prefix(const char *path)
{
    if (path != NULL && strncmp(path, "file:", 5) == 0)
    {
        return path + 5;
    }
    return path;
}

/*
 * Validates that the configured API revision falls within the supported range.
 * Combines major.minor into a single 32-bit value for range comparison.
 * Returns 1 if valid, 0 otherwise.
 */
static int azihsm_api_revision_is_valid(const AZIHSM_CONFIG *config)
{
    uint32_t version;
    uint32_t min_version;
    uint32_t max_version;

    version = ((uint32_t)config->api_revision_major << 16) | config->api_revision_minor;
    min_version = ((uint32_t)AZIHSM_API_REVISION_MIN_MAJOR << 16) | AZIHSM_API_REVISION_MIN_MINOR;
    max_version = ((uint32_t)AZIHSM_API_REVISION_MAX_MAJOR << 16) | AZIHSM_API_REVISION_MAX_MINOR;

    return (version >= min_version && version <= max_version);
}

/*
 * Populates a fixed-size path buffer from an environment variable,
 * falling back to a default if the env var is unset or empty.
 */
static void load_path_from_env_or_default(
    char *dest,
    size_t dest_size,
    const char *env_var,
    const char *default_path
)
{
    const char *env_val = getenv(env_var);

    if (env_val != NULL && env_val[0] != '\0')
    {
        snprintf(dest, dest_size, "%s", env_val);
    }
    else
    {
        snprintf(dest, dest_size, "%s", default_path);
    }
}

/*
 * Parses provider configuration from the OpenSSL config file (openssl.cnf)
 * and environment variables into the provider context's config struct.
 *
 * Key paths (BMK, MUK, OBK) are read from openssl.cnf with fallback to defaults.
 * Credential paths are read from environment variables only (not openssl.cnf) for security.
 * API revision is parsed from openssl.cnf in "major.minor" format.
 */
static void parse_provider_config(
    AZIHSM_CONFIG *config,
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_get_params_fn *get_params_fn
)
{
    char *bmk_path = NULL;
    char *muk_path = NULL;
    char *obk_path = NULL;
    char *api_revision = NULL;

    /* Set defaults for all fields */
    snprintf(config->bmk_path, sizeof(config->bmk_path), "%s", AZIHSM_DEFAULT_BMK_PATH);
    snprintf(config->muk_path, sizeof(config->muk_path), "%s", AZIHSM_DEFAULT_MUK_PATH);
    snprintf(config->obk_path, sizeof(config->obk_path), "%s", AZIHSM_DEFAULT_OBK_PATH);
    config->api_revision_major = AZIHSM_API_REVISION_DEFAULT_MAJOR;
    config->api_revision_minor = AZIHSM_API_REVISION_DEFAULT_MINOR;

    /* Credentials: env vars only (security-sensitive, not in openssl.cnf) */
    load_path_from_env_or_default(
        config->credentials_id_path,
        sizeof(config->credentials_id_path),
        AZIHSM_ENV_CREDENTIALS_ID_PATH,
        AZIHSM_DEFAULT_CREDENTIALS_ID_PATH
    );
    load_path_from_env_or_default(
        config->credentials_pin_path,
        sizeof(config->credentials_pin_path),
        AZIHSM_ENV_CREDENTIALS_PIN_PATH,
        AZIHSM_DEFAULT_CREDENTIALS_PIN_PATH
    );

    if (get_params_fn == NULL)
    {
        return;
    }

    /* Query key paths and API revision from openssl.cnf */
    OSSL_PARAM config_params[] = { OSSL_PARAM_utf8_ptr(AZIHSM_CFG_BMK_PATH, &bmk_path, 0),
                                   OSSL_PARAM_utf8_ptr(AZIHSM_CFG_MUK_PATH, &muk_path, 0),
                                   OSSL_PARAM_utf8_ptr(AZIHSM_CFG_OBK_PATH, &obk_path, 0),
                                   OSSL_PARAM_utf8_ptr(AZIHSM_CFG_API_REVISION, &api_revision, 0),
                                   OSSL_PARAM_END };

    if (get_params_fn(handle, config_params) != 1)
    {
        return;
    }

    /* Override defaults with configured values, stripping "file:" prefix */
    if (bmk_path != NULL)
    {
        snprintf(config->bmk_path, sizeof(config->bmk_path), "%s", strip_file_prefix(bmk_path));
    }
    if (muk_path != NULL)
    {
        snprintf(config->muk_path, sizeof(config->muk_path), "%s", strip_file_prefix(muk_path));
    }
    if (obk_path != NULL)
    {
        snprintf(config->obk_path, sizeof(config->obk_path), "%s", strip_file_prefix(obk_path));
    }

    /* Parse API revision in "major.minor" format */
    if (api_revision != NULL)
    {
        unsigned int major = 0;
        unsigned int minor = 0;
        if (sscanf(api_revision, "%u.%u", &major, &minor) == 2)
        {
            config->api_revision_major = (uint16_t)major;
            config->api_revision_minor = (uint16_t)minor;
        }
        else
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_CONFIG_DATA,
                "invalid api-revision format '%s', expected 'major.minor' (e.g. '1.0')",
                api_revision
            );
        }
    }
}

OSSL_STATUS OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx
)
{
    AZIHSM_OSSL_PROV_CTX *ctx;
    azihsm_status status;
    const OSSL_DISPATCH *in_iter;
    OSSL_FUNC_core_get_params_fn *get_params_fn = NULL;

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

    /* Find core_get_params before using it for config parsing */
    for (in_iter = in; in_iter->function_id != 0; in_iter++)
    {
        if (in_iter->function_id == OSSL_FUNC_CORE_GET_PARAMS)
        {
            get_params_fn = OSSL_FUNC_core_get_params(in_iter);
            core_get_params = get_params_fn;
            break;
        }
    }

    /* Parse configuration from openssl.cnf and environment variables */
    parse_provider_config(&ctx->config, handle, get_params_fn);

    /* Validate API revision is within supported range */
    if (!azihsm_api_revision_is_valid(&ctx->config))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "API revision %u.%u is outside supported range %u.%u - %u.%u",
            ctx->config.api_revision_major,
            ctx->config.api_revision_minor,
            AZIHSM_API_REVISION_MIN_MAJOR,
            AZIHSM_API_REVISION_MIN_MINOR,
            AZIHSM_API_REVISION_MAX_MAJOR,
            AZIHSM_API_REVISION_MAX_MINOR
        );
        CRYPTO_THREAD_lock_free(ctx->unwrapping_key.lock);
        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
        return OSSL_FAILURE;
    }

    status = azihsm_open_device_and_session(&ctx->config, &ctx->device, &ctx->session);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INIT_FAIL);

        CRYPTO_THREAD_lock_free(ctx->unwrapping_key.lock);
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

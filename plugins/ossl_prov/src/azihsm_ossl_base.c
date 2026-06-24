// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _DEFAULT_SOURCE
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/prov_ssl.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_names.h"
#include "azihsm_ossl_resiliency.h"

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
extern const OSSL_DISPATCH azihsm_ossl_aes256gcm_functions[];
extern const OSSL_DISPATCH azihsm_ossl_aes128xts_functions[];
extern const OSSL_DISPATCH azihsm_ossl_aes256xts_functions[];

static const OSSL_ALGORITHM azihsm_ossl_cipher[] = {
    ALG(AZIHSM_OSSL_ALG_NAME_AES_128_CBC, azihsm_ossl_aes128cbc_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_192_CBC, azihsm_ossl_aes192cbc_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_256_CBC, azihsm_ossl_aes256cbc_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_256_GCM, azihsm_ossl_aes256gcm_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_128_XTS, azihsm_ossl_aes128xts_functions),
    ALG(AZIHSM_OSSL_ALG_NAME_AES_256_XTS, azihsm_ossl_aes256xts_functions),
    ALG_TABLE_END
};

// Symmetric Key Management (SKEYMGMT, OpenSSL 3.5+)
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
extern const OSSL_DISPATCH azihsm_ossl_aes_skeymgmt_functions[];

static const OSSL_ALGORITHM azihsm_ossl_skeymgmt[] = { ALG(AZIHSM_OSSL_ALG_NAME_AES_SKEYMGMT,
                                                           azihsm_ossl_aes_skeymgmt_functions),
                                                       ALG_TABLE_END };
#endif

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
    CRYPTO_THREAD_lock_free(provctx->session_lock);

    /* Destroy resiliency context before closing the device */
    if (provctx->resiliency_ctx != NULL)
    {
        azihsm_resiliency_destroy(provctx->resiliency_ctx);
        provctx->resiliency_ctx = NULL;
    }

    azihsm_close_device_and_session(provctx->device, provctx->session);

    /* Release the default provider reference we acquired in OSSL_provider_init
     * to keep the NULL library context's default provider active. */
    if (provctx->default_provider != NULL)
    {
        OSSL_PROVIDER_unload(provctx->default_provider);
    }

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
    /* query_operation is a pure discovery callback.  OpenSSL invokes it from
     * inside libcrypto initialisation paths — notably EVP_RAND_instantiate,
     * which fetches its AES cipher provider while the global DRBG is being
     * brought up.  Any work performed here that calls back into libcrypto
     * (for example opening the HSM session, which in turn instantiates the
     * simulator backend and asks libcrypto for random bytes / EC keys) would
     * re-enter the very initialisation path that is on the stack, deadlock
     * the OpenSSL Once cell guarding DRBG init, and ultimately poison the
     * lazy-initialised dispatcher in the mock DDI.  See the integration test
     * `nginx_tests` and the design note in azihsm_ossl_hsm.c
     * (azihsm_ensure_session) for the full backtrace.
     *
     * The dispatch tables are static, so we always return them
     * unconditionally and defer azihsm_ensure_session() to each algorithm's
     * first real entry point (newctx / open / init). */
    *no_store = 0;
    switch (operation_id)
    {
    case OSSL_OP_DIGEST:
        return azihsm_ossl_digest;
    case OSSL_OP_CIPHER:
        return azihsm_ossl_cipher;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    case OSSL_OP_SKEYMGMT:
        return azihsm_ossl_skeymgmt;
#endif
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
    default:
        return NULL;
    }
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

/* Returns non-zero if c is a valid hexadecimal digit (0-9, a-f, A-F). */
static int is_hex_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/*
 * Decodes a hex-encoded credential string into a binary output buffer.
 *
 * The hex string must be exactly AZIHSM_CREDENTIALS_HEX_SIZE characters long
 * and contain only valid hex digits (0-9, a-f, A-F).  On any error the output
 * buffer is cleansed and a descriptive message is pushed to the OpenSSL error
 * stack including the environment variable name for diagnostics.
 *
 * Returns OSSL_SUCCESS on success, OSSL_FAILURE on error.
 */
static OSSL_STATUS hex_decode_credentials(const char *env_name, const char *hex_str, uint8_t *out)
{
    size_t len = strlen(hex_str);

    if (len != AZIHSM_CREDENTIALS_HEX_SIZE)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "%s must be exactly %d hex characters, got %zu",
            env_name,
            AZIHSM_CREDENTIALS_HEX_SIZE,
            len
        );
        return OSSL_FAILURE;
    }

    for (size_t i = 0; i < AZIHSM_CREDENTIALS_SIZE; i++)
    {
        unsigned int byte_val = 0;
        char pair[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };

        if (!is_hex_char(pair[0]) || !is_hex_char(pair[1]))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_CONFIG_DATA,
                "%s contains invalid hex character at position %zu",
                env_name,
                i * 2
            );
            OPENSSL_cleanse(out, AZIHSM_CREDENTIALS_SIZE);
            return OSSL_FAILURE;
        }

        sscanf(pair, "%02x", &byte_val);
        out[i] = (uint8_t)byte_val;
    }

    return OSSL_SUCCESS;
}

/* Returns non-zero if path is safe to use as a credential file path. */
static int azihsm_path_is_safe(const char *path)
{
    if (path == NULL || path[0] == '\0')
    {
        return 0;
    }
    if (strstr(path, "..") != NULL)
    {
        return 0;
    }
    return 1;
}

/*
 * Parses provider configuration from the OpenSSL config file (openssl.cnf)
 * and environment variables into the provider context's config struct.
 *
 * Key paths (BMK, MUK, OBK) are read from openssl.cnf with fallback to defaults.
 * Credential paths are read from environment variables only (not openssl.cnf) for security.
 * API revision is parsed from openssl.cnf in "major.minor" format.
 *
 * Returns OSSL_SUCCESS on success, OSSL_FAILURE if credential paths are unsafe.
 */
static OSSL_STATUS parse_provider_config(
    AZIHSM_CONFIG *config,
    const OSSL_CORE_HANDLE *handle,
    OSSL_FUNC_core_get_params_fn *get_params_fn
)
{
    char *bmk_path = NULL;
    char *muk_path = NULL;
    char *obk_path = NULL;
    char *mobk_path = NULL;
    char *obk_source = NULL;
    char *pota_source = NULL;
    char *pota_private_key_path = NULL;
    char *pota_public_key_path = NULL;
    char *api_revision = NULL;

    /* Set defaults for all fields */
    snprintf(config->bmk_path, sizeof(config->bmk_path), "%s", AZIHSM_DEFAULT_BMK_PATH);
    snprintf(config->muk_path, sizeof(config->muk_path), "%s", AZIHSM_DEFAULT_MUK_PATH);
    snprintf(config->obk_path, sizeof(config->obk_path), "%s", AZIHSM_DEFAULT_OBK_PATH);
    snprintf(config->mobk_path, sizeof(config->mobk_path), "%s", AZIHSM_DEFAULT_MOBK_PATH);
    snprintf(
        config->pota_private_key_path,
        sizeof(config->pota_private_key_path),
        "%s",
        AZIHSM_DEFAULT_POTA_PRIVATE_KEY_PATH
    );
    snprintf(
        config->pota_public_key_path,
        sizeof(config->pota_public_key_path),
        "%s",
        AZIHSM_DEFAULT_POTA_PUBLIC_KEY_PATH
    );
    config->api_revision_major = AZIHSM_API_REVISION_DEFAULT_MAJOR;
    config->api_revision_minor = AZIHSM_API_REVISION_DEFAULT_MINOR;
    config->use_tpm_obk = false;
    config->use_tpm_pota = false;
    config->credentials_id_from_env = false;
    config->credentials_pin_from_env = false;

    /* Credentials: hex env var (preferred) or default file in CWD (fallback).
     * ID and PIN resolve independently — one may come from the env var while
     * the other falls back to the default file. */
    {
        const char *id_hex = getenv(AZIHSM_ENV_CREDENTIALS_ID);

        if (id_hex != NULL && id_hex[0] != '\0')
        {
            if (hex_decode_credentials(AZIHSM_ENV_CREDENTIALS_ID, id_hex, config->credentials_id) !=
                OSSL_SUCCESS)
            {
                return OSSL_FAILURE;
            }
            config->credentials_id_from_env = true;
        }
    }

    {
        const char *pin_hex = getenv(AZIHSM_ENV_CREDENTIALS_PIN);

        if (pin_hex != NULL && pin_hex[0] != '\0')
        {
            if (hex_decode_credentials(
                    AZIHSM_ENV_CREDENTIALS_PIN,
                    pin_hex,
                    config->credentials_pin
                ) != OSSL_SUCCESS)
            {
                return OSSL_FAILURE;
            }
            config->credentials_pin_from_env = true;
        }
    }

    if (get_params_fn == NULL)
    {
        return OSSL_SUCCESS;
    }

    /* Query key paths, source selections, and API revision from openssl.cnf */
    OSSL_PARAM config_params[] = {
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_BMK_PATH, &bmk_path, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_MUK_PATH, &muk_path, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_OBK_PATH, &obk_path, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_MOBK_PATH, &mobk_path, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_OBK_SOURCE, &obk_source, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_POTA_SOURCE, &pota_source, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_POTA_PRIVATE_KEY_PATH, &pota_private_key_path, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_POTA_PUBLIC_KEY_PATH, &pota_public_key_path, 0),
        OSSL_PARAM_utf8_ptr(AZIHSM_CFG_API_REVISION, &api_revision, 0),
        OSSL_PARAM_END,
    };

    if (get_params_fn(handle, config_params) != 1)
    {
        return OSSL_SUCCESS;
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
    if (mobk_path != NULL)
    {
        snprintf(config->mobk_path, sizeof(config->mobk_path), "%s", strip_file_prefix(mobk_path));
    }
    if (pota_private_key_path != NULL)
    {
        snprintf(
            config->pota_private_key_path,
            sizeof(config->pota_private_key_path),
            "%s",
            strip_file_prefix(pota_private_key_path)
        );
    }
    if (pota_public_key_path != NULL)
    {
        snprintf(
            config->pota_public_key_path,
            sizeof(config->pota_public_key_path),
            "%s",
            strip_file_prefix(pota_public_key_path)
        );
    }

    /* Validate key-material paths read from openssl.cnf */
    if (!azihsm_path_is_safe(config->bmk_path))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "unsafe BMK path '%s'",
            config->bmk_path
        );
        return OSSL_FAILURE;
    }
    if (!azihsm_path_is_safe(config->muk_path))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "unsafe MUK path '%s'",
            config->muk_path
        );
        return OSSL_FAILURE;
    }
    if (!azihsm_path_is_safe(config->obk_path))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "unsafe OBK path '%s'",
            config->obk_path
        );
        return OSSL_FAILURE;
    }
    if (!azihsm_path_is_safe(config->mobk_path))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "unsafe MOBK path '%s'",
            config->mobk_path
        );
        return OSSL_FAILURE;
    }
    if (!azihsm_path_is_safe(config->pota_private_key_path))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "unsafe POTA private key path '%s'",
            config->pota_private_key_path
        );
        return OSSL_FAILURE;
    }
    if (!azihsm_path_is_safe(config->pota_public_key_path))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_CONFIG_DATA,
            "unsafe POTA public key path '%s'",
            config->pota_public_key_path
        );
        return OSSL_FAILURE;
    }

    /* Parse source selections: "caller" (default) or "tpm" */
    if (obk_source != NULL && OPENSSL_strcasecmp(obk_source, "tpm") == 0)
    {
        config->use_tpm_obk = true;
    }
    if (pota_source != NULL && OPENSSL_strcasecmp(pota_source, "tpm") == 0)
    {
        config->use_tpm_pota = true;
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
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

/*
 * Ensure the OpenSSL default provider is loaded in the process's default
 * library context.
 *
 * The azihsm provider registers standard algorithm names (SHA-256,
 * AES-CBC, RSA, EC, etc.) with the property "provider=azihsm".
 * The Rust HSM library (libazihsm_api_native.so) dynamically links
 * the same libcrypto.so and makes bare EVP calls (no property query).
 * OpenSSL routes those calls to the default provider.
 *
 * If the default provider is not loaded \u2014 for example because
 * openssl.cnf only activates azihsm \u2014 the bare EVP calls would be
 * dispatched to the azihsm provider, creating infinite recursion.
 */
static OSSL_PROVIDER *ensure_default_provider(void)
{
    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(NULL, "default");
    if (dflt == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "azihsm: the OpenSSL 'default' provider must be loaded "
            "alongside the azihsm provider to prevent infinite "
            "recursion in internal crypto operations"
        );
    }
    return dflt;
}

OSSL_STATUS OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx
)
{
    AZIHSM_OSSL_PROV_CTX *ctx;
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
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    ctx->default_provider = ensure_default_provider();
    if (ctx->default_provider == NULL)
    {
        goto cleanup;
    }

    ctx->unwrapping_key.lock = CRYPTO_THREAD_lock_new();
    if (ctx->unwrapping_key.lock == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    ctx->session_lock = CRYPTO_THREAD_lock_new();
    if (ctx->session_lock == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    /* Find get_params_fn from the core dispatch table for config parsing */
    for (in_iter = in; in_iter->function_id != 0; in_iter++)
    {
        if (in_iter->function_id == OSSL_FUNC_CORE_GET_PARAMS)
        {
            get_params_fn = OSSL_FUNC_core_get_params(in_iter);
            break;
        }
    }

    /* Parse configuration from openssl.cnf and environment variables */
    if (parse_provider_config(&ctx->config, handle, get_params_fn) != OSSL_SUCCESS)
    {
        goto cleanup;
    }

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
        goto cleanup;
    }

    /* Check if resiliency is enabled via environment variable */
    const char *res_env = getenv(AZIHSM_RESILIENCY_ENABLED_ENV);
    if (res_env != NULL && (strcmp(res_env, "1") == 0 || OPENSSL_strcasecmp(res_env, "true") == 0))
    {
        const char *dir_env;
        ctx->config.resiliency_enabled = true;

        dir_env = getenv(AZIHSM_RESILIENCY_STORAGE_DIR_ENV);
        const char *dir = (dir_env != NULL && dir_env[0] != '\0')
                              ? dir_env
                              : AZIHSM_DEFAULT_RESILIENCY_STORAGE_DIR;
        if (!azihsm_path_is_safe(dir))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_CONFIG_DATA,
                "unsafe resiliency storage dir '%s'",
                dir
            );
            goto cleanup;
        }
        int ret = snprintf(
            ctx->config.resiliency_storage_dir,
            sizeof(ctx->config.resiliency_storage_dir),
            "%s",
            dir
        );
        if (ret < 0 || (size_t)ret >= sizeof(ctx->config.resiliency_storage_dir))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_CONFIG_DATA,
                "Resiliency storage dir path too long"
            );
            goto cleanup;
        }
    }

    /* Open is deferred to azihsm_ensure_session. */

    *provctx = ctx;
    *out = azihsm_ossl_base_dispatch;

    return OSSL_SUCCESS;

cleanup:
    CRYPTO_THREAD_lock_free(ctx->session_lock);
    CRYPTO_THREAD_lock_free(ctx->unwrapping_key.lock);
    if (ctx->default_provider != NULL)
    {
        OSSL_PROVIDER_unload(ctx->default_provider);
    }
    OSSL_LIB_CTX_free(ctx->libctx);
    OPENSSL_free(ctx);
    return OSSL_FAILURE;
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

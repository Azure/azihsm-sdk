// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_file_io.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_masked_key.h"
#include "azihsm_ossl_pkey_param.h"
#include "azihsm_ossl_skeymgmt.h"

/*
 * AES SKEYMGMT (EVP_SKEY) Implementation
 *
 * This provider implements opaque, HSM-backed symmetric keys for AES.  The
 * EVP_SKEY object holds an HSM key handle rather than raw key material, so key
 * bytes never cross the provider boundary.
 *
 * SKEYMGMT (OSSL_OP_SKEYMGMT) and the OSSL_SKEY_* params exist only in OpenSSL
 * 3.5+.  On older OpenSSL this file is an empty translation unit and the
 * provider does not advertise SKEYMGMT.
 *
 * Key Design:
 * - The keydata (AZIHSM_SKEY) wraps an opaque HSM key handle, not raw key bytes
 * - import accepts a masked-key blob (path via azihsm.masked_key); raw-bytes
 *   import is refused
 * - generate creates a fresh AES/AES-GCM/AES-XTS key in the HSM and can persist
 *   the masked blob to a file (azihsm.masked_key) for later reload
 * - export refuses OSSL_SKEYMGMT_SELECT_SECRET_KEY, so EVP_SKEY_get0_raw_key
 *   always fails (key material never leaves the HSM)
 */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

/* HSM-supported AES key sizes, in bytes. */
#define AZIHSM_AES128_KEY_BYTES 16
#define AZIHSM_AES192_KEY_BYTES 24
#define AZIHSM_AES256_KEY_BYTES 32
#define AZIHSM_AES_XTS_KEY_BYTES 64 /* an AES-256 key pair */

/* Helper: map an azihsm.key_kind string to the HSM key kind + key-generation algo ID */
static int azihsm_skey_kind_from_str(
    const char *s,
    azihsm_key_kind *kind,
    azihsm_algo_id *keygen_algo,
    size_t *default_bytes
)
{
    if (s == NULL || OPENSSL_strcasecmp(s, "AES") == 0)
    {
        *kind = AZIHSM_KEY_KIND_AES;
        *keygen_algo = AZIHSM_ALGO_ID_AES_KEY_GEN;
        *default_bytes = AZIHSM_AES256_KEY_BYTES;
        return 1;
    }
    if (OPENSSL_strcasecmp(s, "AES-GCM") == 0)
    {
        *kind = AZIHSM_KEY_KIND_AES_GCM;
        *keygen_algo = AZIHSM_ALGO_ID_AES_GCM_KEY_GEN;
        *default_bytes = AZIHSM_AES256_KEY_BYTES; /* HSM AES-GCM is 256-bit only */
        return 1;
    }
    if (OPENSSL_strcasecmp(s, "AES-XTS") == 0)
    {
        *kind = AZIHSM_KEY_KIND_AES_XTS;
        *keygen_algo = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;
        *default_bytes = AZIHSM_AES_XTS_KEY_BYTES; /* HSM AES-XTS is a 512-bit key pair */
        return 1;
    }
    return 0;
}

/* Helper: is key_bytes a length the HSM supports for this kind? */
static bool azihsm_skey_key_bytes_supported(azihsm_key_kind kind, size_t key_bytes)
{
    switch (kind)
    {
    case AZIHSM_KEY_KIND_AES_GCM:
        return key_bytes == AZIHSM_AES256_KEY_BYTES;
    case AZIHSM_KEY_KIND_AES_XTS:
        return key_bytes == AZIHSM_AES_XTS_KEY_BYTES;
    default: /* plain AES */
        return key_bytes == AZIHSM_AES128_KEY_BYTES || key_bytes == AZIHSM_AES192_KEY_BYTES ||
               key_bytes == AZIHSM_AES256_KEY_BYTES;
    }
}

/* Helper: read a UTF-8 string parameter into a fixed-size buffer (NUL-terminated) */
static int azihsm_skey_get_str_param(
    const OSSL_PARAM params[],
    const char *key,
    char *out,
    size_t out_size
)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, key);
    char *pout = out;

    if (p == NULL)
    {
        out[0] = '\0';
        return 0; /* absent */
    }
    if (!OSSL_PARAM_get_utf8_string(p, &pout, out_size))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return -1; /* present but invalid */
    }
    return 1; /* present */
}

/* Helper: allocate an AZIHSM_SKEY wrapping a freshly obtained HSM key handle */
static AZIHSM_SKEY *azihsm_skey_new(
    AZIHSM_OSSL_PROV_CTX *provctx,
    azihsm_handle handle,
    azihsm_key_kind kind,
    size_t key_bytes
)
{
    AZIHSM_SKEY *skey = OPENSSL_zalloc(sizeof(AZIHSM_SKEY));
    if (skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    skey->provctx = provctx;
    skey->key_handle = handle;
    skey->key_kind = kind;
    skey->key_bytes = key_bytes;
    BIO_snprintf(skey->key_id, sizeof(skey->key_id), "%u", (unsigned int)handle);
    return skey;
}

/* Key Management Functions */

static void azihsm_ossl_aes_skeymgmt_free(void *keydata)
{
    AZIHSM_SKEY *skey = (AZIHSM_SKEY *)keydata;

    if (skey == NULL)
    {
        return;
    }
    if (skey->key_handle != 0)
    {
        azihsm_key_delete(skey->key_handle);
    }
    OPENSSL_clear_free(skey, sizeof(AZIHSM_SKEY));
}

/* Import an opaque masked-key blob into the HSM. */
static void *azihsm_ossl_aes_skeymgmt_import(
    void *vprovctx,
    int selection,
    const OSSL_PARAM params[]
)
{
    AZIHSM_OSSL_PROV_CTX *provctx = (AZIHSM_OSSL_PROV_CTX *)vprovctx;
    char masked_key_file[AZIHSM_MAX_FILE_PATH];
    char kind_str[16];
    azihsm_key_kind kind = AZIHSM_KEY_KIND_AES;
    azihsm_algo_id keygen_algo; /* unused for import */
    size_t default_bytes = 0;
    size_t key_bytes = 0;
    struct azihsm_buffer masked_buf = { 0 };
    azihsm_handle handle = 0;
    azihsm_status status;
    AZIHSM_SKEY *skey;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return NULL;
    }

    /* Raw key material is never accepted: keys stay opaque inside the HSM. */
    if (params != NULL && OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES) != NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_NOT_SUPPORTED,
            "raw AES key import is not supported; use azihsm.masked_key"
        );
        return NULL;
    }

    if (params == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return NULL;
    }
    switch (azihsm_skey_get_str_param(
        params,
        AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY,
        masked_key_file,
        sizeof(masked_key_file)
    ))
    {
    case 1:
        break;
    case -1:
        return NULL; /* present but invalid; the specific error is already raised */
    default:         /* 0 = absent */
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return NULL;
    }

    if (azihsm_ossl_masked_key_filepath_validate(masked_key_file) < 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return NULL;
    }

    /* Optional kind selector (defaults to plain AES). */
    if (azihsm_skey_get_str_param(
            params,
            AZIHSM_OSSL_PKEY_PARAM_KEY_KIND,
            kind_str,
            sizeof(kind_str)
        ) == 1)
    {
        if (!azihsm_skey_kind_from_str(kind_str, &kind, &keygen_algo, &default_bytes))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return NULL;
        }
        /* GCM/XTS have an HSM-fixed key length; a plain-AES masked blob's length
         * is not derivable from the opaque bytes, so leave key_bytes = 0
         * ("unknown") rather than guess a default. */
        if (kind == AZIHSM_KEY_KIND_AES_GCM || kind == AZIHSM_KEY_KIND_AES_XTS)
        {
            key_bytes = default_bytes;
        }
    }

    if (azihsm_ensure_session(provctx) != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return NULL;
    }

    if (azihsm_file_load(masked_key_file, &masked_buf) != AZIHSM_STATUS_SUCCESS ||
        masked_buf.ptr == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_MISSING_KEY,
            "failed to load masked AES key file '%s'",
            masked_key_file
        );
        return NULL;
    }

    status = azihsm_key_unmask(provctx->session, kind, &masked_buf, &handle);
    OPENSSL_cleanse(masked_buf.ptr, masked_buf.len);
    OPENSSL_free(masked_buf.ptr);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return NULL;
    }

    skey = azihsm_skey_new(provctx, handle, kind, key_bytes);
    if (skey == NULL)
    {
        azihsm_key_delete(handle);
        return NULL;
    }
    return skey;
}

/* Create a fresh AES key inside the HSM. */
static void *azihsm_ossl_aes_skeymgmt_generate(void *vprovctx, const OSSL_PARAM params[])
{
    AZIHSM_OSSL_PROV_CTX *provctx = (AZIHSM_OSSL_PROV_CTX *)vprovctx;
    char masked_key_file[AZIHSM_MAX_FILE_PATH];
    char kind_str[16];
    azihsm_key_kind kind = AZIHSM_KEY_KIND_AES;
    azihsm_algo_id keygen_algo = AZIHSM_ALGO_ID_AES_KEY_GEN;
    size_t default_bytes = AZIHSM_AES256_KEY_BYTES;
    size_t key_bytes = 0;
    bool persist_masked = false;
    uint32_t bits;
    azihsm_handle handle = 0;
    azihsm_status status;
    AZIHSM_SKEY *skey;

    const azihsm_key_class secret_class = AZIHSM_KEY_CLASS_SECRET;
    const bool enable = true;

    if (azihsm_ensure_session(provctx) != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return NULL;
    }

    if (params != NULL)
    {
        const OSSL_PARAM *p;

        /* Kind selector first so we know the default key length. */
        if (azihsm_skey_get_str_param(
                params,
                AZIHSM_OSSL_PKEY_PARAM_KEY_KIND,
                kind_str,
                sizeof(kind_str)
            ) == 1)
        {
            if (!azihsm_skey_kind_from_str(kind_str, &kind, &keygen_algo, &default_bytes))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return NULL;
            }
        }

        key_bytes = default_bytes;

        p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH);
        if (p != NULL && !OSSL_PARAM_get_size_t(p, &key_bytes))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return NULL;
        }

        switch (azihsm_skey_get_str_param(
            params,
            AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY,
            masked_key_file,
            sizeof(masked_key_file)
        ))
        {
        case 1:
            if (azihsm_ossl_masked_key_filepath_validate(masked_key_file) < 0)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return NULL;
            }
            persist_masked = true;
            break;
        case -1:
            return NULL;
        default:
            break;
        }
    }
    else
    {
        key_bytes = default_bytes;
    }

    /* Reject lengths the HSM cannot honour up front, with a clear error, rather
     * than forwarding an unsupported request and failing opaquely in the HSM. */
    if (!azihsm_skey_key_bytes_supported(kind, key_bytes))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY_LENGTH,
            "unsupported AES key length %zu for the requested kind",
            key_bytes
        );
        return NULL;
    }

    bits = (uint32_t)(key_bytes * 8u);

    {
        struct azihsm_key_prop gen_props[] = {
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = (void *)&secret_class,
              .len = sizeof(secret_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&kind, .len = sizeof(kind) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = (void *)&enable, .len = sizeof(enable) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = (void *)&enable, .len = sizeof(enable) },
        };
        struct azihsm_key_prop_list gen_prop_list = {
            .props = gen_props,
            .count = sizeof(gen_props) / sizeof(gen_props[0]),
        };
        struct azihsm_algo algo = {
            .id = keygen_algo,
            .params = NULL,
            .len = 0,
        };

        status = azihsm_key_gen(provctx->session, &algo, &gen_prop_list, &handle);
    }

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return NULL;
    }

    /* Optionally persist the masked blob so a later process can re-import it. */
    if (persist_masked)
    {
        uint8_t *masked_buf = NULL;
        uint32_t masked_len = 0;

        if (!azihsm_ossl_extract_masked_key(handle, &masked_buf, &masked_len))
        {
            azihsm_key_delete(handle);
            return NULL;
        }

        int wret = azihsm_ossl_write_masked_key_to_file(masked_buf, masked_len, masked_key_file);
        OPENSSL_cleanse(masked_buf, masked_len);
        OPENSSL_free(masked_buf);

        if (!wret)
        {
            azihsm_key_delete(handle);
            return NULL;
        }
    }

    skey = azihsm_skey_new(provctx, handle, kind, key_bytes);
    if (skey == NULL)
    {
        azihsm_key_delete(handle);
        return NULL;
    }
    return skey;
}

/* Export non-secret metadata only; secret-key export is refused. */
static int azihsm_ossl_aes_skeymgmt_export(
    void *keydata,
    int selection,
    OSSL_CALLBACK *param_cb,
    void *cbarg
)
{
    AZIHSM_SKEY *skey = (AZIHSM_SKEY *)keydata;

    if (skey == NULL)
    {
        return OSSL_FAILURE;
    }

    /*
     * Refusing to export the secret key is the opacity guarantee: it makes
     * EVP_SKEY_get0_raw_key() (and the cipher raw-key fallback) fail, so HSM
     * key material can never leave the device.
     */
    if (selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_NOT_SUPPORTED,
            "AES key material is non-exportable (HSM-resident)"
        );
        return OSSL_FAILURE;
    }

    /* Only non-secret metadata (key length) may be exported. */
    if ((selection & OSSL_SKEYMGMT_SELECT_PARAMETERS) && skey->key_bytes > 0)
    {
        size_t klen = skey->key_bytes;
        OSSL_PARAM out[2] = {
            OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &klen),
            OSSL_PARAM_construct_end(),
        };
        return param_cb(out, cbarg);
    }

    return OSSL_FAILURE;
}

static const char *azihsm_ossl_aes_skeymgmt_get_key_id(void *keydata)
{
    AZIHSM_SKEY *skey = (AZIHSM_SKEY *)keydata;

    if (skey == NULL)
    {
        return NULL;
    }
    return skey->key_id;
}

/* Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_aes_skeymgmt_imp_settable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_KEY_KIND, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_aes_skeymgmt_gen_settable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_KEY_KIND, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH azihsm_ossl_aes_skeymgmt_functions[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))azihsm_ossl_aes_skeymgmt_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_aes_skeymgmt_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_aes_skeymgmt_export },
    { OSSL_FUNC_SKEYMGMT_GENERATE, (void (*)(void))azihsm_ossl_aes_skeymgmt_generate },
    { OSSL_FUNC_SKEYMGMT_GET_KEY_ID, (void (*)(void))azihsm_ossl_aes_skeymgmt_get_key_id },
    { OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
      (void (*)(void))azihsm_ossl_aes_skeymgmt_imp_settable_params },
    { OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))azihsm_ossl_aes_skeymgmt_gen_settable_params },
    { 0, NULL }
};

#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

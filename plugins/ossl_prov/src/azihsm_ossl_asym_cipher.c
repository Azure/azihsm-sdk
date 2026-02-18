// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_rsa.h"

/* RSA padding modes for asymmetric cipher */
#define AZIHSM_RSA_CIPHER_PAD_MODE_PKCS1 0
#define AZIHSM_RSA_CIPHER_PAD_MODE_OAEP 1

/* Asymmetric cipher context for RSA operations */
typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx; /* Provider context for HSM access */
    AZIHSM_RSA_KEY *key;           /* RSA key (public for encrypt, private for decrypt) */

    /* Padding parameters */
    int pad_mode; /* PKCS1 or OAEP (default: OAEP) */

    /* OAEP-specific parameters */
    const EVP_MD *oaep_md;     /* OAEP hash algorithm (default: SHA-256) */
    const EVP_MD *mgf1_md;     /* MGF1 hash algorithm (defaults to oaep_md) */
    unsigned char *oaep_label; /* Optional OAEP label */
    size_t oaep_label_len;     /* Length of OAEP label */

    /* Operation state */
    int operation; /* 1 = encrypt, 0 = decrypt */
} azihsm_rsa_asym_cipher_ctx;

/* ═══════════════════════════════════════════════════════════════════════════
   RSA ASYMMETRIC CIPHER CONTEXT LIFECYCLE
   ═══════════════════════════════════════════════════════════════════════════ */

static void *azihsm_ossl_asym_cipher_newctx(void *provctx)
{
    azihsm_rsa_asym_cipher_ctx *ctx;
    AZIHSM_OSSL_PROV_CTX *prov = (AZIHSM_OSSL_PROV_CTX *)provctx;

    if (prov == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = prov;

    /* Default to OAEP padding with SHA-256 (HSM rejects SHA-1 for OAEP security reasons) */
    ctx->pad_mode = AZIHSM_RSA_CIPHER_PAD_MODE_OAEP;
    ctx->oaep_md = EVP_sha256();
    ctx->mgf1_md = NULL; /* Will default to oaep_md */
    ctx->oaep_label = NULL;
    ctx->oaep_label_len = 0;

    return ctx;
}

static void azihsm_ossl_asym_cipher_freectx(void *cctx)
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;

    if (ctx == NULL)
        return;

    /* Free OAEP label if allocated */
    if (ctx->oaep_label != NULL)
    {
        OPENSSL_clear_free(ctx->oaep_label, ctx->oaep_label_len);
    }

    /* Note: Don't free key - caller (keymgmt) owns it */
    OPENSSL_free(ctx);
}

static void *azihsm_ossl_asym_cipher_dupctx(void *cctx)
{
    azihsm_rsa_asym_cipher_ctx *src = (azihsm_rsa_asym_cipher_ctx *)cctx;
    azihsm_rsa_asym_cipher_ctx *dst;

    if (src == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy all scalar fields */
    *dst = *src;

    /* Deep copy OAEP label if present */
    if (src->oaep_label != NULL && src->oaep_label_len > 0)
    {
        dst->oaep_label = OPENSSL_memdup(src->oaep_label, src->oaep_label_len);
        if (dst->oaep_label == NULL)
        {
            OPENSSL_free(dst);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }
    else
    {
        dst->oaep_label = NULL;
        dst->oaep_label_len = 0;
    }

    return dst;
}

/* ═══════════════════════════════════════════════════════════════════════════
   RSA ASYMMETRIC CIPHER PARAMETER HANDLING
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_asym_cipher_set_ctx_params(void *cctx, const OSSL_PARAM params[])
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    /* Parse padding mode */
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            const char *pad_mode_str = NULL;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &pad_mode_str) || pad_mode_str == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
                return OSSL_FAILURE;
            }

            if (strcasecmp(pad_mode_str, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0)
            {
                ctx->pad_mode = AZIHSM_RSA_CIPHER_PAD_MODE_OAEP;
            }
            else if (strcasecmp(pad_mode_str, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
            {
                ctx->pad_mode = AZIHSM_RSA_CIPHER_PAD_MODE_PKCS1;
            }
            else
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
                return OSSL_FAILURE;
            }
        }
        else if (p->data_type == OSSL_PARAM_INTEGER)
        {
            int pad_mode_int = 0;
            if (!OSSL_PARAM_get_int(p, &pad_mode_int))
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
                return OSSL_FAILURE;
            }

            if (pad_mode_int == RSA_PKCS1_PADDING)
            {
                ctx->pad_mode = AZIHSM_RSA_CIPHER_PAD_MODE_PKCS1;
            }
            else if (pad_mode_int == RSA_PKCS1_OAEP_PADDING)
            {
                ctx->pad_mode = AZIHSM_RSA_CIPHER_PAD_MODE_OAEP;
            }
            else
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
                return OSSL_FAILURE;
            }
        }
    }

    /* Parse OAEP digest algorithm */
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname) || mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }

        ctx->oaep_md = EVP_get_digestbyname(mdname);
        if (ctx->oaep_md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return OSSL_FAILURE;
        }
    }

    /* Parse MGF1 digest algorithm */
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const char *mgf1_mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mgf1_mdname) || mgf1_mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }

        ctx->mgf1_md = EVP_get_digestbyname(mgf1_mdname);
        if (ctx->mgf1_md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return OSSL_FAILURE;
        }
    }

    /* Parse OAEP label */
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL)
    {
        void *label_data = NULL;
        size_t label_len = 0;

        /* Free existing label if any */
        if (ctx->oaep_label != NULL)
        {
            OPENSSL_clear_free(ctx->oaep_label, ctx->oaep_label_len);
            ctx->oaep_label = NULL;
            ctx->oaep_label_len = 0;
        }

        if (!OSSL_PARAM_get_octet_string(p, &label_data, 0, &label_len))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }

        if (label_len > 0)
        {
            ctx->oaep_label = label_data;
            ctx->oaep_label_len = label_len;
        }
        else
        {
            OPENSSL_free(label_data);
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_asym_cipher_get_ctx_params(void *cctx, OSSL_PARAM params[])
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;
    OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    /* Return padding mode */
    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
    {
        const char *pad_mode_str = (ctx->pad_mode == AZIHSM_RSA_CIPHER_PAD_MODE_OAEP)
                                       ? OSSL_PKEY_RSA_PAD_MODE_OAEP
                                       : OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
        if (!OSSL_PARAM_set_utf8_string(p, pad_mode_str))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }
    }

    /* Return OAEP digest name */
    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL)
    {
        const char *mdname = (ctx->oaep_md != NULL) ? EVP_MD_name(ctx->oaep_md) : "SHA256";
        if (!OSSL_PARAM_set_utf8_string(p, mdname))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }
    }

    /* Return MGF1 digest name */
    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->oaep_md;
        const char *mgf1_mdname = (mgf1_md != NULL) ? EVP_MD_name(mgf1_md) : "SHA256";
        if (!OSSL_PARAM_set_utf8_string(p, mgf1_mdname))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }
    }

    /* Return OAEP label */
    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL)
    {
        if (!OSSL_PARAM_set_octet_string(p, ctx->oaep_label, ctx->oaep_label_len))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_ossl_asym_cipher_gettable_ctx_params(
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

/* ═══════════════════════════════════════════════════════════════════════════
   RSA ASYMMETRIC CIPHER OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_asym_cipher_encrypt_init(
    void *cctx,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    ctx->key = (AZIHSM_RSA_KEY *)provkey;
    ctx->operation = 1; /* Encrypt */

    if (!ctx->key->has_public)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return OSSL_FAILURE;
    }

    /* Apply any provided parameters */
    if (params != NULL)
    {
        if (!azihsm_ossl_asym_cipher_set_ctx_params(ctx, params))
        {
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_asym_cipher_encrypt(
    void *cctx,
    unsigned char *out,
    size_t *outlen,
    size_t outsize,
    const unsigned char *in,
    size_t inlen
)
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = { 0 };
    struct azihsm_buffer plain_buf, cipher_buf;
    struct azihsm_buffer label_buf = { 0 };
    azihsm_status status;
    size_t key_size;

    if (ctx == NULL || ctx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Calculate key size in bytes */
    key_size = ctx->key->genctx.pubkey_bits / 8;

    /* Size query: return the maximum output size (equals key size for RSA) */
    if (out == NULL)
    {
        *outlen = key_size;
        return OSSL_SUCCESS;
    }

    /* Validate output buffer size */
    if (outsize < key_size)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (inlen > UINT32_MAX || outsize > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Build algorithm parameters based on padding mode */
    if (ctx->pad_mode == AZIHSM_RSA_CIPHER_PAD_MODE_OAEP)
    {
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->oaep_md;

        /* SHA-1 is not supported by HSM for OAEP */
        if (EVP_MD_type(ctx->oaep_md) == NID_sha1)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "SHA-1 is not supported for OAEP encryption, use SHA-256 or stronger"
            );
            return OSSL_FAILURE;
        }

        /* OAEP hash and MGF1 hash must match (AZIHSM requirement) */
        if (EVP_MD_type(ctx->oaep_md) != EVP_MD_type(mgf1_md))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "OAEP hash (%s) and MGF1 hash (%s) must use the same algorithm",
                EVP_MD_name(ctx->oaep_md),
                EVP_MD_name(mgf1_md)
            );
            return OSSL_FAILURE;
        }

        oaep_params.hash_algo_id = azihsm_ossl_evp_md_to_algo_id(ctx->oaep_md);
        oaep_params.mgf1_hash_algo_id = azihsm_ossl_evp_md_to_mgf1_id(mgf1_md);

        /* Handle optional label */
        if (ctx->oaep_label != NULL && ctx->oaep_label_len > 0)
        {
            if (ctx->oaep_label_len > UINT32_MAX)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
                return OSSL_FAILURE;
            }
            label_buf.ptr = ctx->oaep_label;
            label_buf.len = (uint32_t)ctx->oaep_label_len;
            oaep_params.label = &label_buf;
        }
        else
        {
            oaep_params.label = NULL;
        }

        algo.id = AZIHSM_ALGO_ID_RSA_PKCS_OAEP;
        algo.params = &oaep_params;
        algo.len = sizeof(oaep_params);
    }
    else /* PKCS#1 v1.5 */
    {
        algo.id = AZIHSM_ALGO_ID_RSA_PKCS;
        algo.params = NULL;
        algo.len = 0;
    }

    /* Set up buffers */
    plain_buf.ptr = (uint8_t *)in;
    plain_buf.len = (uint32_t)inlen;
    cipher_buf.ptr = out;
    cipher_buf.len = (uint32_t)outsize;

    status = azihsm_crypt_encrypt(&algo, ctx->key->key.pub, &plain_buf, &cipher_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    *outlen = cipher_buf.len;
    return OSSL_SUCCESS;
}

static int azihsm_ossl_asym_cipher_decrypt_init(
    void *cctx,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    ctx->key = (AZIHSM_RSA_KEY *)provkey;
    ctx->operation = 0; /* Decrypt */

    if (!ctx->key->has_private)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return OSSL_FAILURE;
    }

    /* Apply any provided parameters */
    if (params != NULL)
    {
        if (!azihsm_ossl_asym_cipher_set_ctx_params(ctx, params))
        {
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_asym_cipher_decrypt(
    void *cctx,
    unsigned char *out,
    size_t *outlen,
    size_t outsize,
    const unsigned char *in,
    size_t inlen
)
{
    azihsm_rsa_asym_cipher_ctx *ctx = (azihsm_rsa_asym_cipher_ctx *)cctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = { 0 };
    struct azihsm_buffer cipher_buf, plain_buf;
    struct azihsm_buffer label_buf = { 0 };
    azihsm_status status;
    size_t key_size;

    if (ctx == NULL || ctx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Calculate key size in bytes */
    key_size = ctx->key->genctx.pubkey_bits / 8;

    /* Size query: return key size as safe upper bound */
    if (out == NULL)
    {
        *outlen = key_size;
        return OSSL_SUCCESS;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (inlen > UINT32_MAX || outsize > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Build algorithm parameters based on padding mode */
    if (ctx->pad_mode == AZIHSM_RSA_CIPHER_PAD_MODE_OAEP)
    {
        const EVP_MD *mgf1_md = (ctx->mgf1_md != NULL) ? ctx->mgf1_md : ctx->oaep_md;

        /* SHA-1 is not supported by HSM for OAEP */
        if (EVP_MD_type(ctx->oaep_md) == NID_sha1)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "SHA-1 is not supported for OAEP decryption, use SHA-256 or stronger"
            );
            return OSSL_FAILURE;
        }

        /* OAEP hash and MGF1 hash must match (AZIHSM requirement) */
        if (EVP_MD_type(ctx->oaep_md) != EVP_MD_type(mgf1_md))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "OAEP hash (%s) and MGF1 hash (%s) must use the same algorithm",
                EVP_MD_name(ctx->oaep_md),
                EVP_MD_name(mgf1_md)
            );
            return OSSL_FAILURE;
        }

        oaep_params.hash_algo_id = azihsm_ossl_evp_md_to_algo_id(ctx->oaep_md);
        oaep_params.mgf1_hash_algo_id = azihsm_ossl_evp_md_to_mgf1_id(mgf1_md);

        /* Handle optional label */
        if (ctx->oaep_label != NULL && ctx->oaep_label_len > 0)
        {
            if (ctx->oaep_label_len > UINT32_MAX)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
                return OSSL_FAILURE;
            }
            label_buf.ptr = ctx->oaep_label;
            label_buf.len = (uint32_t)ctx->oaep_label_len;
            oaep_params.label = &label_buf;
        }
        else
        {
            oaep_params.label = NULL;
        }

        algo.id = AZIHSM_ALGO_ID_RSA_PKCS_OAEP;
        algo.params = &oaep_params;
        algo.len = sizeof(oaep_params);
    }
    else /* PKCS#1 v1.5 */
    {
        algo.id = AZIHSM_ALGO_ID_RSA_PKCS;
        algo.params = NULL;
        algo.len = 0;
    }

    /* Set up buffers */
    cipher_buf.ptr = (uint8_t *)in;
    cipher_buf.len = (uint32_t)inlen;
    plain_buf.ptr = out;
    plain_buf.len = (uint32_t)outsize;

    status = azihsm_crypt_decrypt(&algo, ctx->key->key.priv, &cipher_buf, &plain_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    *outlen = plain_buf.len;
    return OSSL_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════════
   RSA ASYMMETRIC CIPHER DISPATCH TABLE
   ═══════════════════════════════════════════════════════════════════════════ */

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

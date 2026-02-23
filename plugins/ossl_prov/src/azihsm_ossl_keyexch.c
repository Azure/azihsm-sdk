// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_ec.h"
#include "azihsm_ossl_masked_key.h"
#include "azihsm_ossl_pkey_param.h"

/* Upper bound for masked key blob output buffer.
 * Callers that do not use output_file receive the masked blob in their buffer.
 * This must be large enough for any masked key the HSM can produce. */
#define MASKED_KEY_MAX_BUFFER 8192

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;
    const AZIHSM_EC_KEY *our_key; /* Not owned */
    AZIHSM_EC_KEY *peer_key;      /* Owned, deep copy */
    char output_file[4096];
} AZIHSM_KEYEXCH_CTX;

static void keyexch_free_peer(AZIHSM_KEYEXCH_CTX *ctx)
{
    if (ctx->peer_key == NULL)
    {
        return;
    }

    OPENSSL_free(ctx->peer_key->pub_key_data);
    OPENSSL_free(ctx->peer_key);
    ctx->peer_key = NULL;
}

/*
 * Convert a raw EC public point into a DER-encoded SubjectPublicKeyInfo (SPKI).
 *
 * Parameters:
 *   nid           - OpenSSL NID identifying the EC curve (for example, NID_X9_62_prime256v1).
 *   pub_point     - Buffer containing the encoded EC public point for the given curve.
 *   pub_point_len - Length in bytes of the pub_point buffer.
 *   der_out       - On success, set to a newly allocated buffer containing the DER-encoded
 *                   SPKI structure for the EC public key.
 *   der_len       - On success, set to the length in bytes of *der_out.
 *
 * Memory ownership:
 *   On success, *der_out is allocated by OpenSSL (for example via i2d_* routines) and the
 *   caller is responsible for freeing it by calling OPENSSL_free(*der_out). On failure,
 *   *der_out and *der_len are not guaranteed to be modified.
 *
 * Returns:
 *   OSSL_SUCCESS on success, OSSL_FAILURE on failure.
 *   On failure, no DER-encoded SPKI is returned and appropriate OpenSSL error
 *   information may be queued for diagnostic purposes.
 */
static int ec_point_to_der_spki(
    int nid,
    const unsigned char *pub_point,
    size_t pub_point_len,
    unsigned char **der_out,
    int *der_len
)
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;

    *der_out = NULL;
    *der_len = 0;

    /* Build an EC_GROUP for the requested curve */
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    point = EC_POINT_new(group);
    if (point == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    /* Decode the uncompressed EC point from its octet-string form */
    if (!EC_POINT_oct2point(group, point, pub_point, pub_point_len, NULL))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    if (!EC_KEY_set_group(ec_key, group))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    if (!EC_KEY_set_public_key(ec_key, point))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EVP_LIB);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }
    ec_key = NULL; /* Ownership transferred to pkey */

    /* Encode the public key as a DER SubjectPublicKeyInfo */
    *der_len = i2d_PUBKEY(pkey, der_out);
    if (*der_len <= 0)
    {
        *der_out = NULL;
        *der_len = 0;
        ERR_raise(ERR_LIB_PROV, ERR_R_ASN1_LIB);

        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return OSSL_FAILURE;
    }

    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    EC_GROUP_free(group);

    return OSSL_SUCCESS;
}

static void *azihsm_ossl_keyexch_newctx(void *provctx)
{
    AZIHSM_KEYEXCH_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(AZIHSM_KEYEXCH_CTX));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = (AZIHSM_OSSL_PROV_CTX *)provctx;
    return ctx;
}

static void azihsm_ossl_keyexch_freectx(void *kectx)
{
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;

    if (ctx == NULL)
    {
        return;
    }

    /* Do not free our_key - it is owned by keymgmt */
    keyexch_free_peer(ctx);
    OPENSSL_free(ctx);
}

static void *azihsm_ossl_keyexch_dupctx(void *kectx)
{
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;
    AZIHSM_KEYEXCH_CTX *dup;

    if (ctx == NULL)
    {
        return NULL;
    }

    dup = OPENSSL_zalloc(sizeof(AZIHSM_KEYEXCH_CTX));
    if (dup == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memcpy(dup, ctx, sizeof(AZIHSM_KEYEXCH_CTX));
    dup->peer_key = NULL;
    if (ctx->peer_key != NULL)
    {
        dup->peer_key = OPENSSL_zalloc(sizeof(AZIHSM_EC_KEY));
        if (dup->peer_key == NULL)
        {
            OPENSSL_free(dup);

            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        memcpy(dup->peer_key, ctx->peer_key, sizeof(AZIHSM_EC_KEY));
        dup->peer_key->pub_key_data = NULL;

        if (ctx->peer_key->pub_key_data != NULL && ctx->peer_key->pub_key_data_len > 0)
        {
            dup->peer_key->pub_key_data = OPENSSL_malloc(ctx->peer_key->pub_key_data_len);
            if (dup->peer_key->pub_key_data == NULL)
            {
                OPENSSL_free(dup->peer_key);
                OPENSSL_free(dup);

                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return NULL;
            }
            memcpy(
                dup->peer_key->pub_key_data,
                ctx->peer_key->pub_key_data,
                ctx->peer_key->pub_key_data_len
            );
        }
    }

    return dup;
}

static int azihsm_ossl_keyexch_set_ctx_params(void *kectx, const OSSL_PARAM params[])
{
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    if (params == NULL)
    {
        return OSSL_SUCCESS;
    }

    p = OSSL_PARAM_locate_const(params, "output_file");
    if (p != NULL)
    {
        const char *path = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &path) || path == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (azihsm_ossl_masked_key_filepath_validate(path) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        strncpy(ctx->output_file, path, sizeof(ctx->output_file) - 1);
        ctx->output_file[sizeof(ctx->output_file) - 1] = '\0';
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_keyexch_init(void *kectx, void *provkey, const OSSL_PARAM params[])
{
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;
    AZIHSM_EC_KEY *key = (AZIHSM_EC_KEY *)provkey;

    if (ctx == NULL || key == NULL)
    {
        return OSSL_FAILURE;
    }

    if (!key->has_private)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return OSSL_FAILURE;
    }

    ctx->our_key = key;

    if (!azihsm_ossl_keyexch_set_ctx_params(ctx, params))
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_keyexch_set_peer(void *kectx, void *provkey)
{
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;
    AZIHSM_EC_KEY *key = (AZIHSM_EC_KEY *)provkey;
    AZIHSM_EC_KEY *copy = NULL;

    if (ctx == NULL || key == NULL)
    {
        return OSSL_FAILURE;
    }

    if (!key->has_public)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return OSSL_FAILURE;
    }

    copy = OPENSSL_zalloc(sizeof(AZIHSM_EC_KEY));
    if (copy == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return OSSL_FAILURE;
    }

    memcpy(copy, key, sizeof(AZIHSM_EC_KEY));
    copy->pub_key_data = NULL;

    if (key->pub_key_data != NULL && key->pub_key_data_len > 0)
    {
        copy->pub_key_data = OPENSSL_malloc(key->pub_key_data_len);
        if (copy->pub_key_data == NULL)
        {
            OPENSSL_free(copy);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return OSSL_FAILURE;
        }
        memcpy(copy->pub_key_data, key->pub_key_data, key->pub_key_data_len);
    }

    keyexch_free_peer(ctx);
    ctx->peer_key = copy;
    return OSSL_SUCCESS;
}

/*
 * azihsm_ossl_keyexch_derive
 *
 * Perform an ECDH key exchange using the Azure Integrated HSM.
 *
 * The derived shared secret is always a masked key blob. Output mode depends
 * on whether the caller supplied the "output_file" context parameter:
 *
 *   - output_file set:   masked blob is written to that file; *secretlen is
 *                         set to 0 (no bytes returned in the buffer).
 *   - output_file unset: masked blob is copied into the caller's buffer and
 *                         *secretlen is set to the number of bytes written.
 *
 * Size query (secret == NULL): sets *secretlen to MASKED_KEY_MAX_BUFFER when
 * no output_file is configured, or 1 when output_file is set (the caller
 * still needs to supply a non-NULL buffer to trigger the actual derive).
 *
 * Parameters:
 *   kectx     - Pointer to the AZIHSM_KEYEXCH_CTX.
 *   secret    - Caller's buffer, or NULL for a size query.
 *   secretlen - On return, the number of bytes written to secret.
 *   outlen    - Size of the caller's buffer in bytes.
 *
 * Returns OSSL_SUCCESS (1) on success or OSSL_FAILURE (0) on error.
 */
static int azihsm_ossl_keyexch_derive(
    void *kectx,
    unsigned char *secret,
    size_t *secretlen,
    size_t outlen
)
{
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;
    unsigned char *der_spki = NULL;
    int der_spki_len = 0;
    azihsm_handle derived_handle = 0;
    azihsm_status status;
    uint8_t *masked_buf = NULL;
    uint32_t masked_len = 0;
    int ret = OSSL_FAILURE;
    int nid;
    int curve_bits;

    if (ctx == NULL || ctx->our_key == NULL || ctx->peer_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Size query: return the expected output size without performing the derive */
    if (secret == NULL)
    {
        if (secretlen != NULL)
        {
            if (ctx->output_file[0] != '\0')
            {
                /* File output mode — caller still needs a non-NULL buffer to
                 * trigger the derive, but no bytes are returned in it. */
                *secretlen = 1;
            }
            else
            {
                /* Buffer output mode — caller must provide this much space. */
                *secretlen = MASKED_KEY_MAX_BUFFER;
            }
        }
        return OSSL_SUCCESS;
    }

    if (ctx->peer_key->pub_key_data == NULL || ctx->peer_key->pub_key_data_len == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return OSSL_FAILURE;
    }

    if (ctx->peer_key->genctx.ec_curve_id != ctx->our_key->genctx.ec_curve_id)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
        return OSSL_FAILURE;
    }

    nid = azihsm_ossl_ec_curve_id_to_nid((int)ctx->peer_key->genctx.ec_curve_id);
    if (nid == NID_undef)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        return OSSL_FAILURE;
    }

    if (!ec_point_to_der_spki(
            nid,
            ctx->peer_key->pub_key_data,
            ctx->peer_key->pub_key_data_len,
            &der_spki,
            &der_spki_len
        ))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return OSSL_FAILURE;
    }

    struct azihsm_buffer pub_key_buf = {
        .ptr = der_spki,
        .len = (uint32_t)der_spki_len,
    };

    struct azihsm_algo_ecdh_params ecdh_params = {
        .pub_key = &pub_key_buf,
    };

    struct azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDH,
        .params = &ecdh_params,
        .len = sizeof(ecdh_params),
    };

    const azihsm_key_class secret_class = AZIHSM_KEY_CLASS_SECRET;
    const azihsm_key_kind shared_secret_kind = AZIHSM_KEY_KIND_SHARED_SECRET;
    const bool enable_derive = true;

    curve_bits = azihsm_ossl_ec_curve_id_to_bits((int)ctx->our_key->genctx.ec_curve_id);
    if (curve_bits <= 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        OPENSSL_free(der_spki);
        return OSSL_FAILURE;
    }
    uint32_t bit_len_val = (uint32_t)curve_bits;

    struct azihsm_key_prop derive_props[] = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS,
          .val = (void *)&secret_class,
          .len = sizeof(secret_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND,
          .val = (void *)&shared_secret_kind,
          .len = sizeof(shared_secret_kind) },
        { .id = AZIHSM_KEY_PROP_ID_DERIVE,
          .val = (void *)&enable_derive,
          .len = sizeof(enable_derive) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
          .val = (void *)&bit_len_val,
          .len = sizeof(bit_len_val) },
    };

    struct azihsm_key_prop_list derive_prop_list = {
        .props = derive_props,
        .count = sizeof(derive_props) / sizeof(derive_props[0]),
    };

    status = azihsm_key_derive(
        ctx->provctx->session,
        &algo,
        ctx->our_key->key.priv,
        &derive_prop_list,
        &derived_handle
    );

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        OPENSSL_free(der_spki);
        return OSSL_FAILURE;
    }

    /* Extract masked key using two-call pattern */
    if (!azihsm_ossl_extract_masked_key(derived_handle, &masked_buf, &masked_len))
    {
        azihsm_key_delete(derived_handle);
        OPENSSL_free(der_spki);
        return OSSL_FAILURE;
    }

    /* Output masked key to file or buffer */
    if (ctx->output_file[0] != '\0')
    {
        ret = azihsm_ossl_write_masked_key_to_file(masked_buf, masked_len, ctx->output_file);
        if (ret == OSSL_SUCCESS && secretlen != NULL)
        {
            *secretlen = 0;
        }
    }
    else
    {
        if (outlen < masked_len)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            ret = OSSL_FAILURE;
        }
        else
        {
            memcpy(secret, masked_buf, masked_len);
            if (secretlen != NULL)
            {
                *secretlen = masked_len;
            }
            ret = OSSL_SUCCESS;
        }
    }

    OPENSSL_cleanse(masked_buf, masked_len);
    OPENSSL_free(masked_buf);
    OPENSSL_free(der_spki);
    azihsm_key_delete(derived_handle);
    return ret;
}

static const OSSL_PARAM *azihsm_ossl_keyexch_settable_ctx_params(
    ossl_unused void *kectx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_utf8_string("output_file", NULL, 0),
                                         OSSL_PARAM_END };
    return params;
}

const OSSL_DISPATCH azihsm_ossl_ecdh_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))azihsm_ossl_keyexch_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))azihsm_ossl_keyexch_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))azihsm_ossl_keyexch_dupctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))azihsm_ossl_keyexch_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))azihsm_ossl_keyexch_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))azihsm_ossl_keyexch_derive },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_keyexch_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_keyexch_settable_ctx_params },
    { 0, NULL }
};

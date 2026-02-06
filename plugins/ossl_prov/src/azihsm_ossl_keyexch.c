// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
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
#include <sys/stat.h>
#include <unistd.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_ec.h"

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;
    AZIHSM_EC_KEY *our_key;  /* Not owned */
    AZIHSM_EC_KEY *peer_key; /* Owned, deep copy */
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

/* Convert raw EC point to DER-encoded SPKI. Caller must OPENSSL_free(*der_out). */
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
    int ret = OSSL_FAILURE;

    *der_out = NULL;
    *der_len = 0;

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }

    point = EC_POINT_new(group);
    if (point == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point(group, point, pub_point, pub_point_len, NULL))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_KEY_set_group(ec_key, group))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_KEY_set_public_key(ec_key, point))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_EVP_LIB);
        goto err;
    }
    ec_key = NULL; /* Ownership transferred to pkey */

    *der_len = i2d_PUBKEY(pkey, der_out);
    if (*der_len <= 0)
    {
        *der_out = NULL;
        *der_len = 0;
        ERR_raise(ERR_LIB_PROV, ERR_R_ASN1_LIB);
        goto err;
    }

    ret = OSSL_SUCCESS;

err:
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return ret;
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

        int ret = snprintf(ctx->output_file, sizeof(ctx->output_file), "%s", path);
        if (ret < 0 || (size_t)ret >= sizeof(ctx->output_file))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
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
 * Perform a key exchange using the Azure IoT HSM and produce a shared secret.
 *
 * Parameters:
 *   kectx     - Pointer to the AZIHSM_KEYEXCH_CTX containing our private key,
 *               the peer public key, and provider context.
 *   secret    - Optional buffer where the derived secret will be written. May
 *               be NULL when the caller only wants to learn the required size.
 *   secretlen - In/out: on entry, may contain the size of the 'secret' buffer;
 *               on successful return, set to the number of bytes in the
 *               derived secret.
 *   outlen    - Unused by this implementation (required by the OpenSSL
 *               provider interface); present only for API compatibility.
 *
 * Returns OSSL_SUCCESS (1) on success or OSSL_FAILURE (0) on error.  On
 * failure, an appropriate error is raised on the OpenSSL error stack and any
 * temporary resources are freed.
 */
static int azihsm_ossl_keyexch_derive(
    void *kectx,
    unsigned char *secret,
    size_t *secretlen,
    ossl_unused size_t outlen
)
{
    /* Retrieve the key exchange context and initialize temporary state. */
    AZIHSM_KEYEXCH_CTX *ctx = (AZIHSM_KEYEXCH_CTX *)kectx;
    unsigned char *der_spki = NULL;
    int der_spki_len = 0;
    azihsm_handle derived_handle = 0;
    azihsm_status status;
    uint8_t *masked_key_buffer = NULL;
    int ret = OSSL_FAILURE;
    int nid;
    int curve_bits;

    if (ctx == NULL || ctx->our_key == NULL || ctx->peer_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    if (secret == NULL)
    {
        if (secretlen != NULL)
        {
            *secretlen = 1;
        }
        return OSSL_SUCCESS;
    }

    if (ctx->output_file[0] == '\0')
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
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
        .count = 4,
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
        goto err;
    }

    const uint32_t masked_key_buffer_size = 8192;
    masked_key_buffer = OPENSSL_malloc(masked_key_buffer_size);
    if (masked_key_buffer == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    struct azihsm_key_prop masked_prop = {
        .id = AZIHSM_KEY_PROP_ID_MASKED_KEY,
        .val = masked_key_buffer,
        .len = masked_key_buffer_size,
    };

    status = azihsm_key_get_prop(derived_handle, &masked_prop);
    if (status != AZIHSM_STATUS_SUCCESS || masked_prop.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    int fd = open(ctx->output_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
        goto err;
    }

    ssize_t written = write(fd, masked_key_buffer, masked_prop.len);
    close(fd);

    if (written < 0 || (uint32_t)written != masked_prop.len)
    {
        unlink(ctx->output_file);
        ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
        goto err;
    }

    if (secretlen != NULL)
    {
        *secretlen = 0;
    }

    ret = OSSL_SUCCESS;

err:
    if (masked_key_buffer != NULL)
    {
        OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
        OPENSSL_free(masked_key_buffer);
    }
    OPENSSL_free(der_spki);
    if (derived_handle != 0)
    {
        azihsm_key_delete(derived_handle);
    }
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

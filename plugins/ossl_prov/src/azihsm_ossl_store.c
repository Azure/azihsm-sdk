// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/store.h>
#include <stdlib.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_ec.h"
#include "azihsm_ossl_pkey_param.h"
#include "azihsm_ossl_store.h"

typedef struct
{
    char *file_path;
    int key_kind;
} AZIHSM_URI_INFO;

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;
    AZIHSM_URI_INFO uri_info;
    int eof;
    AZIHSM_KEY_PAIR_OBJ key_handles;
    int key_type;
    int expect;    /* Expected object type (OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY, etc.) */
    void *key_obj; /* Allocated key object (AZIHSM_EC_KEY, etc.) for store callback */

    /* Properties queried from unmasked key */
    azihsm_ecc_curve ec_curve; /* EC curve ID for ECC keys */
    bool is_session_key;       /* Whether this is a session key */
} AZIHSM_STORE_CTX;

static AZIHSM_STORE_CTX *store_ctx_new(AZIHSM_OSSL_PROV_CTX *provctx)
{
    AZIHSM_STORE_CTX *ctx = NULL;

    if (provctx == NULL)
    {
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(AZIHSM_STORE_CTX));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->uri_info.file_path = NULL;
    ctx->uri_info.key_kind = -1;
    ctx->eof = 0;
    ctx->key_type = -1; // Uninitialized
    ctx->expect = 0;    // No expectation set
    ctx->ec_curve = 0;
    ctx->is_session_key = false;

    return ctx;
}

static void azihsm_uri_info_free(AZIHSM_URI_INFO *info)
{
    if (info == NULL)
        return;

    if (info->file_path != NULL)
        OPENSSL_free(info->file_path);
}

static void store_ctx_free(AZIHSM_STORE_CTX *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    azihsm_uri_info_free(&ctx->uri_info);
    if (ctx->key_obj != NULL)
    {
        OPENSSL_free(ctx->key_obj);
    }
    OPENSSL_clear_free(ctx, sizeof(AZIHSM_STORE_CTX));
}

static int parse_key_kind(const char *kind_str)
{
    if (kind_str == NULL)
        return -1;

    if (strcasecmp(kind_str, "ec") == 0)
        return AZIHSM_KEY_KIND_ECC;
    else if (strcasecmp(kind_str, "rsa") == 0)
        return AZIHSM_KEY_KIND_RSA;

    return -1;
}

static int parse_uri_attribute(const char *attr_str, char **out_key, char **out_val)
{
    const char *eq = strchr(attr_str, '=');
    size_t key_len, val_len;

    if (eq == NULL)
        return OSSL_FAILURE;

    key_len = eq - attr_str;
    if (key_len == 0)
        return OSSL_FAILURE;

    *out_key = OPENSSL_malloc(key_len + 1);
    if (*out_key == NULL)
        return OSSL_FAILURE;
    strncpy(*out_key, attr_str, key_len);
    (*out_key)[key_len] = '\0';

    val_len = strlen(eq + 1);
    *out_val = OPENSSL_malloc(val_len + 1);
    if (*out_val == NULL)
    {
        OPENSSL_free(*out_key);
        return OSSL_FAILURE;
    }
    strcpy(*out_val, eq + 1);

    return OSSL_SUCCESS;
}

static int parse_azihsm_uri(const char *uri, AZIHSM_URI_INFO *out_info)
{
    const char *scheme = "azihsm://";
    size_t scheme_len = 9;
    const char *path_start, *semicolon;
    size_t path_len;
    char *attr_copy = NULL, *attr_token = NULL, *attr_saveptr = NULL;
    char *attr_name = NULL, *attr_value = NULL;

    if (uri == NULL || out_info == NULL)
    {
        return OSSL_FAILURE;
    }

    // Initialize output structure
    out_info->file_path = NULL;
    out_info->key_kind = -1;

    // Check URI starts with "azihsm://"
    if (strncmp(uri, scheme, scheme_len) != 0)
    {
        return OSSL_FAILURE;
    }

    path_start = uri + scheme_len;

    // Find semicolon that separates path from attributes
    semicolon = strchr(path_start, ';');
    if (semicolon == NULL)
    {
        path_len = strlen(path_start);
    }
    else
    {
        path_len = semicolon - path_start;
    }

    // Path must not be empty
    if (path_len == 0)
    {
        return OSSL_FAILURE;
    }

    // Allocate and copy path
    out_info->file_path = OPENSSL_malloc(path_len + 1);
    if (out_info->file_path == NULL)
    {
        return OSSL_FAILURE;
    }
    strncpy(out_info->file_path, path_start, path_len);
    out_info->file_path[path_len] = '\0';

    // Parse attributes if present
    if (semicolon != NULL)
    {
        attr_copy = OPENSSL_strdup(semicolon + 1);
        if (attr_copy == NULL)
        {
            return OSSL_FAILURE;
        }

        attr_token = strtok_r(attr_copy, ";", &attr_saveptr);
        while (attr_token != NULL)
        {
            if (parse_uri_attribute(attr_token, &attr_name, &attr_value))
            {
                if (strcasecmp(attr_name, "type") == 0)
                {
                    out_info->key_kind = parse_key_kind(attr_value);
                }

                OPENSSL_free(attr_name);
                OPENSSL_free(attr_value);
            }

            attr_token = strtok_r(NULL, ";", &attr_saveptr);
        }

        OPENSSL_free(attr_copy);
    }

    // Validate that type was provided
    if (out_info->key_kind == -1)
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static unsigned char *read_key_file(const char *path, size_t *out_len)
{
    FILE *f = NULL;
    long size;
    unsigned char *buf = NULL;
    size_t bytes_read;

    if (path == NULL || out_len == NULL)
        return NULL;

    f = fopen(path, "rb");
    if (f == NULL)
        return NULL;

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }

    size = ftell(f);
    if (size <= 0)
    {
        fclose(f);
        return NULL;
    }

    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return NULL;
    }

    buf = OPENSSL_malloc(size);
    if (buf == NULL)
    {
        fclose(f);
        return NULL;
    }

    bytes_read = fread(buf, 1, size, f);
    fclose(f);

    if (bytes_read != (size_t)size)
    {
        OPENSSL_free(buf);
        return NULL;
    }

    *out_len = size;
    return buf;
}

static int load_and_unmask_key(AZIHSM_STORE_CTX *ctx)
{
    unsigned char *masked_key_data = NULL;
    size_t masked_key_size = 0;
    azihsm_status status;
    struct azihsm_buffer masked_buf;
    azihsm_key_kind actual_kind;
    struct azihsm_key_prop prop;

    if (ctx->provctx == NULL || ctx->provctx->session == 0)
    {
        return OSSL_FAILURE;
    }

    /* Read masked key from file - fail if file doesn't exist or cannot be read */
    masked_key_data = read_key_file(ctx->uri_info.file_path, &masked_key_size);
    if (masked_key_data == NULL)
    {
        return OSSL_FAILURE;
    }

    masked_buf.ptr = (void *)masked_key_data;
    masked_buf.len = (uint32_t)masked_key_size;

    /* Unmask the key - fail if unmask operation fails */
    status = azihsm_key_unmask_pair(
        ctx->provctx->session,
        ctx->uri_info.key_kind,
        &masked_buf,
        &ctx->key_handles.priv,
        &ctx->key_handles.pub
    );

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_free(masked_key_data);
        return OSSL_FAILURE;
    }

    /* Query the key kind to verify it matches expectations */
    actual_kind = 0;
    prop.id = AZIHSM_KEY_PROP_ID_KIND;
    prop.val = &actual_kind;
    prop.len = sizeof(azihsm_key_kind);

    status = azihsm_key_get_prop(ctx->key_handles.priv, &prop);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_free(masked_key_data);
        return OSSL_FAILURE;
    }

    ctx->key_type = actual_kind;

    /* For ECC keys, query additional properties */
    if (actual_kind == AZIHSM_KEY_KIND_ECC)
    {
        /* Query EC curve */
        azihsm_ecc_curve curve_id = 0;
        prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
        prop.val = &curve_id;
        prop.len = sizeof(azihsm_ecc_curve);

        status = azihsm_key_get_prop(ctx->key_handles.priv, &prop);
        if (status == AZIHSM_STATUS_SUCCESS)
        {
            ctx->ec_curve = curve_id;
        }

        /* Query session flag */
        uint8_t is_session = 0;
        prop.id = AZIHSM_KEY_PROP_ID_SESSION;
        prop.val = &is_session;
        prop.len = sizeof(uint8_t);

        status = azihsm_key_get_prop(ctx->key_handles.priv, &prop);
        if (status == AZIHSM_STATUS_SUCCESS)
        {
            ctx->is_session_key = (is_session != 0);
        }
    }

    OPENSSL_free(masked_key_data);

    return OSSL_SUCCESS;
}

static const char *key_kind_to_string(int key_kind)
{
    switch (key_kind)
    {
    case AZIHSM_KEY_KIND_ECC:
        return "EC";
    case AZIHSM_KEY_KIND_RSA:
        return "RSA";
    default:
        return NULL;
    }
}

static void *azihsm_store_open(
    void *provctx,
    const char *uri,
    ossl_unused const OSSL_PARAM params[],
    ossl_unused OSSL_CALLBACK *object_cb,
    ossl_unused void *object_cbarg
)
{
    AZIHSM_STORE_CTX *ctx = NULL;
    AZIHSM_OSSL_PROV_CTX *prov_ctx = (AZIHSM_OSSL_PROV_CTX *)provctx;

    if (uri == NULL)
    {
        return NULL;
    }

    // Create context first
    ctx = store_ctx_new(prov_ctx);
    if (ctx == NULL)
    {
        return NULL;
    }

    // Parse URI with type support into the allocated context
    if (!parse_azihsm_uri(uri, &ctx->uri_info))
    {
        store_ctx_free(ctx);
        return NULL;
    }

    return (void *)ctx;
}

static int azihsm_store_load(
    void *loaderctx,
    OSSL_CALLBACK *object_cb,
    void *object_cbarg,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *pw_cb,
    ossl_unused void *pw_cbarg
)
{
    AZIHSM_STORE_CTX *ctx = (AZIHSM_STORE_CTX *)loaderctx;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *data_type;
    AZIHSM_EC_KEY *ec_key = NULL;

    if (ctx == NULL || ctx->eof)
        return OSSL_FAILURE;

    if (!load_and_unmask_key(ctx))
    {
        ctx->eof = 1;
        return OSSL_FAILURE;
    }

    data_type = key_kind_to_string(ctx->key_type);
    if (data_type == NULL)
    {
        ctx->eof = 1;
        return OSSL_FAILURE;
    }

    // For EC keys, construct an AZIHSM_EC_KEY object
    if (ctx->key_type == AZIHSM_KEY_KIND_ECC)
    {
        ec_key = OPENSSL_zalloc(sizeof(AZIHSM_EC_KEY));
        if (ec_key == NULL)
        {
            ctx->eof = 1;
            return OSSL_FAILURE;
        }

        // Copy key handles
        ec_key->key.pub = ctx->key_handles.pub;
        ec_key->key.priv = ctx->key_handles.priv;
        ec_key->has_public = true;
        /*
         * Set has_private based on what OpenSSL expects:
         * - If expect == OSSL_STORE_INFO_PUBKEY, report as public-key-only
         *   so OpenSSL's load_pubkey() accepts it for verification
         * - Otherwise, report as having private key for signing operations
         * The actual private key handle is always available for signing.
         */
        ec_key->has_private = (ctx->expect != OSSL_STORE_INFO_PUBKEY);

        /* Initialize genctx using queried properties from unmasked key */
        ec_key->genctx.ec_curve_id = ctx->ec_curve;
        ec_key->genctx.key_usage = KEY_USAGE_DIGITAL_SIGNATURE;
        ec_key->genctx.session = ctx->provctx->session;
        ec_key->genctx.session_flag = ctx->is_session_key;

        /* Store the key object in context so it persists past this call */
        ctx->key_obj = ec_key;

        // Build OSSL_PARAM array to return to OpenSSL
        // Pass the actual AZIHSM_EC_KEY structure as binary reference
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE,
            ec_key, /* Pass the actual key object bytes */
            sizeof(AZIHSM_EC_KEY)
        );
        params[3] = OSSL_PARAM_construct_end();
    }
    else
    {
        // For non-EC keys, return raw reference (RSA, AES, etc.)
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE,
            &ctx->key_handles,
            sizeof(AZIHSM_KEY_PAIR_OBJ)
        );
        params[3] = OSSL_PARAM_construct_end();
    }

    // Mark as EOF (single object per store)
    ctx->eof = 1;

    // Call OpenSSL's callback with the object description
    return object_cb(params, object_cbarg);
}

static int azihsm_store_eof(void *loaderctx)
{
    AZIHSM_STORE_CTX *ctx = (AZIHSM_STORE_CTX *)loaderctx;

    if (ctx == NULL)
        return 1;

    return ctx->eof;
}

static int azihsm_store_close(void *loaderctx)
{
    store_ctx_free((AZIHSM_STORE_CTX *)loaderctx);
    return OSSL_SUCCESS;
}

static void *azihsm_store_attach(ossl_unused void *loaderctx, ossl_unused OSSL_CORE_BIO *in)
{
    return NULL;
}

static int azihsm_store_export_object(
    ossl_unused void *loaderctx,
    ossl_unused const void *reference,
    ossl_unused size_t reference_sz,
    ossl_unused OSSL_CALLBACK *export_cb,
    ossl_unused void *export_cbarg
)
{
    return OSSL_FAILURE;
}

static int azihsm_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    AZIHSM_STORE_CTX *ctx = (AZIHSM_STORE_CTX *)loaderctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return OSSL_SUCCESS;

    if (params == NULL)
        return OSSL_SUCCESS;

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_int(p, &ctx->expect))
            return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_store_settable_ctx_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

const OSSL_DISPATCH azihsm_ossl_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))azihsm_store_open },
    { OSSL_FUNC_STORE_ATTACH, (void (*)(void))azihsm_store_attach },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))azihsm_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))azihsm_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))azihsm_store_close },
    { OSSL_FUNC_STORE_EXPORT_OBJECT, (void (*)(void))azihsm_store_export_object },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))azihsm_store_set_ctx_params },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_store_settable_ctx_params },
    { 0, NULL }
};

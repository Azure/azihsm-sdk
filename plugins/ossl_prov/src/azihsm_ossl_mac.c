// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"

/*
 * HMAC (Hash-based Message Authentication Code) Implementation
 *
 * This provider implements HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512,
 * delegating the actual cryptographic operations to the HSM via the
 * streaming sign API (azihsm_crypt_sign_init/update/final).
 *
 * HMAC-SHA1 is intentionally unsupported as a security best practice
 * (no AZIHSM_KEY_KIND_HMAC_SHA1 is defined).
 *
 * Key Design:
 * - HMAC key comes from a masked key file (path via OSSL_MAC_PARAM_KEY)
 * - The digest algorithm (SHA256/384/512) is set via OSSL_MAC_PARAM_DIGEST
 * - The key kind for unmasking is derived from the selected digest
 */

/* Maximum file size for masked key files (64KB) */
#define MAX_FILE_SIZE (64 * 1024)

/* Forward declaration */
static int azihsm_ossl_mac_set_ctx_params(void *mctx, const OSSL_PARAM params[]);

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;

    /* Key configuration */
    char key_file[4096];
    azihsm_handle key_handle;
    bool key_loaded;

    /* Algorithm configuration */
    azihsm_algo_id hmac_algo_id;
    azihsm_key_kind key_kind;
    size_t mac_size;

    /* Streaming context */
    azihsm_handle ctx_handle;
    bool ctx_initialized;
} AZIHSM_HMAC_CTX;

/* Helper: Read file contents */
static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = NULL;
    long size;
    unsigned char *buf = NULL;
    size_t bytes_read;

    if (path == NULL || out_len == NULL)
    {
        return NULL;
    }

    f = fopen(path, "rb");
    if (f == NULL)
    {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }

    size = ftell(f);
    if (size <= 0 || size > MAX_FILE_SIZE)
    {
        fclose(f);
        return NULL;
    }

    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return NULL;
    }

    buf = OPENSSL_malloc((size_t)size);
    if (buf == NULL)
    {
        fclose(f);
        return NULL;
    }

    bytes_read = fread(buf, 1, (size_t)size, f);
    fclose(f);

    if (bytes_read != (size_t)size)
    {
        OPENSSL_free(buf);
        return NULL;
    }

    *out_len = (size_t)size;
    return buf;
}

/* Helper: Load and unmask HMAC key from file */
static int load_and_unmask_key(AZIHSM_HMAC_CTX *ctx)
{
    unsigned char *masked_key_data = NULL;
    size_t masked_key_size = 0;
    struct azihsm_buffer masked_buf;
    azihsm_status status;

    if (ctx->key_loaded)
    {
        return OSSL_SUCCESS;
    }

    if (ctx->key_file[0] == '\0')
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return OSSL_FAILURE;
    }

    if (ctx->key_kind == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return OSSL_FAILURE;
    }

    masked_key_data = read_file(ctx->key_file, &masked_key_size);
    if (masked_key_data == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (masked_key_size > UINT32_MAX)
    {
        OPENSSL_cleanse(masked_key_data, masked_key_size);
        OPENSSL_free(masked_key_data);
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    masked_buf.ptr = masked_key_data;
    masked_buf.len = (uint32_t)masked_key_size;

    /* Unmask the HMAC key */
    status = azihsm_key_unmask(
        ctx->provctx->session,
        ctx->key_kind,
        &masked_buf,
        &ctx->key_handle
    );

    OPENSSL_cleanse(masked_key_data, masked_key_size);
    OPENSSL_free(masked_key_data);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    }

    ctx->key_loaded = true;
    return OSSL_SUCCESS;
}

/* Context Management Functions */

static void *azihsm_ossl_mac_newctx(void *provctx)
{
    AZIHSM_HMAC_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(AZIHSM_HMAC_CTX));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = (AZIHSM_OSSL_PROV_CTX *)provctx;

    /* Default to SHA-256 */
    ctx->hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA256;
    ctx->key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
    ctx->mac_size = 32;

    return ctx;
}

static void azihsm_ossl_mac_freectx(void *mctx)
{
    AZIHSM_HMAC_CTX *ctx = (AZIHSM_HMAC_CTX *)mctx;

    if (ctx == NULL)
    {
        return;
    }

    /* Free streaming context handle if initialized */
    if (ctx->ctx_initialized && ctx->ctx_handle != 0)
    {
        azihsm_free_handle(ctx->ctx_handle);
    }

    /* Delete key handle if loaded */
    if (ctx->key_loaded && ctx->key_handle != 0)
    {
        azihsm_key_delete(ctx->key_handle);
    }

    OPENSSL_clear_free(ctx, sizeof(AZIHSM_HMAC_CTX));
}

static void *azihsm_ossl_mac_dupctx(void *mctx)
{
    AZIHSM_HMAC_CTX *src_ctx = (AZIHSM_HMAC_CTX *)mctx;
    AZIHSM_HMAC_CTX *dst_ctx;

    if (src_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    dst_ctx = OPENSSL_zalloc(sizeof(AZIHSM_HMAC_CTX));
    if (dst_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy configuration (not handles) */
    dst_ctx->provctx = src_ctx->provctx;
    memcpy(dst_ctx->key_file, src_ctx->key_file, sizeof(dst_ctx->key_file));
    dst_ctx->hmac_algo_id = src_ctx->hmac_algo_id;
    dst_ctx->key_kind = src_ctx->key_kind;
    dst_ctx->mac_size = src_ctx->mac_size;

    /* Don't share handles - duplicate will need to reload */
    dst_ctx->key_handle = 0;
    dst_ctx->key_loaded = false;
    dst_ctx->ctx_handle = 0;
    dst_ctx->ctx_initialized = false;

    return dst_ctx;
}

/* MAC Generation Functions */

static int azihsm_ossl_mac_init(
    void *mctx,
    ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    const OSSL_PARAM params[]
)
{
    AZIHSM_HMAC_CTX *ctx = (AZIHSM_HMAC_CTX *)mctx;
    struct azihsm_algo algo;
    azihsm_status status;

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Apply params if provided */
    if (params != NULL)
    {
        if (!azihsm_ossl_mac_set_ctx_params(ctx, params))
        {
            return OSSL_FAILURE;
        }
    }

    /* Clean up previous context if reinitializing */
    if (ctx->ctx_initialized && ctx->ctx_handle != 0)
    {
        azihsm_free_handle(ctx->ctx_handle);
        ctx->ctx_handle = 0;
        ctx->ctx_initialized = false;
    }

    /* Load key from file if not already loaded */
    if (!load_and_unmask_key(ctx))
    {
        return OSSL_FAILURE;
    }

    /* Initialize HMAC streaming context */
    algo.id = ctx->hmac_algo_id;
    algo.params = NULL;
    algo.len = 0;

    status = azihsm_crypt_sign_init(&algo, ctx->key_handle, &ctx->ctx_handle);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    ctx->ctx_initialized = true;
    return OSSL_SUCCESS;
}

static int azihsm_ossl_mac_update(void *mctx, const unsigned char *in, size_t inl)
{
    AZIHSM_HMAC_CTX *ctx = (AZIHSM_HMAC_CTX *)mctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    if (!ctx->ctx_initialized || ctx->ctx_handle == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    /* Empty update is a no-op */
    if (in == NULL || inl == 0)
    {
        return OSSL_SUCCESS;
    }

    /* Bounds check */
    if (inl > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    data_buf.ptr = (uint8_t *)in;
    data_buf.len = (uint32_t)inl;

    status = azihsm_crypt_sign_update(ctx->ctx_handle, &data_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_mac_final(
    void *mctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize
)
{
    AZIHSM_HMAC_CTX *ctx = (AZIHSM_HMAC_CTX *)mctx;
    struct azihsm_buffer mac_buf;
    azihsm_status status;

    if (ctx == NULL || outl == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    if (!ctx->ctx_initialized || ctx->ctx_handle == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    /* Size query */
    if (out == NULL)
    {
        *outl = ctx->mac_size;
        return OSSL_SUCCESS;
    }

    /* Verify output buffer is large enough */
    if (outsize < ctx->mac_size)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return OSSL_FAILURE;
    }

    mac_buf.ptr = out;
    mac_buf.len = (uint32_t)ctx->mac_size;

    status = azihsm_crypt_sign_final(ctx->ctx_handle, &mac_buf);

    /* Context is consumed after final */
    ctx->ctx_handle = 0;
    ctx->ctx_initialized = false;

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    *outl = mac_buf.len;
    return OSSL_SUCCESS;
}

/* MAC Parameter Functions */

static int azihsm_ossl_mac_get_params(OSSL_PARAM params[], size_t macsize)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, macsize))
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_hmac_get_params(OSSL_PARAM params[])
{
    /* HMAC max size is SHA-512 = 64 bytes */
    return azihsm_ossl_mac_get_params(params, 64);
}

static int azihsm_ossl_mac_get_ctx_params(void *mctx, OSSL_PARAM params[])
{
    AZIHSM_HMAC_CTX *ctx = (AZIHSM_HMAC_CTX *)mctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL)
    {
        if (!OSSL_PARAM_set_size_t(p, ctx->mac_size))
        {
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (p != NULL)
    {
        /* Block size depends on digest: SHA-256/384/512 all use 128-byte blocks */
        size_t block_size;
        switch (ctx->hmac_algo_id)
        {
        case AZIHSM_ALGO_ID_HMAC_SHA256:
            block_size = 64;
            break;
        case AZIHSM_ALGO_ID_HMAC_SHA384:
        case AZIHSM_ALGO_ID_HMAC_SHA512:
            block_size = 128;
            break;
        default:
            block_size = 64;
            break;
        }
        if (!OSSL_PARAM_set_size_t(p, block_size))
        {
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_mac_set_ctx_params(void *mctx, const OSSL_PARAM params[])
{
    AZIHSM_HMAC_CTX *ctx = (AZIHSM_HMAC_CTX *)mctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    if (params == NULL)
    {
        return OSSL_SUCCESS;
    }

    /* Digest algorithm */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname) || mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        /* Map digest name to HMAC algorithm ID and key kind */
        if (OPENSSL_strcasecmp(mdname, "SHA256") == 0 ||
            OPENSSL_strcasecmp(mdname, "SHA2-256") == 0)
        {
            ctx->hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA256;
            ctx->key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
            ctx->mac_size = 32;
        }
        else if (OPENSSL_strcasecmp(mdname, "SHA384") == 0 ||
                 OPENSSL_strcasecmp(mdname, "SHA2-384") == 0)
        {
            ctx->hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA384;
            ctx->key_kind = AZIHSM_KEY_KIND_HMAC_SHA384;
            ctx->mac_size = 48;
        }
        else if (OPENSSL_strcasecmp(mdname, "SHA512") == 0 ||
                 OPENSSL_strcasecmp(mdname, "SHA2-512") == 0)
        {
            ctx->hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA512;
            ctx->key_kind = AZIHSM_KEY_KIND_HMAC_SHA512;
            ctx->mac_size = 64;
        }
        else
        {
            /* SHA-1 and other digests not supported */
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return OSSL_FAILURE;
        }

        /* If key was already loaded with different kind, need to reload */
        if (ctx->key_loaded)
        {
            azihsm_key_delete(ctx->key_handle);
            ctx->key_handle = 0;
            ctx->key_loaded = false;
        }
    }

    /* Key file path (azihsm-specific: OSSL_MAC_PARAM_KEY is treated as file path) */
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p != NULL)
    {
        const void *key_data = NULL;
        size_t key_len = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, &key_data, &key_len))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (key_data == NULL || key_len == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return OSSL_FAILURE;
        }

        /* Treat key data as file path string */
        if (key_len >= sizeof(ctx->key_file))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return OSSL_FAILURE;
        }

        memcpy(ctx->key_file, key_data, key_len);
        ctx->key_file[key_len] = '\0';

        /* Reset key loaded state since path changed */
        if (ctx->key_loaded)
        {
            azihsm_key_delete(ctx->key_handle);
            ctx->key_handle = 0;
            ctx->key_loaded = false;
        }
    }

    return OSSL_SUCCESS;
}

/* MAC Parameter Descriptors */

static const OSSL_PARAM *azihsm_ossl_mac_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_mac_gettable_ctx_params(
    ossl_unused void *mctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_mac_settable_ctx_params(
    ossl_unused void *mctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH azihsm_ossl_hmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))azihsm_ossl_mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))azihsm_ossl_mac_freectx },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))azihsm_ossl_mac_dupctx },

    { OSSL_FUNC_MAC_INIT, (void (*)(void))azihsm_ossl_mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))azihsm_ossl_mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))azihsm_ossl_mac_final },

    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))azihsm_ossl_hmac_get_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_get_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_set_ctx_params },

    { OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_mac_gettable_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_gettable_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_mac_settable_ctx_params },
    { 0, NULL }
};

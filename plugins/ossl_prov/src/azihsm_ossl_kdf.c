// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"

/*
 * HKDF (HMAC-based Key Derivation Function) Implementation
 *
 * This provider implements HKDF per RFC 5869, delegating the actual
 * cryptographic operations to the HSM via azihsm_key_derive().
 *
 * Key Design Decisions:
 * - IKM (Input Keying Material) comes from a masked key file (e.g., ECDH output)
 * - Output is a masked key blob written to a file (not raw bytes)
 * - Only full HKDF mode (Extract-and-Expand) is supported
 *
 * Custom Parameters (azihsm-specific):
 * - ikm_file: Path to masked shared secret file (IKM source)
 * - output_file: Path to write derived masked key
 * - derived_key_type: "aes" or "hmac" (default: "aes")
 * - derived_key_bits: Key size in bits (default: 256)
 */

/* Derived key type constants */
#define DERIVED_KEY_TYPE_AES 1
#define DERIVED_KEY_TYPE_HMAC 2

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;

    /* HKDF Parameters */
    const EVP_MD *md;
    azihsm_algo_id hmac_algo_id;

    /* IKM - Input Keying Material (from masked key file) */
    char ikm_file[4096];
    azihsm_handle ikm_handle;
    bool ikm_loaded;

    /* Salt (optional) */
    unsigned char *salt;
    size_t salt_len;

    /* Info/Context (optional) */
    unsigned char *info;
    size_t info_len;

    /* Output configuration */
    char output_file[4096];
    int derived_key_type; /* DERIVED_KEY_TYPE_AES or DERIVED_KEY_TYPE_HMAC */
    uint32_t derived_key_bits;
} AZIHSM_HKDF_CTX;

/* Helper: Convert EVP_MD to HMAC algorithm ID */
static azihsm_algo_id evp_md_to_hmac_algo_id(const EVP_MD *md)
{
    if (md == NULL)
    {
        return 0;
    }

    switch (EVP_MD_type(md))
    {
    case NID_sha1:
        return AZIHSM_ALGO_ID_HMAC_SHA1;
    case NID_sha256:
        return AZIHSM_ALGO_ID_HMAC_SHA256;
    case NID_sha384:
        return AZIHSM_ALGO_ID_HMAC_SHA384;
    case NID_sha512:
        return AZIHSM_ALGO_ID_HMAC_SHA512;
    default:
        return 0;
    }
}

/* Maximum file size for read_file (64KB, consistent with keymgmt) */
#define MAX_FILE_SIZE (64 * 1024)

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

/* Helper: Load and unmask IKM from file */
static int load_and_unmask_ikm(AZIHSM_HKDF_CTX *ctx)
{
    unsigned char *masked_key_data = NULL;
    size_t masked_key_size = 0;
    struct azihsm_buffer masked_buf;
    azihsm_status status;

    if (ctx->ikm_loaded)
    {
        return OSSL_SUCCESS;
    }

    if (ctx->ikm_file[0] == '\0')
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return OSSL_FAILURE;
    }

    masked_key_data = read_file(ctx->ikm_file, &masked_key_size);
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

    /* Unmask the shared secret key */
    status = azihsm_key_unmask(
        ctx->provctx->session,
        AZIHSM_KEY_KIND_SHARED_SECRET,
        &masked_buf,
        &ctx->ikm_handle
    );

    OPENSSL_cleanse(masked_key_data, masked_key_size);
    OPENSSL_free(masked_key_data);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    }

    ctx->ikm_loaded = true;
    return OSSL_SUCCESS;
}

/*
 * Helper: Extract masked key from a derived key handle and write it to a file.
 *
 * Allocates a temporary buffer, retrieves the masked key property from the HSM,
 * writes it to the output file, and cleanses the buffer before freeing.
 */
static int extract_and_write_masked_key(azihsm_handle derived_handle, const char *output_file)
{
    const uint32_t buffer_size = 8192;
    uint8_t *buffer = NULL;
    azihsm_status status;
    int fd;
    ssize_t written;

    buffer = OPENSSL_malloc(buffer_size);
    if (buffer == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return OSSL_FAILURE;
    }

    struct azihsm_key_prop masked_prop = {
        .id = AZIHSM_KEY_PROP_ID_MASKED_KEY,
        .val = buffer,
        .len = buffer_size,
    };

    status = azihsm_key_get_prop(derived_handle, &masked_prop);
    if (status != AZIHSM_STATUS_SUCCESS || masked_prop.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        OPENSSL_cleanse(buffer, buffer_size);
        OPENSSL_free(buffer);
        return OSSL_FAILURE;
    }

    fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
        OPENSSL_cleanse(buffer, buffer_size);
        OPENSSL_free(buffer);
        return OSSL_FAILURE;
    }

    written = write(fd, buffer, masked_prop.len);
    close(fd);

    OPENSSL_cleanse(buffer, buffer_size);
    OPENSSL_free(buffer);

    if (written < 0 || (uint32_t)written != masked_prop.len)
    {
        unlink(output_file);
        ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

/* Context Management Functions */

static void *azihsm_ossl_hkdf_newctx(void *provctx)
{
    AZIHSM_HKDF_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(AZIHSM_HKDF_CTX));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = (AZIHSM_OSSL_PROV_CTX *)provctx;
    ctx->md = EVP_sha256(); /* Default to SHA-256 */
    ctx->hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA256;
    ctx->derived_key_type = DERIVED_KEY_TYPE_AES;
    ctx->derived_key_bits = 256;

    return ctx;
}

static void azihsm_ossl_hkdf_freectx(void *kctx)
{
    AZIHSM_HKDF_CTX *ctx = (AZIHSM_HKDF_CTX *)kctx;

    if (ctx == NULL)
    {
        return;
    }

    /* Delete IKM handle if loaded */
    if (ctx->ikm_loaded && ctx->ikm_handle != 0)
    {
        azihsm_key_delete(ctx->ikm_handle);
    }

    /* Cleanse and free salt */
    if (ctx->salt != NULL)
    {
        OPENSSL_cleanse(ctx->salt, ctx->salt_len);
        OPENSSL_free(ctx->salt);
    }

    /* Cleanse and free info */
    if (ctx->info != NULL)
    {
        OPENSSL_cleanse(ctx->info, ctx->info_len);
        OPENSSL_free(ctx->info);
    }

    OPENSSL_clear_free(ctx, sizeof(AZIHSM_HKDF_CTX));
}

static void *azihsm_ossl_hkdf_dupctx(void *kctx)
{
    AZIHSM_HKDF_CTX *ctx = (AZIHSM_HKDF_CTX *)kctx;
    AZIHSM_HKDF_CTX *dup;

    if (ctx == NULL)
    {
        return NULL;
    }

    dup = OPENSSL_zalloc(sizeof(AZIHSM_HKDF_CTX));
    if (dup == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memcpy(dup, ctx, sizeof(AZIHSM_HKDF_CTX));

    /* Deep copy salt */
    dup->salt = NULL;
    if (ctx->salt != NULL && ctx->salt_len > 0)
    {
        dup->salt = OPENSSL_malloc(ctx->salt_len);
        if (dup->salt == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            OPENSSL_clear_free(dup, sizeof(AZIHSM_HKDF_CTX));
            return NULL;
        }
        memcpy(dup->salt, ctx->salt, ctx->salt_len);
    }

    /* Deep copy info */
    dup->info = NULL;
    if (ctx->info != NULL && ctx->info_len > 0)
    {
        dup->info = OPENSSL_malloc(ctx->info_len);
        if (dup->info == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            OPENSSL_cleanse(dup->salt, ctx->salt_len);
            OPENSSL_free(dup->salt);
            OPENSSL_clear_free(dup, sizeof(AZIHSM_HKDF_CTX));
            return NULL;
        }
        memcpy(dup->info, ctx->info, ctx->info_len);
    }

    /* IKM handle cannot be shared - dup must reload from file */
    dup->ikm_loaded = false;
    dup->ikm_handle = 0;

    return dup;
}

static void azihsm_ossl_hkdf_reset(void *kctx)
{
    AZIHSM_HKDF_CTX *ctx = (AZIHSM_HKDF_CTX *)kctx;
    AZIHSM_OSSL_PROV_CTX *provctx;

    if (ctx == NULL)
    {
        return;
    }

    provctx = ctx->provctx;

    /* Delete IKM handle if loaded */
    if (ctx->ikm_loaded && ctx->ikm_handle != 0)
    {
        azihsm_key_delete(ctx->ikm_handle);
    }

    /* Cleanse and free salt */
    if (ctx->salt != NULL)
    {
        OPENSSL_cleanse(ctx->salt, ctx->salt_len);
        OPENSSL_free(ctx->salt);
    }

    /* Cleanse and free info */
    if (ctx->info != NULL)
    {
        OPENSSL_cleanse(ctx->info, ctx->info_len);
        OPENSSL_free(ctx->info);
    }

    /* Reset to defaults */
    memset(ctx, 0, sizeof(AZIHSM_HKDF_CTX));
    ctx->provctx = provctx;
    ctx->md = EVP_sha256();
    ctx->hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA256;
    ctx->derived_key_type = DERIVED_KEY_TYPE_AES;
    ctx->derived_key_bits = 256;
}

/* KDF Parameter Functions */

static int azihsm_ossl_hkdf_set_ctx_params(void *kctx, const OSSL_PARAM params[])
{
    AZIHSM_HKDF_CTX *ctx = (AZIHSM_HKDF_CTX *)kctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    if (params == NULL)
    {
        return OSSL_SUCCESS;
    }

    /* Digest algorithm */
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname) || mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        ctx->md = EVP_get_digestbyname(mdname);
        if (ctx->md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return OSSL_FAILURE;
        }

        ctx->hmac_algo_id = evp_md_to_hmac_algo_id(ctx->md);
        if (ctx->hmac_algo_id == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return OSSL_FAILURE;
        }
    }

    /* Salt */
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p != NULL)
    {
        if (ctx->salt != NULL)
        {
            OPENSSL_cleanse(ctx->salt, ctx->salt_len);
            OPENSSL_free(ctx->salt);
        }
        ctx->salt = NULL;
        ctx->salt_len = 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->salt, 0, &ctx->salt_len))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
    }

    /* Info */
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (p != NULL)
    {
        if (ctx->info != NULL)
        {
            OPENSSL_cleanse(ctx->info, ctx->info_len);
            OPENSSL_free(ctx->info);
        }
        ctx->info = NULL;
        ctx->info_len = 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->info, 0, &ctx->info_len))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
    }

    /* IKM file path (azihsm-specific: OSSL_KDF_PARAM_KEY is treated as file path) */
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p != NULL)
    {
        const char *path = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &path) || path == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (strlen(path) >= sizeof(ctx->ikm_file))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        snprintf(ctx->ikm_file, sizeof(ctx->ikm_file), "%s", path);

        /* Reset IKM loaded state since path changed */
        if (ctx->ikm_loaded && ctx->ikm_handle != 0)
        {
            azihsm_key_delete(ctx->ikm_handle);
            ctx->ikm_handle = 0;
            ctx->ikm_loaded = false;
        }
    }

    /* Output file (azihsm-specific) */
    p = OSSL_PARAM_locate_const(params, "output_file");
    if (p != NULL)
    {
        const char *path = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &path) || path == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (strlen(path) >= sizeof(ctx->output_file))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        snprintf(ctx->output_file, sizeof(ctx->output_file), "%s", path);
    }

    /* Derived key type (azihsm-specific) */
    p = OSSL_PARAM_locate_const(params, "derived_key_type");
    if (p != NULL)
    {
        const char *type_str = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &type_str) || type_str == NULL)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (strcasecmp(type_str, "aes") == 0)
        {
            ctx->derived_key_type = DERIVED_KEY_TYPE_AES;
        }
        else if (strcasecmp(type_str, "hmac") == 0)
        {
            ctx->derived_key_type = DERIVED_KEY_TYPE_HMAC;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
    }

    /* Derived key bits (azihsm-specific) */
    p = OSSL_PARAM_locate_const(params, "derived_key_bits");
    if (p != NULL)
    {
        uint32_t bits = 0;
        if (!OSSL_PARAM_get_uint32(p, &bits))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
        ctx->derived_key_bits = bits;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_hkdf_get_ctx_params(void *kctx, OSSL_PARAM params[])
{
    AZIHSM_HKDF_CTX *ctx = (AZIHSM_HKDF_CTX *)kctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL)
    {
        /* Return the derived key size in bytes */
        size_t size = ctx->derived_key_bits / 8;
        if (!OSSL_PARAM_set_size_t(p, size))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

/* KDF Derivation */

static int azihsm_ossl_hkdf_derive(
    void *kctx,
    unsigned char *key,
    ossl_unused size_t keylen,
    const OSSL_PARAM params[]
)
{
    AZIHSM_HKDF_CTX *ctx = (AZIHSM_HKDF_CTX *)kctx;
    azihsm_status status;
    azihsm_handle derived_handle = 0;
    azihsm_key_kind derived_kind;
    azihsm_key_prop_id usage_prop1;
    azihsm_key_prop_id usage_prop2;
    const azihsm_key_class secret_class = AZIHSM_KEY_CLASS_SECRET;
    const bool enable = true;
    int ret;

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Apply params if provided */
    if (params != NULL)
    {
        if (!azihsm_ossl_hkdf_set_ctx_params(ctx, params))
        {
            return OSSL_FAILURE;
        }
    }

    /*
     * Size query: if key is NULL, just return success.
     * The actual size is returned via get_ctx_params(OSSL_KDF_PARAM_SIZE).
     */
    if (key == NULL)
    {
        return OSSL_SUCCESS;
    }

    /* Validate required parameters */
    if (ctx->ikm_file[0] == '\0')
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return OSSL_FAILURE;
    }

    if (ctx->output_file[0] == '\0')
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Step 1: Load and unmask IKM from file */
    if (!load_and_unmask_ikm(ctx))
    {
        return OSSL_FAILURE;
    }

    /* Step 2: Build HKDF algorithm parameters */
    struct azihsm_buffer salt_buf = { 0 };
    struct azihsm_buffer info_buf = { 0 };

    if (ctx->salt != NULL && ctx->salt_len > 0)
    {
        if (ctx->salt_len > UINT32_MAX)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return OSSL_FAILURE;
        }
        salt_buf.ptr = ctx->salt;
        salt_buf.len = (uint32_t)ctx->salt_len;
    }

    if (ctx->info != NULL && ctx->info_len > 0)
    {
        if (ctx->info_len > UINT32_MAX)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return OSSL_FAILURE;
        }
        info_buf.ptr = ctx->info;
        info_buf.len = (uint32_t)ctx->info_len;
    }

    struct azihsm_algo_hkdf_params hkdf_params = {
        .hmac_algo_id = ctx->hmac_algo_id,
        .salt = (ctx->salt != NULL) ? &salt_buf : NULL,
        .info = (ctx->info != NULL) ? &info_buf : NULL,
    };

    struct azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_HKDF_DERIVE,
        .params = &hkdf_params,
        .len = sizeof(hkdf_params),
    };

    /* Step 3: Determine derived key kind and usage properties */
    if (ctx->derived_key_type == DERIVED_KEY_TYPE_AES)
    {
        derived_kind = AZIHSM_KEY_KIND_AES;
        usage_prop1 = AZIHSM_KEY_PROP_ID_ENCRYPT;
        usage_prop2 = AZIHSM_KEY_PROP_ID_DECRYPT;
    }
    else
    {
        /* HMAC key - kind depends on hash algorithm */
        switch (ctx->hmac_algo_id)
        {
        case AZIHSM_ALGO_ID_HMAC_SHA256:
            derived_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
            break;
        case AZIHSM_ALGO_ID_HMAC_SHA384:
            derived_kind = AZIHSM_KEY_KIND_HMAC_SHA384;
            break;
        case AZIHSM_ALGO_ID_HMAC_SHA512:
            derived_kind = AZIHSM_KEY_KIND_HMAC_SHA512;
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return OSSL_FAILURE;
        }
        usage_prop1 = AZIHSM_KEY_PROP_ID_SIGN;
        usage_prop2 = AZIHSM_KEY_PROP_ID_VERIFY;
    }

    struct azihsm_key_prop derive_props[] = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS,
          .val = (void *)&secret_class,
          .len = sizeof(secret_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND,
          .val = (void *)&derived_kind,
          .len = sizeof(derived_kind) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
          .val = (void *)&ctx->derived_key_bits,
          .len = sizeof(ctx->derived_key_bits) },
        { .id = usage_prop1, .val = (void *)&enable, .len = sizeof(enable) },
        { .id = usage_prop2, .val = (void *)&enable, .len = sizeof(enable) },
    };

    struct azihsm_key_prop_list derive_prop_list = {
        .props = derive_props,
        .count = sizeof(derive_props) / sizeof(derive_props[0]),
    };

    /* Step 4: Call azihsm_key_derive */
    status = azihsm_key_derive(
        ctx->provctx->session,
        &algo,
        ctx->ikm_handle,
        &derive_prop_list,
        &derived_handle
    );

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return OSSL_FAILURE;
    }

    /* Step 5: Extract masked key and write to output file */
    ret = extract_and_write_masked_key(derived_handle, ctx->output_file);

    azihsm_key_delete(derived_handle);
    return ret;
}

/* KDF Parameter Descriptors */

static int azihsm_ossl_hkdf_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL)
    {
        /* Variable output size */
        if (!OSSL_PARAM_set_size_t(p, SIZE_MAX))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_ossl_hkdf_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_hkdf_gettable_ctx_params(
    ossl_unused void *kctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_hkdf_settable_ctx_params(
    ossl_unused void *kctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_utf8_string("output_file", NULL, 0),
        OSSL_PARAM_utf8_string("derived_key_type", NULL, 0),
        OSSL_PARAM_uint32("derived_key_bits", NULL),
        OSSL_PARAM_END,
    };
    return params;
}

/* HKDF Dispatch Table */
const OSSL_DISPATCH azihsm_ossl_hkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))azihsm_ossl_hkdf_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))azihsm_ossl_hkdf_freectx },
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void))azihsm_ossl_hkdf_dupctx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void))azihsm_ossl_hkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))azihsm_ossl_hkdf_derive },
    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void))azihsm_ossl_hkdf_get_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_hkdf_get_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_hkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_hkdf_gettable_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))azihsm_ossl_hkdf_settable_ctx_params },
    { 0, NULL }
};

// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_store.h"

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;  // Provider context (contains HSM session)
    char *file_path;                 // File path extracted from azihsm:// URI
    int eof;                         // 0=not loaded, 1=loaded/EOF
    AZIHSM_KEY_PAIR_OBJ key_handles; // Key handles after unmasking
    int key_type;                    // AZIHSM_KEY_KIND_ECC, _RSA, _AES, etc.
} AZIHSM_STORE_CTX;

/*
 * Allocate and initialize a new store context
 */
static AZIHSM_STORE_CTX *store_ctx_new(AZIHSM_OSSL_PROV_CTX *provctx)
{
    AZIHSM_STORE_CTX *ctx = NULL;

    fprintf(stderr, "[AZIHSM STORE] store_ctx_new() called, provctx=%p\n", (void *)provctx);
    fflush(stderr);

    if (provctx == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: provctx is NULL\n");
        fflush(stderr);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(AZIHSM_STORE_CTX));
    if (ctx == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: Failed to allocate store context\n");
        fflush(stderr);
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->file_path = NULL;
    ctx->eof = 0;
    ctx->key_type = -1;  // Uninitialized

    fprintf(stderr, "[AZIHSM STORE] store_ctx_new() created context %p\n", (void *)ctx);
    fflush(stderr);
    return ctx;
}

/*
 * Free store context and all associated resources
 */
static void store_ctx_free(AZIHSM_STORE_CTX *ctx)
{
    fprintf(stderr, "[AZIHSM STORE] store_ctx_free() called with ctx=%p\n", (void *)ctx);
    fflush(stderr);

    if (ctx == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] WARNING: ctx is NULL\n");
        fflush(stderr);
        return;
    }

    if (ctx->file_path != NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] Freeing file_path: %s\n", ctx->file_path);
        fflush(stderr);
        OPENSSL_free(ctx->file_path);
        ctx->file_path = NULL;
    }

    fprintf(stderr, "[AZIHSM STORE] Freeing context %p\n", (void *)ctx);
    fflush(stderr);
    OPENSSL_clear_free(ctx, sizeof(AZIHSM_STORE_CTX));
}


/*
 * Parse azihsm:// URI and extract file path
 * 
 * Example: azihsm://./masked_key.bin -> ./masked_key.bin
 * 
 * @param uri URI string starting with "azihsm://"
 * @param out_path Output pointer to allocated file path string
 * 
 * @return 1 on success, 0 on failure (caller must free out_path)
 */
static int parse_azihsm_uri(const char *uri, char **out_path)
{
    const char *scheme = "azihsm://";
    size_t scheme_len = 9;  // strlen("azihsm://")
    const char *path_start;
    size_t path_len;

    fprintf(stderr, "[AZIHSM STORE] parse_azihsm_uri() called with URI: %s\n", uri);
    fflush(stderr);

    if (uri == NULL || out_path == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: uri or out_path is NULL\n");
        fflush(stderr);
        return 0;
    }

    // Check URI starts with "azihsm://"
    if (strncmp(uri, scheme, scheme_len) != 0)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: URI does not start with azihsm://\n");
        fflush(stderr);
        return 0;
    }

    path_start = uri + scheme_len;
    path_len = strlen(path_start);

    // Path must not be empty
    if (path_len == 0)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: Path is empty\n");
        fflush(stderr);
        return 0;
    }

    // Allocate and copy path
    *out_path = OPENSSL_malloc(path_len + 1);
    if (*out_path == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: Failed to allocate memory for path\n");
        fflush(stderr);
        return 0;
    }

    strcpy(*out_path, path_start);
    fprintf(stderr, "[AZIHSM STORE] Successfully parsed URI, extracted path: %s\n", *out_path);
    fflush(stderr);
    return 1;
}

/*
 * Read masked key file into buffer
 * 
 * @param path File path
 * @param out_len Output size of buffer
 * 
 * @return Allocated buffer on success (caller must free), NULL on failure
 */
static unsigned char *read_masked_key_file(const char *path, size_t *out_len)
{
    FILE *f = NULL;
    long size;
    unsigned char *buf = NULL;
    size_t bytes_read;

    if (path == NULL || out_len == NULL)
    {
        return NULL;
    }

    // Open file
    f = fopen(path, "rb");
    if (f == NULL)
    {
        return NULL;
    }

    // Get file size
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

    // Allocate buffer
    buf = OPENSSL_malloc(size);
    if (buf == NULL)
    {
        fclose(f);
        return NULL;
    }

    // Read file
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

/*
 * Load and unmask key from file
 */
static int load_and_unmask_key(AZIHSM_STORE_CTX *ctx)
{
    // STUB: Return 0 (failure) for now
    // This will be implemented in Phase 3
    (void)ctx;
    return 0;
}

/*
 * Map key kind to OpenSSL algorithm string
 * 
 * @param key_kind AZIHSM_KEY_KIND_* value
 * 
 * @return Pointer to static string ("EC", "RSA", "AES") or NULL
 */
static const char *key_kind_to_string(int key_kind)
{
    switch (key_kind)
    {
    case AZIHSM_KEY_KIND_ECC:
        return "EC";
    case AZIHSM_KEY_KIND_RSA:
        return "RSA";
    // AES may be supported in future for key wrapping, not signing
    default:
        return NULL;
    }
}

/*
 * OSSL_FUNC_STORE_OPEN - Create store context and parse URI
 * 
 * Called by OpenSSL when a URI like "azihsm://./key.bin" is encountered
 */
static void *azihsm_store_open(
    void *provctx,
    const char *uri,
    const OSSL_PARAM params[],
    OSSL_CALLBACK *object_cb,
    void *object_cbarg)
{
    AZIHSM_STORE_CTX *ctx = NULL;
    AZIHSM_OSSL_PROV_CTX *prov_ctx = (AZIHSM_OSSL_PROV_CTX *)provctx;
    char *file_path = NULL;

    fprintf(stderr, "[AZIHSM STORE] ========================================\n");
    fprintf(stderr, "[AZIHSM STORE] azihsm_store_open() called\n");
    fprintf(stderr, "[AZIHSM STORE] URI: %s\n", uri ? uri : "NULL");
    fprintf(stderr, "[AZIHSM STORE] provctx: %p\n", provctx);
    fflush(stderr);

    (void)params;      // Unused
    (void)object_cb;   // Unused
    (void)object_cbarg; // Unused

    if (uri == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: uri is NULL\n");
        fflush(stderr);
        return NULL;
    }

    // Parse URI to extract file path
    if (!parse_azihsm_uri(uri, &file_path))
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: Failed to parse URI\n");
        fflush(stderr);
        return NULL;
    }

    // Create context
    ctx = store_ctx_new(prov_ctx);
    if (ctx == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: Failed to create store context\n");
        fflush(stderr);
        OPENSSL_free(file_path);
        return NULL;
    }

    ctx->file_path = file_path;
    fprintf(stderr, "[AZIHSM STORE] azihsm_store_open() SUCCESS, returning ctx=%p\n", (void *)ctx);
    fprintf(stderr, "[AZIHSM STORE] ========================================\n");
    fflush(stderr);
    return (void *)ctx;
}

/*
 * OSSL_FUNC_STORE_LOAD - Load the next object from the store
 */
static int azihsm_store_load(
    void *loaderctx,
    OSSL_CALLBACK *object_cb,
    void *object_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb,
    void *pw_cbarg)
{
    AZIHSM_STORE_CTX *ctx = (AZIHSM_STORE_CTX *)loaderctx;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *data_type;

    fprintf(stderr, "[AZIHSM STORE] ========================================\n");
    fprintf(stderr, "[AZIHSM STORE] azihsm_store_load() called\n");
    fprintf(stderr, "[AZIHSM STORE] ctx=%p, eof=%d\n", (void *)ctx, ctx ? ctx->eof : -1);
    fflush(stderr);

    (void)pw_cb;       // Unused
    (void)pw_cbarg;    // Unused

    if (ctx == NULL || ctx->eof)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: ctx is NULL or EOF already reached\n");
        fflush(stderr);
        return 0;
    }

    fprintf(stderr, "[AZIHSM STORE] Calling load_and_unmask_key()...\n");
    fflush(stderr);
    // Load and unmask the key
    if (!load_and_unmask_key(ctx))
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: load_and_unmask_key() failed (Phase 3 stub)\n");
        fflush(stderr);
        ctx->eof = 1;
        return 0;
    }

    // Get string representation of key type
    data_type = key_kind_to_string(ctx->key_type);
    if (data_type == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] ERROR: Could not convert key_type to string\n");
        fflush(stderr);
        ctx->eof = 1;
        return 0;
    }

    // Build OSSL_PARAM array to return to OpenSSL
    // This describes the object being returned
    params[0] = OSSL_PARAM_construct_int(
        OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_OBJECT_PARAM_REFERENCE,
        &ctx->key_handles, sizeof(AZIHSM_KEY_PAIR_OBJ));
    params[3] = OSSL_PARAM_construct_end();

    // Mark as EOF (single object per store)
    ctx->eof = 1;

    fprintf(stderr, "[AZIHSM STORE] azihsm_store_load() SUCCESS (would return to OpenSSL)\n");
    fprintf(stderr, "[AZIHSM STORE] ========================================\n");
    fflush(stderr);
    // Call OpenSSL's callback with the object description
    return object_cb(params, object_cbarg);
}

/*
 * OSSL_FUNC_STORE_EOF - Check if end of objects reached
 * 
 * Returns 1 if no more objects available, 0 otherwise
 */
static int azihsm_store_eof(void *loaderctx)
{
    AZIHSM_STORE_CTX *ctx = (AZIHSM_STORE_CTX *)loaderctx;
    int eof_status;

    if (ctx == NULL)
    {
        fprintf(stderr, "[AZIHSM STORE] azihsm_store_eof() called, ctx=NULL, returning 1 (EOF)\n");
        fflush(stderr);
        return 1;  // EOF on NULL
    }

    eof_status = ctx->eof;
    fprintf(stderr, "[AZIHSM STORE] azihsm_store_eof() called, ctx=%p, eof=%d\n", (void *)ctx, eof_status);
    fflush(stderr);
    return eof_status;
}

/*
 * OSSL_FUNC_STORE_CLOSE - Close store and free resources
 * 
 * Called when OpenSSL is done with the store
 */
static int azihsm_store_close(void *loaderctx)
{
    fprintf(stderr, "[AZIHSM STORE] ========================================\n");
    fprintf(stderr, "[AZIHSM STORE] azihsm_store_close() called, ctx=%p\n", loaderctx);
    fflush(stderr);
    store_ctx_free((AZIHSM_STORE_CTX *)loaderctx);
    fprintf(stderr, "[AZIHSM STORE] azihsm_store_close() COMPLETE\n");
    fprintf(stderr, "[AZIHSM STORE] ========================================\n");
    fflush(stderr);
    return 1;
}

/*
 * OSSL_FUNC_STORE_ATTACH - Attach to a BIO stream
 * 
 * This store only supports URI-based loading, not BIO attachment.
 * Returns NULL to indicate not implemented.
 */
static void *azihsm_store_attach(void *loaderctx, OSSL_CORE_BIO *in)
{
    (void)loaderctx;  // Unused
    (void)in;         // Unused
    return NULL;      // Not implemented
}

/*
 * OSSL_FUNC_STORE_EXPORT_OBJECT - Export key reference to parameters
 */
static int azihsm_store_export_object(
    void *loaderctx,
    const void *reference,
    size_t reference_sz,
    OSSL_CALLBACK *export_cb,
    void *export_cbarg)
{
    (void)loaderctx;     // Unused
    (void)reference;     // Unused
    (void)reference_sz;  // Unused
    (void)export_cb;     // Unused
    (void)export_cbarg;  // Unused
    return 0;            // Not implemented
}

/*
 * OSSL_FUNC_STORE_SET_CTX_PARAMS - Set context parameters
 * 
 * This store doesn't support search filters, but we implement this
 * to accept (and ignore) any parameters.
 */
static int azihsm_store_set_ctx_params(
    void *loaderctx,
    const OSSL_PARAM params[])
{
    (void)loaderctx;  // Unused
    (void)params;     // Unused
    return 1;         // Accept all parameters
}

/*
 * OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS - Describe settable parameters
 * 
 * This store doesn't support any parameters, so return empty list.
 */
static const OSSL_PARAM *azihsm_store_settable_ctx_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM params[] = {OSSL_PARAM_END};
    return params;
}

const OSSL_DISPATCH azihsm_ossl_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))azihsm_store_open},
    {OSSL_FUNC_STORE_ATTACH, (void (*)(void))azihsm_store_attach},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))azihsm_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))azihsm_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))azihsm_store_close},
    {OSSL_FUNC_STORE_EXPORT_OBJECT, (void (*)(void))azihsm_store_export_object},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))azihsm_store_set_ctx_params},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
     (void (*)(void))azihsm_store_settable_ctx_params},
    {0, NULL}};

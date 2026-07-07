// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_file_io.h"

#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_resiliency.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AZIHSM_OBK_SIZE 48
#define P384_COORD_SIZE 48
#define P384_RAW_SIG_SIZE 96
#define P384_UNCOMPRESSED_POINT_SIZE 97

/*
 * Thin wrapper: write an azihsm_buffer to a file via azihsm_file_write().
 */
static azihsm_status write_buffer_to_file(const char *path, const struct azihsm_buffer *buffer)
{
    if (path == NULL || buffer == NULL || buffer->ptr == NULL || buffer->len == 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_PASSED_NULL_PARAMETER,
            "write_buffer_to_file: invalid arguments"
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    return azihsm_file_write(path, buffer->ptr, buffer->len);
}

/*
 * Retrieves a partition property by ID.
 * Returns AZIHSM_STATUS_SUCCESS on success, error status otherwise.
 */
static azihsm_status get_part_property(
    azihsm_handle device,
    azihsm_part_prop_id prop_id,
    struct azihsm_buffer *buffer
)
{
    azihsm_status status;
    struct azihsm_part_prop prop = { prop_id, NULL, 0 };

    buffer->ptr = NULL;
    buffer->len = 0;

    // First call to get required size
    status = azihsm_part_get_prop(device, &prop);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return status;
    }

    if (prop.len == 0)
    {
        return AZIHSM_STATUS_SUCCESS;
    }

    // Allocate buffer
    buffer->ptr = OPENSSL_malloc(prop.len);
    if (buffer->ptr == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Second call to get actual value
    prop.val = buffer->ptr;
    status = azihsm_part_get_prop(device, &prop);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(buffer->ptr, prop.len);
        OPENSSL_free(buffer->ptr);
        buffer->ptr = NULL;
        return status;
    }

    buffer->len = prop.len;
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Frees an azihsm_buffer.
 */
static void free_buffer(struct azihsm_buffer *buffer)
{
    if (buffer != NULL && buffer->ptr != NULL)
    {
        OPENSSL_cleanse(buffer->ptr, buffer->len);
        OPENSSL_free(buffer->ptr);
        buffer->ptr = NULL;
        buffer->len = 0;
    }
}

/*
 * Loads a binary credential file (ID or PIN) into a fixed-size output buffer.
 * The file must be a regular file containing exactly AZIHSM_CREDENTIALS_SIZE bytes.
 * Returns AZIHSM_STATUS_SUCCESS on success, AZIHSM_STATUS_INTERNAL_ERROR on error.
 */
static azihsm_status load_credentials_from_file(const char *path, uint8_t *output)
{
    int fd = -1;
    struct stat st;
    ssize_t bytes_read = 0;

    if (path == NULL || output == NULL)
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "credentials path is NULL");
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "failed to open credentials file '%s': %s",
            path,
            strerror(errno)
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (fstat(fd, &st) != 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "fstat failed for credentials file '%s': %s",
            path,
            strerror(errno)
        );
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (!S_ISREG(st.st_mode) || st.st_size != AZIHSM_CREDENTIALS_SIZE)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "credentials file '%s' must be a regular file of exactly %d bytes",
            path,
            AZIHSM_CREDENTIALS_SIZE
        );
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    {
        size_t total = 0;

        while (total < AZIHSM_CREDENTIALS_SIZE)
        {
            bytes_read = read(fd, output + total, AZIHSM_CREDENTIALS_SIZE - total);
            if (bytes_read < 0)
            {
                if (errno == EINTR)
                    continue;
                ERR_raise_data(
                    ERR_LIB_PROV,
                    ERR_R_INIT_FAIL,
                    "error reading credentials file '%s': %s",
                    path,
                    strerror(errno)
                );
                close(fd);
                OPENSSL_cleanse(output, AZIHSM_CREDENTIALS_SIZE);
                return AZIHSM_STATUS_INTERNAL_ERROR;
            }
            if (bytes_read == 0)
                break;
            total += (size_t)bytes_read;
        }

        close(fd);

        if (total != AZIHSM_CREDENTIALS_SIZE)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "short read from credentials file '%s': got %zu of %d bytes",
                path,
                total,
                AZIHSM_CREDENTIALS_SIZE
            );
            OPENSSL_cleanse(output, AZIHSM_CREDENTIALS_SIZE);
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
    }

    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Picks and opens the first available HSM device using the given API revision.
 *
 * @param[out] device  Handle to the opened HSM partition
 * @param[in]  api_rev API revision to request when opening the partition
 * @return AZIHSM_STATUS_SUCCESS on success, or a negative error code on failure
 */
static azihsm_status azihsm_get_device_handle(azihsm_handle *device, struct azihsm_api_rev api_rev)
{
    azihsm_status status;
    azihsm_handle device_list;
    uint32_t device_count = 0;

    status = azihsm_part_get_list(&device_list);
    if (status != 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "azihsm_part_get_list() failed with status %d",
            status
        );
        return status;
    }

    status = azihsm_part_get_count(device_list, &device_count);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "azihsm_part_get_count() failed with status %d",
            status
        );
        azihsm_part_free_list(device_list);
        return status;
    }

    for (uint32_t i = 0; i < device_count; i++)
    {
        struct azihsm_part_info info = { { NULL, 0 }, { 0, 0 }, { 0, 0 } };

        // First call to get the required path buffer size
        status = azihsm_part_get_info(device_list, i, &info);
        if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || info.path.len == 0)
        {
            // Skip this device and try the next one
            continue;
        }

        azihsm_char *path = calloc(info.path.len, sizeof(azihsm_char));
        if (path == NULL)
        {
            // skip this device and try the next one
            continue;
        }

        info.path.str = path;

        // Second call to fill the info
        status = azihsm_part_get_info(device_list, i, &info);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            // Skip this device and try the next one
            free(path);
            continue;
        }

        // Skip devices with empty path or no supported API revision
        if (info.path.len == 0 || (info.api_rev_min.major == 0 && info.api_rev_min.minor == 0 &&
                                   info.api_rev_max.major == 0 && info.api_rev_max.minor == 0))
        {
            free(path);
            continue;
        }

        status = azihsm_part_open(&info.path, device, api_rev);
        free(path);

        if (status == AZIHSM_STATUS_SUCCESS)
        {
            // found a device we can open, return it
            azihsm_part_free_list(device_list);
            return AZIHSM_STATUS_SUCCESS;
        }
    }

    // No device could be opened successfully, free the list and return error
    azihsm_part_free_list(device_list);
    ERR_raise_data(
        ERR_LIB_PROV,
        ERR_R_INTERNAL_ERROR,
        "no HSM partition could be opened from %u candidates",
        device_count
    );
    // control shouldn't reach here if the API is well-behaved, but return an error just in case
    // there is no valid device available or all devices fail to open for some reason
    return AZIHSM_STATUS_INTERNAL_ERROR;
}

/*
 * Generate RSA unwrapping key pair, extract masked key (MUK), and save to file.
 * This is called when no MUK file exists to bootstrap the unwrapping key.
 */
/*
 * Extracts the masked key from a private key handle and saves it to a file.
 */
static azihsm_status extract_and_save_masked_key(azihsm_handle priv_key, const char *muk_path)
{
    azihsm_status status;
    struct azihsm_buffer muk_buf = { NULL, 0 };

    struct azihsm_key_prop masked_prop = {
        .id = AZIHSM_KEY_PROP_ID_MASKED_KEY,
        .val = NULL,
        .len = 0,
    };

    /* First call to get required size (expect BUFFER_TOO_SMALL, which sets len) */
    status = azihsm_key_get_prop(priv_key, &masked_prop);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return status;
    }

    if (masked_prop.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    muk_buf.ptr = OPENSSL_malloc(masked_prop.len);
    if (muk_buf.ptr == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    muk_buf.len = masked_prop.len;

    /* Second call to get the actual masked key data */
    masked_prop.val = muk_buf.ptr;
    status = azihsm_key_get_prop(priv_key, &masked_prop);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        free_buffer(&muk_buf);
        return status;
    }

    muk_buf.len = masked_prop.len;

    status = write_buffer_to_file(muk_path, &muk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    }

    free_buffer(&muk_buf);
    return status;
}

static azihsm_status generate_and_save_muk(azihsm_handle session, const char *muk_path)
{
    azihsm_status status;
    azihsm_handle priv_key = 0;
    azihsm_handle pub_key = 0;

    const uint32_t key_bits = 2048;
    const azihsm_key_class priv_class = AZIHSM_KEY_CLASS_PRIVATE;
    const azihsm_key_class pub_class = AZIHSM_KEY_CLASS_PUBLIC;
    const azihsm_key_kind key_kind = AZIHSM_KEY_KIND_RSA;
    const bool can_unwrap = true;
    const bool can_wrap = true;

    struct azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN,
        .params = NULL,
        .len = 0,
    };

    struct azihsm_key_prop priv_key_props[] = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = (void *)&priv_class, .len = sizeof(priv_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&key_bits, .len = sizeof(key_bits) },
        { .id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = (void *)&can_unwrap, .len = sizeof(can_unwrap) },
    };

    struct azihsm_key_prop pub_key_props[] = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = (void *)&pub_class, .len = sizeof(pub_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&key_bits, .len = sizeof(key_bits) },
        { .id = AZIHSM_KEY_PROP_ID_WRAP, .val = (void *)&can_wrap, .len = sizeof(can_wrap) },
    };

    struct azihsm_key_prop_list priv_key_prop_list = {
        .props = priv_key_props,
        .count = sizeof(priv_key_props) / sizeof(priv_key_props[0]),
    };

    struct azihsm_key_prop_list pub_key_prop_list = {
        .props = pub_key_props,
        .count = sizeof(pub_key_props) / sizeof(pub_key_props[0]),
    };

    /* Generate RSA unwrapping key pair */
    status = azihsm_key_gen_pair(
        session,
        &algo,
        &priv_key_prop_list,
        &pub_key_prop_list,
        &priv_key,
        &pub_key
    );
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return status;
    }

    status = extract_and_save_masked_key(priv_key, muk_path);

    azihsm_key_delete(priv_key);
    azihsm_key_delete(pub_key);
    return status;
}

azihsm_status azihsm_get_unwrapping_key(
    AZIHSM_OSSL_PROV_CTX *provctx,
    azihsm_handle *out_pub,
    azihsm_handle *out_priv
)
{
    azihsm_status status;

    if (provctx == NULL || out_pub == NULL || out_priv == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_PASSED_NULL_PARAMETER,
            "azihsm_get_unwrapping_key: NULL argument"
        );
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    /* Fast path: return cached handles if available */
    if (!CRYPTO_THREAD_read_lock(provctx->unwrapping_key.lock))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "failed to acquire read lock for unwrapping key"
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (provctx->unwrapping_key.priv != 0)
    {
        *out_pub = provctx->unwrapping_key.pub;
        *out_priv = provctx->unwrapping_key.priv;
        CRYPTO_THREAD_unlock(provctx->unwrapping_key.lock);
        return AZIHSM_STATUS_SUCCESS;
    }

    CRYPTO_THREAD_unlock(provctx->unwrapping_key.lock);

    /* Slow path: acquire lock and check again */
    if (!CRYPTO_THREAD_write_lock(provctx->unwrapping_key.lock))
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "failed to acquire write lock for unwrapping key"
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (provctx->unwrapping_key.priv != 0)
    {
        /* Another thread initialized while we waited */
        *out_pub = provctx->unwrapping_key.pub;
        *out_priv = provctx->unwrapping_key.priv;
        CRYPTO_THREAD_unlock(provctx->unwrapping_key.lock);
        return AZIHSM_STATUS_SUCCESS;
    }

    /* Build property lists for RSA unwrapping key pair */
    const uint32_t key_bits = 2048;
    const azihsm_key_class priv_class = AZIHSM_KEY_CLASS_PRIVATE;
    const azihsm_key_class pub_class = AZIHSM_KEY_CLASS_PUBLIC;
    const azihsm_key_kind key_kind = AZIHSM_KEY_KIND_RSA;
    const bool can_unwrap = true;
    const bool can_wrap = true;

    struct azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN,
        .params = NULL,
        .len = 0,
    };

    struct azihsm_key_prop priv_key_props[] = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = (void *)&priv_class, .len = sizeof(priv_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&key_bits, .len = sizeof(key_bits) },
        { .id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = (void *)&can_unwrap, .len = sizeof(can_unwrap) },
    };

    struct azihsm_key_prop pub_key_props[] = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = (void *)&pub_class, .len = sizeof(pub_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&key_bits, .len = sizeof(key_bits) },
        { .id = AZIHSM_KEY_PROP_ID_WRAP, .val = (void *)&can_wrap, .len = sizeof(can_wrap) },
    };

    struct azihsm_key_prop_list priv_key_prop_list = {
        .props = priv_key_props,
        .count = sizeof(priv_key_props) / sizeof(priv_key_props[0]),
    };

    struct azihsm_key_prop_list pub_key_prop_list = {
        .props = pub_key_props,
        .count = sizeof(pub_key_props) / sizeof(pub_key_props[0]),
    };

    azihsm_handle pub = 0;
    azihsm_handle priv = 0;

    status = azihsm_key_gen_pair(
        provctx->session,
        &algo,
        &priv_key_prop_list,
        &pub_key_prop_list,
        &priv,
        &pub
    );
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        CRYPTO_THREAD_unlock(provctx->unwrapping_key.lock);
        return status;
    }

    /* Cache the handles for future use */
    provctx->unwrapping_key.pub = pub;
    provctx->unwrapping_key.priv = priv;
    *out_pub = pub;
    *out_priv = priv;

    CRYPTO_THREAD_unlock(provctx->unwrapping_key.lock);
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Converts a DER-encoded SubjectPublicKeyInfo EC public key into its
 * uncompressed point representation (0x04 || x || y).
 *
 * The output buffer must be at least P384_UNCOMPRESSED_POINT_SIZE bytes.
 */
static azihsm_status der_to_uncompressed_point(
    const struct azihsm_buffer *pub_key_der,
    unsigned char point[P384_UNCOMPRESSED_POINT_SIZE]
)
{
    azihsm_status status = AZIHSM_STATUS_INTERNAL_ERROR;
    const unsigned char *der_ptr = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *qx = NULL;
    BIGNUM *qy = NULL;

    if (pub_key_der == NULL || pub_key_der->ptr == NULL)
    {
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    der_ptr = pub_key_der->ptr;
    pkey = d2i_PUBKEY(NULL, &der_ptr, (long)pub_key_der->len);
    if (pkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &qx) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &qy))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    point[0] = 0x04;
    if (BN_bn2binpad(qx, point + 1, P384_COORD_SIZE) != P384_COORD_SIZE ||
        BN_bn2binpad(qy, point + 1 + P384_COORD_SIZE, P384_COORD_SIZE) != P384_COORD_SIZE)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "BN_bn2binpad failed serializing P-384 coordinate"
        );
        goto cleanup;
    }

    status = AZIHSM_STATUS_SUCCESS;

cleanup:
    /* OpenSSL free functions are NULL-safe — call unconditionally */
    BN_free(qx);
    BN_free(qy);
    EVP_PKEY_free(pkey);
    return status;
}

/*
 * Signs data with a POTA private key using ECDSA-SHA384 and returns
 * the signature in raw r||s format (96 bytes for P-384).
 *
 * The caller must free sig_out->ptr with OPENSSL_cleanse + OPENSSL_free.
 */
static azihsm_status sign_with_pota_key(
    const uint8_t *priv_key_der,
    size_t priv_key_der_len,
    const unsigned char *data,
    size_t data_len,
    struct azihsm_buffer *sig_out
)
{
    azihsm_status status = AZIHSM_STATUS_INTERNAL_ERROR;
    const unsigned char *der_ptr = priv_key_der;
    OSSL_LIB_CTX *pota_libctx = NULL;
    OSSL_PROVIDER *pota_default = NULL;
    EVP_PKEY *pota_pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *der_sig_buf = NULL;
    size_t der_sig_len = 0;
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;

    sig_out->ptr = NULL;
    sig_out->len = 0;

    /* The POTA key is a software EC key.  Run its decode + sign in a private
     * library context that has only the default provider, so the operation
     * can never be routed to the azihsm provider (which the application also
     * loads in the default libctx, and whose keymgmt carries no private
     * component — causing intermittent "not a private key" failures). */
    pota_libctx = OSSL_LIB_CTX_new();
    if (pota_libctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
    pota_default = OSSL_PROVIDER_load(pota_libctx, "default");
    if (pota_default == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    /* Decode the POTA private key from its DER representation */
    pota_pkey = d2i_AutoPrivateKey_ex(NULL, &der_ptr, (long)priv_key_der_len, pota_libctx, NULL);
    if (pota_pkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (EVP_DigestSignInit_ex(md_ctx, NULL, "SHA384", pota_libctx, NULL, pota_pkey, NULL) != 1)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    /* Determine required DER signature buffer size */
    if (EVP_DigestSign(md_ctx, NULL, &der_sig_len, data, data_len) != 1)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    der_sig_buf = OPENSSL_malloc(der_sig_len);
    if (der_sig_buf == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (EVP_DigestSign(md_ctx, der_sig_buf, &der_sig_len, data, data_len) != 1)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    /* Convert DER-encoded ECDSA signature to raw r||s format */
    der_ptr = der_sig_buf;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &der_ptr, (long)der_sig_len);
    if (ecdsa_sig == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto cleanup;
    }

    ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);

    if (sig_r == NULL || sig_s == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "ECDSA_SIG_get0 returned NULL r or s component"
        );
        goto cleanup;
    }

    /* Serialize r and s components into a fixed-size raw buffer */
    sig_out->ptr = OPENSSL_zalloc(P384_RAW_SIG_SIZE);
    if (sig_out->ptr == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }

    if (BN_bn2binpad(sig_r, sig_out->ptr, P384_COORD_SIZE) != P384_COORD_SIZE ||
        BN_bn2binpad(sig_s, sig_out->ptr + P384_COORD_SIZE, P384_COORD_SIZE) != P384_COORD_SIZE)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "BN_bn2binpad failed serializing ECDSA r or s component"
        );
        OPENSSL_cleanse(sig_out->ptr, P384_RAW_SIG_SIZE);
        OPENSSL_free(sig_out->ptr);
        sig_out->ptr = NULL;
        goto cleanup;
    }

    sig_out->len = P384_RAW_SIG_SIZE;
    status = AZIHSM_STATUS_SUCCESS;

cleanup:
    /* OpenSSL free functions are NULL-safe — call unconditionally */
    ECDSA_SIG_free(ecdsa_sig);
    OPENSSL_clear_free(der_sig_buf, der_sig_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pota_pkey);
    /* OSSL_PROVIDER_unload is not NULL-safe; OSSL_LIB_CTX_free is. */
    if (pota_default != NULL)
    {
        OSSL_PROVIDER_unload(pota_default);
    }
    OSSL_LIB_CTX_free(pota_libctx);
    return status;
}

/*
 * Computes POTA endorsement for partition initialization.
 *
 * Converts the PID public key from DER to uncompressed EC point format,
 * and signs it with the provided POTA private key using ECDSA-SHA384. The
 * signature is returned in raw r||s format.
 *
 * On success, caller must free sig_out->ptr with OPENSSL_cleanse + OPENSSL_free.
 */
azihsm_status compute_pota_endorsement(
    const struct azihsm_buffer *pid_pub_key_der,
    const struct azihsm_buffer *priv_key_buf,
    struct azihsm_buffer *sig_out
)
{
    azihsm_status status;
    unsigned char uncompressed_point[P384_UNCOMPRESSED_POINT_SIZE];

    sig_out->ptr = NULL;
    sig_out->len = 0;

    status = der_to_uncompressed_point(pid_pub_key_der, uncompressed_point);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    status = sign_with_pota_key(
        priv_key_buf->ptr,
        priv_key_buf->len,
        uncompressed_point,
        sizeof(uncompressed_point),
        sig_out
    );

cleanup:
    return status;
}

azihsm_status azihsm_open_device_and_session(
    const AZIHSM_CONFIG *config,
    azihsm_handle *device,
    azihsm_handle *session,
    struct azihsm_resiliency_ctx **resiliency_ctx
)
{
    azihsm_status status = AZIHSM_STATUS_INTERNAL_ERROR;

    struct azihsm_buffer bmk_buf = { NULL, 0 };
    struct azihsm_buffer muk_buf = { NULL, 0 };
    struct azihsm_buffer obk_buf = { NULL, 0 };
    struct azihsm_buffer mobk_buf = { NULL, 0 };
    struct azihsm_buffer retrieved_bmk = { NULL, 0 };
    struct azihsm_buffer retrieved_mobk = { NULL, 0 };
    struct azihsm_buffer pota_priv_buf = { NULL, 0 };
    struct azihsm_buffer pota_pub_buf = { NULL, 0 };
    struct azihsm_buffer pota_sig_buf = { NULL, 0 };
    struct azihsm_buffer pid_pub_key_buf = { NULL, 0 };

    struct azihsm_resiliency_config resiliency_cfg;
    struct azihsm_resiliency_ctx *res_ctx = NULL;

    bool device_opened = false;
    bool session_opened = false;
    bool muk_was_loaded = false;

    struct azihsm_api_rev api_rev = { 0 };
    struct azihsm_credentials creds = { 0 };
    struct azihsm_owner_backup_key_config backup_config = { 0 };
    struct azihsm_pota_endorsement pota_endorsement = { 0 };
    struct azihsm_pota_endorsement_data pota_data = { 0 };

    if (config == NULL || device == NULL || session == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_PASSED_NULL_PARAMETER,
            "azihsm_open_device_and_session: NULL argument"
        );
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    /* Use API revision from configuration */
    api_rev.major = config->api_revision_major;
    api_rev.minor = config->api_revision_minor;

    /* Load credentials: prefer hex env var, fall back to default file in CWD.
     * ID and PIN are resolved independently by parse_provider_config(). */
    if (config->credentials_id_from_env)
    {
        memcpy(creds.id, config->credentials_id, AZIHSM_CREDENTIALS_SIZE);
    }
    else
    {
        status = load_credentials_from_file(AZIHSM_DEFAULT_CREDENTIALS_ID_PATH, creds.id);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    if (config->credentials_pin_from_env)
    {
        memcpy(creds.pin, config->credentials_pin, AZIHSM_CREDENTIALS_SIZE);
    }
    else
    {
        status = load_credentials_from_file(AZIHSM_DEFAULT_CREDENTIALS_PIN_PATH, creds.pin);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    // Load key files if they exist
    status = azihsm_file_load(config->bmk_path, &bmk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    status = azihsm_file_load(config->muk_path, &muk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }
    muk_was_loaded = (muk_buf.ptr != NULL);

    // Configure OBK based on source selection.
    //
    // Caller-source strategy: always attempt init with the raw OBK first.
    // - On a cold device (post power cycle) the device's one-shot `init_bk3`
    //   succeeds, derives a fresh MOBK, and any stale cached MOBK on disk is
    //   harmlessly overwritten after init.
    // - On a warm device (NSSR/process restart) the device rejects the OBK
    //   with BK3_ALREADY_INITIALIZED; we then retry with the cached MOBK
    //   from `mobk_path`. If the cache is missing in this case, the user
    //   has lost the MOBK without resetting the device — fail cleanly.
    //
    // TPM source: the SDK derives MOBK from the TPM on every init, so no
    // file-based MOBK caching is needed here.
    if (config->use_tpm_obk)
    {
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM;
        backup_config.owner_backup_key = NULL;
    }
    else
    {
        // Load the OBK from file. The OBK is the raw owner backup key for
        // init_bk3, NOT the masked owner backup key (MOBK) returned by the HSM.
        status = azihsm_file_load(config->obk_path, &obk_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        if (obk_buf.ptr == NULL)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "OBK file not found at '%s'. "
                "The OBK must be a %d-byte random binary file. "
                "Generate one with: openssl rand -out '%s' %d "
                "(or set azihsm-obk-source=tpm to retrieve it from the TPM).",
                config->obk_path,
                AZIHSM_OBK_SIZE,
                config->obk_path,
                AZIHSM_OBK_SIZE
            );
            status = AZIHSM_STATUS_INTERNAL_ERROR;
            goto cleanup;
        }

        if (obk_buf.len != AZIHSM_OBK_SIZE)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "OBK file '%s' has wrong size: got %u bytes, expected %d. "
                "Regenerate with: openssl rand -out '%s' %d",
                config->obk_path,
                obk_buf.len,
                AZIHSM_OBK_SIZE,
                config->obk_path,
                AZIHSM_OBK_SIZE
            );
            status = AZIHSM_STATUS_INTERNAL_ERROR;
            goto cleanup;
        }

        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = &obk_buf;
    }

    status = azihsm_get_device_handle(device, api_rev);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }
    device_opened = true;

    /* Create resiliency config if enabled */
    if (config->resiliency_enabled)
    {
        memset(&resiliency_cfg, 0, sizeof(resiliency_cfg));
        status = azihsm_resiliency_create(
            config->resiliency_storage_dir,
            config->pota_private_key_path,
            config->pota_public_key_path,
            config->use_tpm_pota,
            config->obk_path,
            config->use_tpm_obk,
            &resiliency_cfg,
            &res_ctx
        );
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    // Configure POTA endorsement based on source selection
    if (config->use_tpm_pota)
    {
        pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM;
        pota_endorsement.endorsement = NULL;
    }
    else
    {
        // Load POTA keys from files
        status = azihsm_file_load(config->pota_private_key_path, &pota_priv_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        status = azihsm_file_load(config->pota_public_key_path, &pota_pub_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        // POTA key files are required when using caller source — both must be present.
        if (pota_priv_buf.ptr == NULL && pota_pub_buf.ptr == NULL)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "POTA key files not found (private: '%s', public: '%s'). "
                "Provide a P-384 key pair: private key as legacy EC DER (ECPrivateKey/RFC 5915), "
                "public key as SubjectPublicKeyInfo DER "
                "(or set azihsm-pota-source=tpm).",
                config->pota_private_key_path,
                config->pota_public_key_path
            );
            status = AZIHSM_STATUS_INTERNAL_ERROR;
            goto cleanup;
        }
        else if (pota_priv_buf.ptr == NULL || pota_pub_buf.ptr == NULL)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "exactly one POTA key file is present — both are required. "
                "Private key (legacy EC DER / ECPrivateKey): '%s'. "
                "Public key (SubjectPublicKeyInfo DER): '%s'. "
                "Regenerate the pair: openssl ecparam -name P-384 -genkey "
                "| openssl ec -outform DER -out <priv-path>.",
                config->pota_private_key_path,
                config->pota_public_key_path
            );
            status = AZIHSM_STATUS_INTERNAL_ERROR;
            goto cleanup;
        }

        // Compute POTA endorsement: sign PID public key with POTA key
        status = get_part_property(*device, AZIHSM_PART_PROP_ID_PART_PUB_KEY, &pid_pub_key_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        status = compute_pota_endorsement(&pid_pub_key_buf, &pota_priv_buf, &pota_sig_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        pota_data.signature = &pota_sig_buf;
        pota_data.public_key = &pota_pub_buf;
        pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER;
        pota_endorsement.endorsement = &pota_data;
    }

    // Initialize partition with loaded keys (or NULL if not available).
    status = azihsm_part_init(
        *device,
        &creds,
        bmk_buf.ptr != NULL ? &bmk_buf : NULL,
        muk_buf.ptr != NULL ? &muk_buf : NULL,
        &backup_config,
        &pota_endorsement,
        config->resiliency_enabled ? &resiliency_cfg : NULL
    );

    // Caller-source warm-device path: the device's `init_bk3` is one-shot
    // per power cycle, so a re-init on the same device rejects the raw OBK
    // with BK3_ALREADY_INITIALIZED. Recover by re-trying with the cached
    // MOBK from `mobk_path`.
    if (status == AZIHSM_STATUS_BK3_ALREADY_INITIALIZED && !config->use_tpm_obk)
    {
        status = azihsm_file_load(config->mobk_path, &mobk_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }

        if (mobk_buf.ptr == NULL)
        {
            // Device reports BK3 initialized but we have no cached MOBK to
            // re-init with. This is a caller-side state-management failure:
            // either the MOBK file was deleted/lost without resetting the
            // device, or this process is running against a device previously
            // initialized by a different caller.
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "Cached MOBK file '%s' not found but device reports BK3 "
                "already initialized. The cached MOBK was lost without "
                "resetting the device. Recover by either restoring the "
                "cached MOBK file or power-cycling/resetting the device.",
                config->mobk_path
            );
            status = AZIHSM_STATUS_INTERNAL_ERROR;
            goto cleanup;
        }

        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = NULL;
        backup_config.masked_owner_backup_key = &mobk_buf;

        status = azihsm_part_init(
            *device,
            &creds,
            bmk_buf.ptr != NULL ? &bmk_buf : NULL,
            muk_buf.ptr != NULL ? &muk_buf : NULL,
            &backup_config,
            &pota_endorsement,
            config->resiliency_enabled ? &resiliency_cfg : NULL
        );
    }

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    // Retrieve and persist BMK property
    status = get_part_property(*device, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY, &retrieved_bmk);
    if (status == AZIHSM_STATUS_SUCCESS && retrieved_bmk.ptr != NULL)
    {
        status = write_buffer_to_file(config->bmk_path, &retrieved_bmk);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    // Persist the device's current MOBK to `mobk_path`.
    // TPM source re-derives MOBK on every init.
    if (!config->use_tpm_obk)
    {
        status = get_part_property(
            *device,
            AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY,
            &retrieved_mobk
        );

        if ((status != AZIHSM_STATUS_SUCCESS) || (retrieved_mobk.ptr == NULL))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "failed to retrieve MOBK from device after init "
                "(status=%d). MOBK persistence is required for re-init "
                "after warm reset.",
                status
            );
            status = (status == AZIHSM_STATUS_SUCCESS) ? AZIHSM_STATUS_INTERNAL_ERROR : status;
            goto cleanup;
        }

        status = write_buffer_to_file(config->mobk_path, &retrieved_mobk);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    // Open session (seed=NULL lets the library generate random bytes internally)
    status = azihsm_sess_open(*device, &creds, NULL, session);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }
    session_opened = true;

    // If MUK wasn't loaded from file, generate and save it
    if (!muk_was_loaded)
    {
        status = generate_and_save_muk(*session, config->muk_path);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            goto cleanup;
        }
    }

    status = AZIHSM_STATUS_SUCCESS;

cleanup:
    /* Always free temporary buffers — needed on both success and error.
     * free_buffer() is NULL-safe (checks ptr before cleanse+free). */
    free_buffer(&bmk_buf);
    free_buffer(&muk_buf);
    free_buffer(&obk_buf);
    free_buffer(&mobk_buf);
    free_buffer(&pota_priv_buf);
    free_buffer(&pota_pub_buf);
    free_buffer(&pota_sig_buf);
    free_buffer(&pid_pub_key_buf);
    free_buffer(&retrieved_bmk);
    free_buffer(&retrieved_mobk);
    OPENSSL_cleanse(&creds, sizeof(creds));

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        /* Tear down device/session/resiliency only on failure.
         * Zero handles after closing to prevent stale handle usage by caller. */
        azihsm_resiliency_destroy(res_ctx);
        if (session_opened)
        {
            azihsm_sess_close(*session);
            *session = 0;
        }
        if (device_opened)
        {
            azihsm_part_close(*device);
            *device = 0;
        }
    }
    else
    {
        /* Pass resiliency context to caller for lifetime management */
        if (resiliency_ctx != NULL)
        {
            *resiliency_ctx = res_ctx;
        }
        else
        {
            azihsm_resiliency_destroy(res_ctx);
        }
    }
    return status;
}

void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session)
{
    if (session != 0)
    {
        azihsm_sess_close(session);
    }
    if (device != 0)
    {
        azihsm_part_close(device);
    }
}

/* The context this thread is currently opening a session for, so a libcrypto
 * fetch the open triggers re-enters that same context and fails fast instead of
 * recursing into its non-recursive lock.  Other contexts are unaffected. */
static __thread AZIHSM_OSSL_PROV_CTX *azihsm_opening_ctx = NULL;

azihsm_status azihsm_ensure_session(AZIHSM_OSSL_PROV_CTX *provctx)
{
    azihsm_status status;

    if (provctx == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    /* Re-entrant call on the context being opened: must not touch its lock. */
    if (azihsm_opening_ctx == provctx)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INTERNAL_ERROR,
            "azihsm_ensure_session: re-entrant call during HSM session open"
        );
        return AZIHSM_STATUS_INVALID_CONTEXT_STATE;
    }

    /* Fast path: session already open. */
    if (!CRYPTO_THREAD_read_lock(provctx->session_lock))
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "failed to acquire session lock");
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    if (provctx->session != 0)
    {
        CRYPTO_THREAD_unlock(provctx->session_lock);
        return AZIHSM_STATUS_SUCCESS;
    }
    CRYPTO_THREAD_unlock(provctx->session_lock);

    if (!CRYPTO_THREAD_write_lock(provctx->session_lock))
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "failed to acquire session lock");
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    /* Another thread opened the session while we waited for the lock. */
    if (provctx->session != 0)
    {
        CRYPTO_THREAD_unlock(provctx->session_lock);
        return AZIHSM_STATUS_SUCCESS;
    }

    AZIHSM_OSSL_PROV_CTX *prev_opening = azihsm_opening_ctx;
    azihsm_opening_ctx = provctx;

    /* Prime the default libctx's DRBG: the SDK open below draws randomness
     * via bare RAND_bytes, whose lazy DRBG instantiation otherwise fails
     * deep in the open on some hosts (e.g. nginx's config thread). */
    unsigned char primer[1];
    if (RAND_bytes(primer, sizeof(primer)) != 1)
    {
        azihsm_opening_ctx = prev_opening;
        CRYPTO_THREAD_unlock(provctx->session_lock);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    OPENSSL_cleanse(primer, sizeof(primer));

    status = azihsm_open_device_and_session(
        &provctx->config,
        &provctx->device,
        &provctx->session,
        &provctx->resiliency_ctx
    );
    azihsm_opening_ctx = prev_opening;

    CRYPTO_THREAD_unlock(provctx->session_lock);

    return status;
}

/*
 * Wrap a PKCS#8 DER buffer with the HSM's RSA-AES wrapping key, then unwrap
 * into the HSM to produce key handles.
 */
static azihsm_status wrap_and_unwrap_pkcs8(
    azihsm_handle wrapping_pub,
    azihsm_handle wrapping_priv,
    uint8_t *pkcs8_buf,
    int pkcs8_len,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
)
{
    azihsm_status status;
    uint8_t *wrapped_data = NULL;
    uint32_t wrapped_size = 0;

    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = {
        .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
        .mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256,
        .label = NULL,
    };

    struct azihsm_algo_rsa_aes_wrap_params wrap_params = {
        .oaep_params = &oaep_params,
        .aes_key_bits = 256,
    };

    struct azihsm_algo wrap_algo = {
        .id = AZIHSM_ALGO_ID_RSA_AES_WRAP,
        .params = &wrap_params,
        .len = sizeof(wrap_params),
    };

    struct azihsm_buffer plain_buf = {
        .ptr = pkcs8_buf,
        .len = (uint32_t)pkcs8_len,
    };

    struct azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {
        .aes_key_bits = 256,
        .oaep_params = &oaep_params,
    };

    struct azihsm_algo unwrap_algo = {
        .id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP,
        .params = &unwrap_params,
        .len = sizeof(unwrap_params),
    };

    /* Two-call pattern: first query required size */
    struct azihsm_buffer wrapped_buf = {
        .ptr = NULL,
        .len = 0,
    };

    status = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub, &plain_buf, &wrapped_buf);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || wrapped_buf.len == 0)
    {
        status = (status == AZIHSM_STATUS_SUCCESS) ? AZIHSM_STATUS_INTERNAL_ERROR : status;
        goto cleanup;
    }

    /* Allocate buffer for wrapped data */
    wrapped_size = wrapped_buf.len;
    wrapped_data = OPENSSL_malloc(wrapped_size);
    if (wrapped_data == NULL)
    {
        status = AZIHSM_STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    /* Second call: perform actual wrap */
    wrapped_buf.ptr = wrapped_data;
    wrapped_buf.len = wrapped_size;

    status = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub, &plain_buf, &wrapped_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    /* Unwrap into the HSM */
    status = azihsm_key_unwrap_pair(
        &unwrap_algo,
        wrapping_priv,
        &wrapped_buf,
        priv_key_prop_list,
        pub_key_prop_list,
        out_priv,
        out_pub
    );

cleanup:
    OPENSSL_clear_free(wrapped_data, wrapped_size);
    return status;
}

azihsm_status azihsm_import_key_pair(
    AZIHSM_OSSL_PROV_CTX *provctx,
    const char *input_key_file,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
)
{
    azihsm_status status;
    azihsm_handle wrapping_pub = 0, wrapping_priv = 0;
    struct azihsm_buffer input_buf = { NULL, 0 };
    uint8_t *pkcs8_buf = NULL;
    int pkcs8_len = 0;

    if (provctx == NULL || input_key_file == NULL || priv_key_prop_list == NULL ||
        pub_key_prop_list == NULL || out_priv == NULL || out_pub == NULL)
    {
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    /* 1. Read the input file from disk */
    status = azihsm_file_load(input_key_file, &input_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    if (input_buf.ptr == NULL || input_buf.len == 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_MISSING_KEY,
            "input key file '%s' is missing or empty",
            input_key_file
        );
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    /* 2. Get the RSA unwrapping key pair from the HSM */
    status = azihsm_get_unwrapping_key(provctx, &wrapping_pub, &wrapping_priv);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    /* 3. Try to normalize as DER-encoded private key (SEC1, PKCS#1, or PKCS#8) */
    if (azihsm_ossl_normalize_der_to_pkcs8(
            input_buf.ptr,
            (long)input_buf.len,
            &pkcs8_buf,
            &pkcs8_len
        ) != OSSL_SUCCESS)
    {
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    /* Plaintext DER path: wrap then unwrap into HSM */
    status = wrap_and_unwrap_pkcs8(
        wrapping_pub,
        wrapping_priv,
        pkcs8_buf,
        pkcs8_len,
        priv_key_prop_list,
        pub_key_prop_list,
        out_priv,
        out_pub
    );

cleanup:
    free_buffer(&input_buf);
    OPENSSL_clear_free(pkcs8_buf, (size_t)pkcs8_len);
    return status;
}

azihsm_status azihsm_unwrap_key_pair(
    AZIHSM_OSSL_PROV_CTX *provctx,
    const char *wrapped_key_file,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
)
{
    azihsm_status status;
    azihsm_handle wrapping_pub = 0, wrapping_priv = 0;
    struct azihsm_buffer input_buf = { NULL, 0 };

    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = {
        .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
        .mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256,
        .label = NULL,
    };

    struct azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {
        .aes_key_bits = 256,
        .oaep_params = &oaep_params,
    };

    struct azihsm_algo unwrap_algo = {
        .id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP,
        .params = &unwrap_params,
        .len = sizeof(unwrap_params),
    };

    if (provctx == NULL || wrapped_key_file == NULL || priv_key_prop_list == NULL ||
        pub_key_prop_list == NULL || out_priv == NULL || out_pub == NULL)
    {
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    /* 1. Read the wrapped blob from disk */
    status = azihsm_file_load(wrapped_key_file, &input_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    if (input_buf.ptr == NULL || input_buf.len == 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_MISSING_KEY,
            "wrapped key file '%s' is missing or empty",
            wrapped_key_file
        );
        status = AZIHSM_STATUS_INVALID_ARGUMENT;
        goto cleanup;
    }

    /* 2. Get the RSA unwrapping key pair from the HSM */
    status = azihsm_get_unwrapping_key(provctx, &wrapping_pub, &wrapping_priv);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        goto cleanup;
    }

    /* 3. Unwrap directly — the blob is already wrapped */
    status = azihsm_key_unwrap_pair(
        &unwrap_algo,
        wrapping_priv,
        &input_buf,
        priv_key_prop_list,
        pub_key_prop_list,
        out_priv,
        out_pub
    );

cleanup:
    free_buffer(&input_buf);
    return status;
}

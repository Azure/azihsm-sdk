// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_ossl_hsm.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define AZIHSM_MAX_KEY_FILE_SIZE (64 * 1024)
#define P384_COORD_SIZE 48
#define P384_RAW_SIG_SIZE 96
#define P384_UNCOMPRESSED_POINT_SIZE 97

/*
 * Loads a file into an azihsm_buffer structure.
 * Returns AZIHSM_STATUS_SUCCESS on success.
 * Returns AZIHSM_STATUS_INTERNAL_ERROR on error.
 */
static azihsm_status load_file_to_buffer(const char *path, struct azihsm_buffer *buffer)
{
    FILE *file = NULL;
    long file_size = 0;
    size_t bytes_read = 0;

    if (path == NULL || buffer == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->ptr = NULL;
    buffer->len = 0;

    file = fopen(path, "rb");
    if (file == NULL)
    {
        if (errno == ENOENT)
        {
            // File doesn't exist - not an error
            return AZIHSM_STATUS_SUCCESS;
        }
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    file_size = ftell(file);
    if (file_size < 0)
    {
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (file_size == 0)
    {
        fclose(file);
        return AZIHSM_STATUS_SUCCESS;
    }

    // Check for maximum file size and uint32_t overflow
    if (file_size > AZIHSM_MAX_KEY_FILE_SIZE || file_size > UINT32_MAX)
    {
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->ptr = OPENSSL_malloc((size_t)file_size);
    if (buffer->ptr == NULL)
    {
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    bytes_read = fread(buffer->ptr, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size)
    {
        OPENSSL_cleanse(buffer->ptr, (size_t)file_size);
        OPENSSL_free(buffer->ptr);
        buffer->ptr = NULL;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->len = (uint32_t)file_size;
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Writes buffer contents to a file.
 * Returns AZIHSM_STATUS_SUCCESS on success, AZIHSM_STATUS_INTERNAL_ERROR on error.
 */
static azihsm_status write_buffer_to_file(const char *path, const struct azihsm_buffer *buffer)
{
    int fd = -1;
    FILE *file = NULL;
    size_t bytes_written = 0;

    if (path == NULL || buffer == NULL || buffer->ptr == NULL || buffer->len == 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    file = fdopen(fd, "wb");
    if (file == NULL)
    {
        close(fd);
        unlink(path); // Remove the potentially created empty file
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    bytes_written = fwrite(buffer->ptr, 1, buffer->len, file);
    fclose(file); // Also closes fd

    return (bytes_written == buffer->len) ? AZIHSM_STATUS_SUCCESS : AZIHSM_STATUS_INTERNAL_ERROR;
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
 * picks and opens the first possible HSM device
 * */
static azihsm_status azihsm_get_device_handle(azihsm_handle *device)
{
    azihsm_status status;
    azihsm_handle device_list;
    uint32_t device_count = 0;

    status = azihsm_part_get_list(&device_list);
    if (status != 0)
    {
        return status;
    }

    status = azihsm_part_get_count(device_list, &device_count);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        azihsm_part_free_list(device_list);
        return status;
    }

    for (uint32_t i = 0; i < device_count; i++)
    {

        azihsm_char path[64] = { '\0' };
        struct azihsm_str dev_path = { path, sizeof(path) };

        status = azihsm_part_get_path(device_list, i, &dev_path);

        if (status != AZIHSM_STATUS_SUCCESS)
        {
            continue;
        }

        status = azihsm_part_open(&dev_path, device);

        if (status == AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_free_list(device_list);
            return AZIHSM_STATUS_SUCCESS;
        }
    }

    azihsm_part_free_list(device_list);
    return AZIHSM_STATUS_INTERNAL_ERROR;
}

// clang-format off

/* Fallback owner backup key when no MOBK file is available */
static const uint8_t DEFAULT_OBK[48] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
};

// clang-format on
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
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    /* Fast path: return cached handles if available */
    if (!CRYPTO_THREAD_read_lock(provctx->unwrapping_key.lock))
    {
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

/* Fixed POTA private key (DER-encoded PKCS#8 ECC P-384, 185 bytes).
 * Matches TEST_POTA_ECC_PRIVATE_KEY / TEST_POTA_PRIVATE_KEY in the Rust test suite. */
static const uint8_t POTA_PRIVATE_KEY_DER[185] = {
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30, 0x17, 0xe9, 0x1c, 0xac, 0xf7, 0xb7, 0x21, 0xd7, 0x75, 0x20, 0x02, 0x07, 0xbc,
    0xaa, 0x94, 0x2c, 0xe3, 0xb5, 0x5b, 0x78, 0x13, 0xcc, 0x8b, 0xde, 0x87, 0x65, 0x6b, 0xe1, 0x7b,
    0xc2, 0xa8, 0xcc, 0x89, 0x33, 0x4e, 0xcd, 0xaa, 0x9d, 0x1d, 0x09, 0xf1, 0xc7, 0x01, 0x1b, 0x64,
    0xeb, 0x78, 0x5b, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67,
    0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20,
    0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90,
    0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99,
    0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a,
    0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02,
    0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98
};

/* Fixed POTA public key (DER-encoded SubjectPublicKeyInfo ECC P-384, 120 bytes).
 * Corresponds to POTA_PRIVATE_KEY_DER above.
 * Matches TEST_POTA_ECC_PUB_KEY / TEST_POTA_PUBLIC_KEY_DER in the Rust test suite. */
static const uint8_t POTA_PUBLIC_KEY_DER[120] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
    0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0,
    0x67, 0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0,
    0xa9, 0x20, 0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9,
    0x5f, 0xe5, 0x90, 0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10,
    0xd3, 0x17, 0x6e, 0x99, 0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3,
    0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64,
    0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98
};

/*
 * Retrieves the partition's PID public key and builds its uncompressed EC point.
 *
 * Fetches the PID public key via AZIHSM_PART_PROP_ID_PART_PUB_KEY (works before
 * part_init), parses the DER SubjectPublicKeyInfo, and writes the uncompressed
 * point (0x04 || x || y) into the caller-provided buffer.
 *
 * All OpenSSL calls use NULL libctx (default provider), which is safe during
 * provider init since our provider is not yet registered.
 */
static azihsm_status get_pid_uncompressed_point(
    azihsm_handle device,
    unsigned char point[P384_UNCOMPRESSED_POINT_SIZE]
)
{
    azihsm_status status;
    struct azihsm_buffer pid_pub_key_der = { NULL, 0 };
    const unsigned char *der_ptr = NULL;
    EVP_PKEY *pid_pkey = NULL;
    BIGNUM *qx = NULL;
    BIGNUM *qy = NULL;

    status = get_part_property(device, AZIHSM_PART_PROP_ID_PART_PUB_KEY, &pid_pub_key_der);
    if (status != AZIHSM_STATUS_SUCCESS || pid_pub_key_der.ptr == NULL)
    {
        return status != AZIHSM_STATUS_SUCCESS ? status : AZIHSM_STATUS_INTERNAL_ERROR;
    }

    der_ptr = pid_pub_key_der.ptr;
    pid_pkey = d2i_PUBKEY(NULL, &der_ptr, (long)pid_pub_key_der.len);
    free_buffer(&pid_pub_key_der);

    if (pid_pkey == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    qx = NULL;
    qy = NULL;

    if (!EVP_PKEY_get_bn_param(pid_pkey, OSSL_PKEY_PARAM_EC_PUB_X, &qx) ||
        !EVP_PKEY_get_bn_param(pid_pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &qy))
    {
        BN_free(qx);
        BN_free(qy);
        EVP_PKEY_free(pid_pkey);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    EVP_PKEY_free(pid_pkey);

    point[0] = 0x04;
    if (BN_bn2binpad(qx, point + 1, P384_COORD_SIZE) != P384_COORD_SIZE ||
        BN_bn2binpad(qy, point + 1 + P384_COORD_SIZE, P384_COORD_SIZE) != P384_COORD_SIZE)
    {
        BN_free(qx);
        BN_free(qy);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    BN_free(qx);
    BN_free(qy);
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Signs data with the fixed POTA private key using ECDSA-SHA384 and returns
 * the signature in raw r||s format (96 bytes for P-384).
 *
 * The caller must free sig_out->ptr with OPENSSL_cleanse + OPENSSL_free.
 */
static azihsm_status sign_with_pota_key(
    const unsigned char *data,
    size_t data_len,
    struct azihsm_buffer *sig_out
)
{
    const unsigned char *der_ptr = POTA_PRIVATE_KEY_DER;
    EVP_PKEY *pota_pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *der_sig_buf = NULL;
    size_t der_sig_len = 0;
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;

    sig_out->ptr = NULL;
    sig_out->len = 0;

    pota_pkey = d2i_AutoPrivateKey(NULL, &der_ptr, (long)sizeof(POTA_PRIVATE_KEY_DER));
    if (pota_pkey == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
    {
        EVP_PKEY_free(pota_pkey);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha384(), NULL, pota_pkey) != 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pota_pkey);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (EVP_DigestSign(md_ctx, NULL, &der_sig_len, data, data_len) != 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pota_pkey);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    der_sig_buf = OPENSSL_malloc(der_sig_len);
    if (der_sig_buf == NULL)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pota_pkey);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (EVP_DigestSign(md_ctx, der_sig_buf, &der_sig_len, data, data_len) != 1)
    {
        OPENSSL_cleanse(der_sig_buf, der_sig_len);
        OPENSSL_free(der_sig_buf);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pota_pkey);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pota_pkey);

    /* Convert DER-encoded ECDSA signature to raw r||s format */
    der_ptr = der_sig_buf;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &der_ptr, (long)der_sig_len);
    OPENSSL_cleanse(der_sig_buf, der_sig_len);
    OPENSSL_free(der_sig_buf);

    if (ecdsa_sig == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);

    if (sig_r == NULL || sig_s == NULL)
    {
        ECDSA_SIG_free(ecdsa_sig);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    sig_out->ptr = OPENSSL_zalloc(P384_RAW_SIG_SIZE);
    if (sig_out->ptr == NULL)
    {
        ECDSA_SIG_free(ecdsa_sig);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (BN_bn2binpad(sig_r, sig_out->ptr, P384_COORD_SIZE) != P384_COORD_SIZE ||
        BN_bn2binpad(sig_s, sig_out->ptr + P384_COORD_SIZE, P384_COORD_SIZE) != P384_COORD_SIZE)
    {
        OPENSSL_cleanse(sig_out->ptr, P384_RAW_SIG_SIZE);
        OPENSSL_free(sig_out->ptr);
        sig_out->ptr = NULL;
        ECDSA_SIG_free(ecdsa_sig);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    sig_out->len = P384_RAW_SIG_SIZE;
    ECDSA_SIG_free(ecdsa_sig);
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Computes POTA endorsement for partition initialization.
 *
 * Retrieves the partition's PID public key, builds its uncompressed EC point,
 * and signs it with the fixed POTA private key using ECDSA-SHA384. The signature
 * is returned in raw r||s format and the public key points to static data.
 *
 * On success, caller must free sig_out->ptr with OPENSSL_cleanse + OPENSSL_free.
 * pubkey_out points to static POTA_PUBLIC_KEY_DER and must NOT be freed.
 */
static azihsm_status compute_pota_endorsement(
    azihsm_handle device,
    struct azihsm_buffer *sig_out,
    struct azihsm_buffer *pubkey_out
)
{
    azihsm_status status;
    unsigned char uncompressed_point[P384_UNCOMPRESSED_POINT_SIZE];

    sig_out->ptr = NULL;
    sig_out->len = 0;
    pubkey_out->ptr = NULL;
    pubkey_out->len = 0;

    status = get_pid_uncompressed_point(device, uncompressed_point);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    status = sign_with_pota_key(uncompressed_point, sizeof(uncompressed_point), sig_out);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    pubkey_out->ptr = (uint8_t *)POTA_PUBLIC_KEY_DER;
    pubkey_out->len = sizeof(POTA_PUBLIC_KEY_DER);

    return AZIHSM_STATUS_SUCCESS;
}

azihsm_status azihsm_open_device_and_session(
    const AZIHSM_CONFIG *config,
    azihsm_handle *device,
    azihsm_handle *session
)
{
    azihsm_status status;

    struct azihsm_buffer bmk_buf = { NULL, 0 };
    struct azihsm_buffer muk_buf = { NULL, 0 };
    struct azihsm_buffer obk_buf = { NULL, 0 };
    struct azihsm_buffer retrieved_bmk = { NULL, 0 };
    struct azihsm_buffer retrieved_mobk = { NULL, 0 };
    bool default_obk = false;
    bool muk_was_loaded = false;

    struct azihsm_api_rev api_rev = { .major = 1, .minor = 0 };

    if (config == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // clang-format off

    struct azihsm_credentials creds = {
        .id =
        {
            0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A,
            0x3F, 0x76
        },
        .pin =
        {
            0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0,
            0x48, 0x00
        }
    };

    // clang-format on

    // Load key files if they exist
    status = load_file_to_buffer(config->bmk_path, &bmk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    status = load_file_to_buffer(config->muk_path, &muk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        free_buffer(&bmk_buf);
        return status;
    }
    muk_was_loaded = (muk_buf.ptr != NULL);

    // Load custom OBK from file if provided, otherwise use hardcoded default.
    // Note: the OBK is the raw owner backup key for init_bk3, NOT the masked
    // owner backup key (MOBK) returned by the HSM.
    status = load_file_to_buffer(config->obk_path, &obk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        return status;
    }

    // Use static default when no OBK file was provided.
    // default_obk tracks whether obk_buf points to static memory (must not be freed).
    if (obk_buf.ptr == NULL)
    {
        obk_buf.ptr = (uint8_t *)DEFAULT_OBK;
        obk_buf.len = sizeof(DEFAULT_OBK);
        default_obk = true;
    }

    status = azihsm_get_device_handle(device);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        if (!default_obk)
        {
            free_buffer(&obk_buf);
        }
        return status;
    }

    // Configure OBK and POTA
    struct azihsm_owner_backup_key_config backup_config = { 0 };
    struct azihsm_pota_endorsement pota_endorsement = { 0 };
    struct azihsm_buffer pota_sig_buf = { 0 };
    struct azihsm_buffer pota_pubkey_buf = { 0 };
    struct azihsm_pota_endorsement_data pota_data = { 0 };

    backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
    backup_config.owner_backup_key = &obk_buf;

    // Compute POTA endorsement: sign PID public key with fixed POTA key
    status = compute_pota_endorsement(*device, &pota_sig_buf, &pota_pubkey_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        if (!default_obk)
        {
            free_buffer(&obk_buf);
        }
        azihsm_part_close(*device);
        return status;
    }

    pota_data.signature = &pota_sig_buf;
    pota_data.public_key = &pota_pubkey_buf;
    pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER;
    pota_endorsement.endorsement = &pota_data;

    // Initialize partition with loaded keys (or NULL if not available)
    status = azihsm_part_init(
        *device,
        &creds,
        bmk_buf.ptr != NULL ? &bmk_buf : NULL,
        muk_buf.ptr != NULL ? &muk_buf : NULL,
        &backup_config,
        &pota_endorsement
    );

    // Input buffers no longer needed after part_init
    free_buffer(&bmk_buf);
    free_buffer(&muk_buf);
    free_buffer(&pota_sig_buf);
    // pota_pubkey_buf points to static POTA_PUBLIC_KEY_DER, do not free
    if (!default_obk)
    {
        free_buffer(&obk_buf);
    }

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        azihsm_part_close(*device);
        return status;
    }

    // Retrieve and persist BMK property
    status = get_part_property(*device, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY, &retrieved_bmk);
    if (status == AZIHSM_STATUS_SUCCESS && retrieved_bmk.ptr != NULL)
    {
        status = write_buffer_to_file(config->bmk_path, &retrieved_bmk);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            free_buffer(&retrieved_bmk);
            azihsm_part_close(*device);
            return status;
        }
    }
    free_buffer(&retrieved_bmk);

    // Open session (seed=NULL lets the library generate random bytes internally)
    status = azihsm_sess_open(*device, &api_rev, &creds, NULL, session);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        azihsm_part_close(*device);
        return status;
    }

    // If MUK wasn't loaded from file, generate and save it
    if (!muk_was_loaded)
    {
        status = generate_and_save_muk(*session, config->muk_path);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_sess_close(*session);
            azihsm_part_close(*device);
            return status;
        }
    }

    return AZIHSM_STATUS_SUCCESS;
}

void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session)
{

    azihsm_sess_close(session);
    azihsm_part_close(device);
}

// Copyright (C) Microsoft Corporation. All rights reserved.

// Standalone tool that wraps a DER-encoded EC private key using the HSM's
// RSA-AES key wrapping mechanism. The resulting blob can be loaded via the
// azihsm OpenSSL store provider:
//
//   azihsm://./wrapped.bin;type=ec
//
// Usage: wrap_key <input.der> <output.bin>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <azihsm.h>
#include <bsd/string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"

#define MAX_INPUT_SIZE (64 * 1024)
#define WRAPPED_BUF_SIZE 4096

static int read_file(const char *path, uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        fprintf(stderr, "error: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0 || (unsigned long)size > buf_size)
    {
        fprintf(stderr, "error: file '%s' too large (%ld bytes, max %u)\n", path, size, buf_size);
        fclose(f);
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return -1;
    }

    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);

    if (n != (size_t)size)
    {
        fprintf(stderr, "error: short read on '%s'\n", path);
        return -1;
    }

    *out_len = (uint32_t)size;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, uint32_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL)
    {
        fprintf(stderr, "error: cannot create '%s': %s\n", path, strerror(errno));
        return -1;
    }

    size_t n = fwrite(buf, 1, len, f);
    fclose(f);

    if (n != len)
    {
        fprintf(stderr, "error: short write on '%s'\n", path);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <input.der> <output.bin>\n", argv[0]);
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argv[2];

    // 1. Read the DER-encoded key
    uint8_t input_buf[MAX_INPUT_SIZE];
    uint32_t input_len = 0;

    if (read_file(input_path, input_buf, sizeof(input_buf), &input_len) != 0)
    {
        return 1;
    }

    // 2. Normalize to PKCS#8 format
    uint8_t *pkcs8_buf = NULL;
    int pkcs8_len = 0;

    if (azihsm_ossl_normalize_der_to_pkcs8(input_buf, (long)input_len, &pkcs8_buf, &pkcs8_len) !=
        OSSL_SUCCESS)
    {
        OPENSSL_cleanse(input_buf, input_len);
        fprintf(stderr, "error: failed to normalize DER key to PKCS#8\n");
        return 1;
    }

    OPENSSL_cleanse(input_buf, input_len);

    // 3. Configure HSM paths
    AZIHSM_CONFIG config;
    strlcpy(config.bmk_path, AZIHSM_DEFAULT_BMK_PATH, sizeof(config.bmk_path));
    strlcpy(config.muk_path, AZIHSM_DEFAULT_MUK_PATH, sizeof(config.muk_path));
    strlcpy(config.obk_path, AZIHSM_DEFAULT_OBK_PATH, sizeof(config.obk_path));

    // 4. Open device and session
    azihsm_handle device = 0;
    azihsm_handle session = 0;

    azihsm_status status = azihsm_open_device_and_session(&config, &device, &session);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        fprintf(stderr, "error: azihsm_open_device_and_session failed (0x%x)\n", status);
        OPENSSL_cleanse(pkcs8_buf, (size_t)pkcs8_len);
        OPENSSL_free(pkcs8_buf);
        return 1;
    }

    // 5. Build a minimal provider context for azihsm_get_unwrapping_key
    AZIHSM_OSSL_PROV_CTX provctx;
    memset(&provctx, 0, sizeof(provctx));
    provctx.device = device;
    provctx.session = session;
    provctx.config = config;
    provctx.unwrapping_key.lock = CRYPTO_THREAD_lock_new();
    if (provctx.unwrapping_key.lock == NULL)
    {
        fprintf(stderr, "error: failed to create lock\n");
        OPENSSL_cleanse(pkcs8_buf, (size_t)pkcs8_len);
        OPENSSL_free(pkcs8_buf);
        azihsm_close_device_and_session(device, session);
        return 1;
    }

    // 6. Get the RSA wrapping key pair
    azihsm_handle wrap_pub = 0;
    azihsm_handle wrap_priv = 0;

    status = azihsm_get_unwrapping_key(&provctx, &wrap_pub, &wrap_priv);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        fprintf(stderr, "error: azihsm_get_unwrapping_key failed (0x%x)\n", status);
        OPENSSL_cleanse(pkcs8_buf, (size_t)pkcs8_len);
        OPENSSL_free(pkcs8_buf);
        CRYPTO_THREAD_lock_free(provctx.unwrapping_key.lock);
        azihsm_close_device_and_session(device, session);
        return 1;
    }

    // 7. Setup RSA-AES wrap algorithm
    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params;
    memset(&oaep_params, 0, sizeof(oaep_params));
    oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    oaep_params.label = NULL;

    struct azihsm_algo_rsa_aes_wrap_params wrap_params;
    memset(&wrap_params, 0, sizeof(wrap_params));
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = 256;

    struct azihsm_algo wrap_algo;
    memset(&wrap_algo, 0, sizeof(wrap_algo));
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    // 8. Wrap the PKCS#8 key
    struct azihsm_buffer plain_buf;
    plain_buf.ptr = (uint8_t *)pkcs8_buf;
    plain_buf.len = (uint32_t)pkcs8_len;

    uint8_t output_data[WRAPPED_BUF_SIZE];
    struct azihsm_buffer wrapped_buf;
    wrapped_buf.ptr = output_data;
    wrapped_buf.len = sizeof(output_data);

    status = azihsm_crypt_encrypt(&wrap_algo, wrap_pub, &plain_buf, &wrapped_buf);

    OPENSSL_cleanse(pkcs8_buf, (size_t)pkcs8_len);
    OPENSSL_free(pkcs8_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        fprintf(stderr, "error: azihsm_crypt_encrypt failed (0x%x)\n", status);
        CRYPTO_THREAD_lock_free(provctx.unwrapping_key.lock);
        azihsm_close_device_and_session(device, session);
        return 1;
    }

    // 9. Write the wrapped blob
    if (write_file(output_path, wrapped_buf.ptr, wrapped_buf.len) != 0)
    {
        CRYPTO_THREAD_lock_free(provctx.unwrapping_key.lock);
        azihsm_close_device_and_session(device, session);
        return 1;
    }

    fprintf(stdout, "wrapped %u bytes -> %u bytes: %s\n", input_len, wrapped_buf.len, output_path);

    // 10. Cleanup — unwrapping key handles are owned by provctx, do not delete
    CRYPTO_THREAD_lock_free(provctx.unwrapping_key.lock);
    azihsm_close_device_and_session(device, session);

    return 0;
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_ossl_hsm.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define AZIHSM_MAX_KEY_FILE_SIZE (64 * 1024)

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

// Fallback owner backup key when no MOBK file is available
static const uint8_t DEFAULT_OBK[48] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
};

// Placeholder POTA signature (96 bytes, zeroed)
static const uint8_t DEFAULT_POTA_SIGNATURE[96] = { 0 };

// Placeholder POTA public key DER (120 bytes, zeroed)
static const uint8_t DEFAULT_POTA_PUBLIC_KEY_DER[120] = { 0 };

// clang-format on

azihsm_status azihsm_open_device_and_session(
    const AZIHSM_CONFIG *config,
    azihsm_handle *device,
    azihsm_handle *session
)
{
    azihsm_status status;

    struct azihsm_buffer bmk_buf = { NULL, 0 };
    struct azihsm_buffer muk_buf = { NULL, 0 };
    struct azihsm_buffer mobk_buf = { NULL, 0 };
    struct azihsm_buffer retrieved_bmk = { NULL, 0 };
    struct azihsm_buffer retrieved_mobk = { NULL, 0 };

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

    status = load_file_to_buffer(config->mobk_path, &mobk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        return status;
    }

    status = azihsm_get_device_handle(device);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        free_buffer(&mobk_buf);
        return status;
    }

    // Configure OBK and POTA based on whether TPM is available
    const char *use_tpm = getenv("AZIHSM_USE_TPM");

    struct azihsm_owner_backup_key_config backup_config = { 0 };
    struct azihsm_buffer obk_buf = { 0 };
    struct azihsm_pota_endorsement pota_endorsement = { 0 };
    struct azihsm_buffer pota_sig_buf = { 0 };
    struct azihsm_buffer pota_pubkey_buf = { 0 };
    struct azihsm_pota_endorsement_data pota_data = { 0 };

    if (use_tpm != NULL)
    {
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM;
        backup_config.owner_backup_key = NULL;

        pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM;
        pota_endorsement.endorsement = NULL;
    }
    else
    {
        // Use loaded OBK file if available, otherwise hardcoded default
        if (mobk_buf.ptr != NULL)
        {
            obk_buf = mobk_buf;
        }
        else
        {
            obk_buf.ptr = (uint8_t *)DEFAULT_OBK;
            obk_buf.len = sizeof(DEFAULT_OBK);
        }
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = &obk_buf;

        // [TODO] Replace placeholder POTA endorsement with real pid signature and pota public key
        // when available
        pota_sig_buf.ptr = (uint8_t *)DEFAULT_POTA_SIGNATURE;
        pota_sig_buf.len = sizeof(DEFAULT_POTA_SIGNATURE);
        pota_pubkey_buf.ptr = (uint8_t *)DEFAULT_POTA_PUBLIC_KEY_DER;
        pota_pubkey_buf.len = sizeof(DEFAULT_POTA_PUBLIC_KEY_DER);
        pota_data.signature = &pota_sig_buf;
        pota_data.public_key = &pota_pubkey_buf;
        pota_endorsement.source = AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER;
        pota_endorsement.endorsement = &pota_data;
    }

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
    free_buffer(&mobk_buf);

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

    // Retrieve and persist MOBK property
    status =
        get_part_property(*device, AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY, &retrieved_mobk);
    if (status == AZIHSM_STATUS_SUCCESS && retrieved_mobk.ptr != NULL)
    {
        status = write_buffer_to_file(config->mobk_path, &retrieved_mobk);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            free_buffer(&retrieved_mobk);
            azihsm_part_close(*device);
            return status;
        }
    }
    free_buffer(&retrieved_mobk);

    // Open session (seed=NULL lets the library generate random bytes internally)
    status = azihsm_sess_open(*device, &api_rev, &creds, NULL, session);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        azihsm_part_close(*device);
        return status;
    }

    return AZIHSM_STATUS_SUCCESS;
}

void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session)
{

    azihsm_sess_close(session);
    azihsm_part_close(device);
}
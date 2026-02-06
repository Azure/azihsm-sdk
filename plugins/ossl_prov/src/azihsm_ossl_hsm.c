// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_ossl_hsm.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AZIHSM_MAX_KEY_FILE_SIZE (64 * 1024)
#define AZIHSM_CREDENTIALS_SIZE 16

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
 * Loads credentials from a file.
 * The file must contain exactly AZIHSM_CREDENTIALS_SIZE (16) bytes of raw binary data.
 * This is the binary representation of the credential (ID or PIN), not hex-encoded.
 * Returns AZIHSM_STATUS_SUCCESS on success, AZIHSM_STATUS_INTERNAL_ERROR on failure.
 */
static azihsm_status load_credentials_from_file(const char *path, uint8_t *output)
{
    FILE *file = NULL;
    size_t bytes_read = 0;
    int extra_byte;

    if (path == NULL || output == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    file = fopen(path, "rb");
    if (file == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    bytes_read = fread(output, 1, AZIHSM_CREDENTIALS_SIZE, file);

    if (bytes_read != AZIHSM_CREDENTIALS_SIZE)
    {
        fclose(file);
        OPENSSL_cleanse(output, AZIHSM_CREDENTIALS_SIZE);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    /* Verify file contains exactly the expected size (no extra data) */
    extra_byte = fgetc(file);
    fclose(file);

    if (extra_byte != EOF)
    {
        OPENSSL_cleanse(output, AZIHSM_CREDENTIALS_SIZE);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Frees the configuration structure contents.
 * All pointer members are set to NULL after freeing to prevent double-free.
 * Safe to call multiple times on the same config.
 */
void azihsm_config_free(AZIHSM_CONFIG *config)
{
    if (config == NULL)
    {
        return;
    }

    OPENSSL_free(config->credentials_id_path);
    OPENSSL_free(config->credentials_pin_path);
    OPENSSL_free(config->bmk_path);
    OPENSSL_free(config->muk_path);
    OPENSSL_free(config->mobk_path);

    config->credentials_id_path = NULL;
    config->credentials_pin_path = NULL;
    config->bmk_path = NULL;
    config->muk_path = NULL;
    config->mobk_path = NULL;
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
    struct azihsm_credentials creds = { { 0 }, { 0 } };

    if (config == NULL || device == NULL || session == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    /* Load credentials from files */
    status = load_credentials_from_file(config->credentials_id_path, creds.id);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    status = load_credentials_from_file(config->credentials_pin_path, creds.pin);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(&creds, sizeof(creds));
        return status;
    }

    /* Load key files if they exist */
    status = load_file_to_buffer(config->bmk_path, &bmk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(&creds, sizeof(creds));
        return status;
    }

    status = load_file_to_buffer(config->muk_path, &muk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(&creds, sizeof(creds));
        free_buffer(&bmk_buf);
        return status;
    }

    status = load_file_to_buffer(config->mobk_path, &mobk_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(&creds, sizeof(creds));
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        return status;
    }

    status = azihsm_get_device_handle(device);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(&creds, sizeof(creds));
        free_buffer(&bmk_buf);
        free_buffer(&muk_buf);
        free_buffer(&mobk_buf);
        return status;
    }

    // Build owner backup key config: use loaded OBK file if available, otherwise hardcoded default
    struct azihsm_buffer obk_buf = { 0 };
    if (mobk_buf.ptr != NULL)
    {
        obk_buf = mobk_buf;
    }
    else
    {
        obk_buf.ptr = (uint8_t *)DEFAULT_OBK;
        obk_buf.len = sizeof(DEFAULT_OBK);
    }

    struct azihsm_owner_backup_key_config backup_config = { 0 };
    backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
    backup_config.owner_backup_key = &obk_buf;

    // Initialize partition with loaded keys (or NULL if not available)
    status = azihsm_part_init(
        *device,
        &creds,
        bmk_buf.ptr != NULL ? &bmk_buf : NULL,
        muk_buf.ptr != NULL ? &muk_buf : NULL,
        &backup_config
    );

    /* Input buffers no longer needed after part_init */
    free_buffer(&bmk_buf);
    free_buffer(&muk_buf);
    free_buffer(&mobk_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(&creds, sizeof(creds));
        azihsm_part_close(*device);
        return status;
    }

    /* Retrieve and persist BMK property */
    status = get_part_property(*device, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY, &retrieved_bmk);
    if (status == AZIHSM_STATUS_SUCCESS && retrieved_bmk.ptr != NULL)
    {
        status = write_buffer_to_file(config->bmk_path, &retrieved_bmk);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            OPENSSL_cleanse(&creds, sizeof(creds));
            free_buffer(&retrieved_bmk);
            azihsm_part_close(*device);
            return status;
        }
    }
    free_buffer(&retrieved_bmk);

    /* Retrieve and persist MOBK property */
    status =
        get_part_property(*device, AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY, &retrieved_mobk);
    if (status == AZIHSM_STATUS_SUCCESS && retrieved_mobk.ptr != NULL)
    {
        status = write_buffer_to_file(config->mobk_path, &retrieved_mobk);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            OPENSSL_cleanse(&creds, sizeof(creds));
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

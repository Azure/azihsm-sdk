#include "azihsm_ossl_hsm.h"

/*
 * picks and opens the first possible HSM device
 * */
static azihsm_error aihsm_get_device_handle(azihsm_handle* device)
{
    azihsm_error  status;
    azihsm_handle device_list;
    uint32_t      device_count = 0;

    status = azihsm_part_get_list(&device_list);

    if (status != 0) {
        return status;
    }

    status = azihsm_part_get_count(device_list, &device_count);

    if (status != AZIHSM_ERROR_SUCCESS) {
        azihsm_part_free_list(device_list);
        return status;
    }

    for (uint32_t i = 0; i < device_count; i++) {

        AzihsmChar       path[64] = { '\0' };
        struct AzihsmStr dev_path = { path, sizeof(path) };

        status = azihsm_part_get_path(device_list, i, &dev_path);

        if (status != AZIHSM_ERROR_SUCCESS) {
            continue;
        }

        status = azihsm_part_open(&dev_path, device);

        if (status == AZIHSM_ERROR_SUCCESS) {
            azihsm_part_free_list(device_list);
            return AZIHSM_ERROR_SUCCESS;
        }
    }

    azihsm_part_free_list(device_list);
    return AZIHSM_INTERNAL_ERROR;
}

azihsm_error aihsm_open_device_and_session(azihsm_handle* device, azihsm_handle* session)
{
    azihsm_error status;

    struct azihsm_api_rev api_rev = {
        .major = 1,
        .minor = 0
    };

    struct azihsm_app_creds creds = {
        .id  = {
            0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38,
            0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76
        },
        .pin = {
            0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00,
            0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00
        }
    };

    status = aihsm_get_device_handle(device);

    if (status != AZIHSM_ERROR_SUCCESS) {
        return status;
    }

    status = azihsm_part_init(*device, &creds);

    if (status != AZIHSM_ERROR_SUCCESS) {
        azihsm_part_close(*device);
        return status;
    }

    status = azihsm_sess_open(*device, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, session);

    if (status != AZIHSM_ERROR_SUCCESS) {
        azihsm_part_close(*device);
        return status;
    }

    return AZIHSM_ERROR_SUCCESS;
}

void aihsm_close_device_and_session(azihsm_handle device, azihsm_handle session) {

    azihsm_sess_close(session);
    azihsm_part_close(device);
}

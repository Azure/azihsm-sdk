// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>

/* Default file paths for partition keys */
#define AZIHSM_DEFAULT_BMK_PATH "/var/lib/azihsm/bmk.bin"
#define AZIHSM_DEFAULT_MUK_PATH "/var/lib/azihsm/muk.bin"
#define AZIHSM_DEFAULT_MOBK_PATH "/var/lib/azihsm/mobk.bin"
#define AZIHSM_DEFAULT_CREDENTIALS_ID_PATH "/var/lib/azihsm/credentials_id.bin"
#define AZIHSM_DEFAULT_CREDENTIALS_PIN_PATH "/var/lib/azihsm/credentials_pin.bin"

/* Configuration parameter names for openssl.cnf */
#define AZIHSM_CFG_CREDENTIALS_ID "azihsm-credentials-id"
#define AZIHSM_CFG_CREDENTIALS_PIN "azihsm-credentials-pin"
#define AZIHSM_CFG_BMK_PATH "azihsm-bmk-path"
#define AZIHSM_CFG_MUK_PATH "azihsm-muk-path"
#define AZIHSM_CFG_MOBK_PATH "azihsm-mobk-path"

/* Provider configuration structure */
typedef struct
{
    char *credentials_id_path;  /* Path to credentials ID file */
    char *credentials_pin_path; /* Path to credentials PIN file */
    char *bmk_path;             /* Path to BMK file */
    char *muk_path;             /* Path to MUK file */
    char *mobk_path;            /* Path to MOBK file */
} AZIHSM_CONFIG;

void azihsm_config_free(AZIHSM_CONFIG *config);
void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session);
azihsm_status azihsm_open_device_and_session(
    const AZIHSM_CONFIG *config,
    azihsm_handle *device,
    azihsm_handle *session
);

#ifdef __cplusplus
}
#endif

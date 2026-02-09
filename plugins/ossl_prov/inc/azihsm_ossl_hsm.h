// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>
#include <stdint.h>

/* Environment variable names for credentials paths.
 * These are checked first, before falling back to hardcoded defaults. */
#define AZIHSM_ENV_CREDENTIALS_ID_PATH "AZIHSM_CREDENTIALS_ID_PATH"
#define AZIHSM_ENV_CREDENTIALS_PIN_PATH "AZIHSM_CREDENTIALS_PIN_PATH"

/* Default file paths for partition keys */
#define AZIHSM_DEFAULT_BMK_PATH "/var/lib/azihsm/bmk.bin"
#define AZIHSM_DEFAULT_MUK_PATH "/var/lib/azihsm/muk.bin"
#define AZIHSM_DEFAULT_MOBK_PATH "/var/lib/azihsm/mobk.bin"
#define AZIHSM_DEFAULT_CREDENTIALS_ID_PATH "/var/lib/azihsm/credentials_id.bin"
#define AZIHSM_DEFAULT_CREDENTIALS_PIN_PATH "/var/lib/azihsm/credentials_pin.bin"

/* Configuration parameter names for openssl.cnf */
#define AZIHSM_CFG_BMK_PATH "azihsm-bmk-path"
#define AZIHSM_CFG_MUK_PATH "azihsm-muk-path"
#define AZIHSM_CFG_MOBK_PATH "azihsm-mobk-path"
#define AZIHSM_CFG_API_REVISION "azihsm-api-revision"

/* Supported API revision range */
#define AZIHSM_API_REVISION_MIN_MAJOR 1
#define AZIHSM_API_REVISION_MIN_MINOR 0
#define AZIHSM_API_REVISION_MAX_MAJOR 1
#define AZIHSM_API_REVISION_MAX_MINOR 0
#define AZIHSM_API_REVISION_DEFAULT_MAJOR 1
#define AZIHSM_API_REVISION_DEFAULT_MINOR 0

/* Provider configuration structure */
typedef struct
{
    char *credentials_id_path;  /* Path to credentials ID file */
    char *credentials_pin_path; /* Path to credentials PIN file */
    char *bmk_path;             /* Path to BMK file */
    char *muk_path;             /* Path to MUK file */
    char *mobk_path;            /* Path to MOBK file */
    uint16_t api_revision_major; /* API revision major version */
    uint16_t api_revision_minor; /* API revision minor version */
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

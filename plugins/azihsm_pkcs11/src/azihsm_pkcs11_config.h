// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define P11_CREDS_ID_LEN 16
#define P11_CREDS_PIN_LEN 16
#define P11_OBK_LEN 48

/* Environment variables consulted by azihsm_pkcs11_config_load(). */
#define AZIHSM_PKCS11_ENV_ID "AZIHSM_PKCS11_ID"
#define AZIHSM_PKCS11_ENV_PIN "AZIHSM_PKCS11_PIN"

/* Persistent host object store: opt-in file backend rooted at a store directory.
 * The backend is enabled by AZIHSM_PKCS11_PERSIST and rooted at
 * AZIHSM_PKCS11_STORE_DIR (a safe path), defaulting to a dedicated directory. */
#define AZIHSM_PKCS11_STORE_DIR_LEN 4096
#define AZIHSM_PKCS11_ENV_STORE_DIR "AZIHSM_PKCS11_STORE_DIR"
#define AZIHSM_PKCS11_ENV_PERSIST "AZIHSM_PKCS11_PERSIST"
#define AZIHSM_PKCS11_DEFAULT_STORE_DIR "/var/lib/azihsm/pkcs11"

/*
 * Provisioning inputs the module supplies to the AZIHSM ceremony, plus the host
 * object-store settings. The partition identifier and owner backup key are
 * operator/token-install configuration; the per-login PIN comes from C_Login,
 * and `default_pin` is only the fallback used when a caller logs in without one.
 */
typedef struct
{
    CK_BYTE id[P11_CREDS_ID_LEN];
    CK_BYTE obk[P11_OBK_LEN];
    CK_BYTE default_pin[P11_CREDS_PIN_LEN];
    char store_dir[AZIHSM_PKCS11_STORE_DIR_LEN]; /* persistent object-store root */
    bool store_persist;                          /* select the file backend over in-memory */
} azihsm_pkcs11_config;

/*
 * Populate `cfg`. Credentials are taken from the environment only
 * (AZIHSM_PKCS11_ID / AZIHSM_PKCS11_PIN, each 32 hex chars = 16 bytes); mock
 * defaults are used for anything unset so the module is usable out of the box
 * against the simulator. AZIHSM_PKCS11_CONF is reserved for a future config file
 * carrying key-material paths and slot layout once persistence lands.
 */
void azihsm_pkcs11_config_load(azihsm_pkcs11_config *cfg);

/*
 * Wipe `cfg` (credential id, OBK, and PIN bytes). Callers must clear a loaded
 * config as soon as it is no longer needed, on success and error paths alike;
 * the wipe is not elided for stack objects about to leave scope.
 */
void azihsm_pkcs11_config_clear(azihsm_pkcs11_config *cfg);

#ifdef __cplusplus
}
#endif

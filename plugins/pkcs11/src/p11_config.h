// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "p11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define P11_CREDS_ID_LEN 16
#define P11_CREDS_PIN_LEN 16
#define P11_OBK_LEN 48

/* Environment variables consulted by p11_config_load(). */
#define AZIHSM_P11_ENV_ID "AZIHSM_PKCS11_ID"
#define AZIHSM_P11_ENV_PIN "AZIHSM_PKCS11_PIN"

/*
 * Provisioning inputs the module supplies to the AZIHSM ceremony. The partition
 * identifier and owner backup key are operator/token-install configuration; the
 * per-login PIN comes from C_Login, and `default_pin` is only the fallback used
 * when a caller logs in without one.
 */
typedef struct
{
    CK_BYTE id[P11_CREDS_ID_LEN];
    CK_BYTE obk[P11_OBK_LEN];
    CK_BYTE default_pin[P11_CREDS_PIN_LEN];
} p11_config;

/*
 * Populate `cfg`. Credentials are taken from the environment only
 * (AZIHSM_PKCS11_ID / AZIHSM_PKCS11_PIN, each 32 hex chars = 16 bytes); mock
 * defaults are used for anything unset so the module is usable out of the box
 * against the simulator. AZIHSM_PKCS11_CONF is reserved for a future config file
 * carrying key-material paths and slot layout once persistence lands.
 */
void p11_config_load(p11_config *cfg);

#ifdef __cplusplus
}
#endif

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>
#include <inttypes.h>
#include <stdbool.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_pkey_param.h"

/*
 * EC-specific definitions which are shared
 * between multiple subsystems like keymgmt, encoder, ...
 * */

/* EC curve key sizes in bits */
#define AZIHSM_EC_P256_KEY_BITS 256
#define AZIHSM_EC_P384_KEY_BITS 384
#define AZIHSM_EC_P521_KEY_BITS 521

/* EC curve coordinate sizes in bytes (ceil(bits/8)) */
#define AZIHSM_EC_P256_COORD_SIZE 32
#define AZIHSM_EC_P384_COORD_SIZE 48
#define AZIHSM_EC_P521_COORD_SIZE 66

/*
 * Raw ECDSA signature sizes (r || s concatenated, no DER encoding).
 * The HSM uses raw format and expects exact buffer sizes.
 */
#define AZIHSM_EC_P256_SIG_SIZE 64
#define AZIHSM_EC_P384_SIG_SIZE 96
#define AZIHSM_EC_P521_SIG_SIZE 132

typedef struct
{
    azihsm_ecc_curve ec_curve_id;
    AZIHSM_KEY_USAGE_TYPE key_usage;
    azihsm_handle session;
    bool session_flag;
    char masked_key_file[4096];
} AIHSM_EC_GEN_CTX;

typedef struct
{
    AZIHSM_KEY_PAIR_OBJ key;
    AIHSM_EC_GEN_CTX genctx;
    bool has_public, has_private;
} AZIHSM_EC_KEY;

#ifdef __cplusplus
}
#endif

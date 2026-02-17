// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <inttypes.h>
#include <stdbool.h>

#include <azihsm.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_pkey_param.h"

/*
 * RSA-specific definitions which are shared
 * between multiple subsystems like keymgmt, encoder, ...
 * */

#define AIHSM_KEY_TYPE_RSA 0
#define AIHSM_KEY_TYPE_RSA_PSS 1

/* Supported RSA key sizes in bits */
#define AZIHSM_RSA_2048_KEY_BITS 2048
#define AZIHSM_RSA_3072_KEY_BITS 3072
#define AZIHSM_RSA_4096_KEY_BITS 4096

typedef struct
{
    int key_type;
    uint32_t pubkey_bits;
    AZIHSM_KEY_USAGE_TYPE key_usage;
    azihsm_handle session;
    bool session_flag;
    char masked_key_file[4096];
    char input_key_file[4096];
} AZIHSM_RSA_GEN_CTX;

typedef struct
{
    AZIHSM_KEY_PAIR_OBJ key;
    AZIHSM_RSA_GEN_CTX genctx;
    bool has_public, has_private;
} AZIHSM_RSA_KEY;

#ifdef __cplusplus
}
#endif

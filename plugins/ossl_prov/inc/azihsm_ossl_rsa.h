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

/*
 * RSA-specific definitions which are shared
 * between multiple subsystems like keymgmt, encoder, ...
 * */

#define AIHSM_KEY_TYPE_RSA 0
#define AIHSM_KEY_TYPE_RSA_PSS 1

typedef struct
{
    int key_type;
    uint32_t pubkey_bits;
    azihsm_handle session;
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

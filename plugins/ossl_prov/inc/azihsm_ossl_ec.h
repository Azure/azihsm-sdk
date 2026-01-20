// Copyright (C) Microsoft Corporation. All rights reserved.
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

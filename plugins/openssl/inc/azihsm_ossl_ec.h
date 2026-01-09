// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <azihsm.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_pkey_param.h"

/*
 * EC-specific definitions which are shared
 * between multiple subsystems like keymgmt, encoder, ...
 * */

typedef struct {
    azihsm_ec_curve_id ec_curve_id;
    AIHSM_KEY_USAGE_LIST pub_key_usage;
    AIHSM_KEY_USAGE_LIST priv_key_usage;
    azihsm_handle session;
} AIHSM_EC_GEN_CTX;

typedef struct {
    AZIHSM_KEY_PAIR_OBJ key;
    AIHSM_EC_GEN_CTX genctx;
    bool has_public, has_private;
} AZIHSM_EC_KEY;

#ifdef __cplusplus
}
#endif

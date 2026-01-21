// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <azihsm_api.h>
#include <cstdint>

/// Key properties for importing keys
typedef struct _KeyProps
{
    azihsm_key_kind key_kind;
    uint32_t key_size_bits;
    bool session_key = true;
    bool sign = false;
    bool verify = false;
    bool encrypt = false;
    bool decrypt = false;
    bool derive = false;
    bool wrap = false;
    bool unwrap = false;
} key_props;
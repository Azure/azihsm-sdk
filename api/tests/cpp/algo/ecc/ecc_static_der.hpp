// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstddef>
#include <cstdint>

// Returns a pointer and length for a precomputed PKCS#8 DER blob matching
// the given ECC curve.  Returns AZIHSM_STATUS_SUCCESS on success, or
// AZIHSM_STATUS_INVALID_ARGUMENT for unrecognised curves.
azihsm_status get_static_ecc_pkcs8_der(
    azihsm_ecc_curve curve,
    const uint8_t *&der_ptr,
    size_t &der_len
);

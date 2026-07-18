// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstddef>
#include <cstdint>

// Returns the pre-generated test-only RSA PKCS#8 DER blob for the requested bit length
// Currently supports 2048, 3072, or 4096-bit RSA keys.
azihsm_status get_static_rsa_pkcs8_der(uint32_t bit_len, const uint8_t *&der_ptr, size_t &der_len);
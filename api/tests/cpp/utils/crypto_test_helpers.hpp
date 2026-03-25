// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <vector>

// Note: we try to mirror Rust approach here without adding a dependency on it

namespace crypto_test_helpers
{
// Uses platform crypto APIs to produce ECC private key material in PKCS#8 DER.
// Why this differs by OS:
// - Linux/OpenSSL can directly emit PKCS#8 DER from generated EC keys.
// - Windows/CNG key export behavior differs and can produce DER that does not
//   always match what our simulator parser expects for these tests.
//   On Windows we therefore generate a CNG key, export its raw ECC private blob,
//   and then construct canonical PKCS#8 DER bytes ourselves.
azihsm_status generate_ecc_pkcs8_der(
    azihsm_ecc_curve curve,
    std::vector<uint8_t> &der
);
} // namespace crypto_test_helpers

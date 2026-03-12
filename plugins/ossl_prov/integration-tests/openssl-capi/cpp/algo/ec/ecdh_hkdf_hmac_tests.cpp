// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file ecdh_hkdf_hmac_tests.cpp
///
/// End-to-end round-trip test: ECDH key exchange → HKDF key derivation → HMAC
/// computation.  Mirrors the CLI integration test (ecdh_hkdf_hmac_roundtrip.sh)
/// but exercises the OpenSSL C API directly.

#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "utils/keygen_helpers.hpp"
#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ec_ecdh_hkdf_hmac : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full chain: ECDH → HKDF (derive HMAC key) → HMAC computation.
TEST_F(ec_ecdh_hkdf_hmac, round_trip)
{
    // Step 1: ECDH — derive a masked shared secret
    std::string ecdh_file = derive_masked_key_file(prov_.libctx(), "P-256");
    ASSERT_FALSE(ecdh_file.empty()) << "ECDH derivation failed";
    TempFileGuard ecdh_guard(ecdh_file.c_str());

    // Step 2: HKDF — derive an HMAC-SHA256 key from the shared secret
    char hmac_key_path[] = "/tmp/azihsm_test_chain_hmac_XXXXXX";
    int fd = mkstemp(hmac_key_path);
    ASSERT_GE(fd, 0);
    ::close(fd);
    ::unlink(hmac_key_path);
    TempFileGuard hmac_key_guard(hmac_key_path);

    {
        EvpKdfPtr kdf(EVP_KDF_fetch(prov_.libctx(), "HKDF", ProviderCtx::propquery()));
        ASSERT_NE(kdf, nullptr);
        EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
        ASSERT_NE(kctx, nullptr);

        char digest[] = "SHA256";
        char derived_type[] = "hmac";
        uint32_t derived_bits = 256;

        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
            OSSL_PARAM_utf8_string("azihsm.ikm_file",
                                   const_cast<char *>(ecdh_file.c_str()), 0),
            OSSL_PARAM_utf8_string("output_file", hmac_key_path, 0),
            OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
            OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
            OSSL_PARAM_END,
        };

        unsigned char dummy[4096];
        ASSERT_EQ(EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params), 1)
            << "HKDF derivation failed";
    }

    // Step 3: HMAC — compute HMAC-SHA256 over test data
    const std::string test_data = "ECDH-HKDF-HMAC round-trip test payload";

    EvpMacPtr mac(EVP_MAC_fetch(prov_.libctx(), "HMAC", ProviderCtx::propquery()));
    ASSERT_NE(mac, nullptr);
    EvpMacCtxPtr mctx(EVP_MAC_CTX_new(mac.get()));
    ASSERT_NE(mctx, nullptr);

    char digest_name[] = "SHA256";
    std::string key_path(hmac_key_path);

    OSSL_PARAM mac_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_octet_string(
            OSSL_MAC_PARAM_KEY,
            const_cast<char *>(key_path.c_str()),
            key_path.size()
        ),
        OSSL_PARAM_END,
    };

    ASSERT_EQ(EVP_MAC_init(mctx.get(), nullptr, 0, mac_params), 1)
        << "HMAC init failed";
    ASSERT_EQ(
        EVP_MAC_update(
            mctx.get(),
            reinterpret_cast<const unsigned char *>(test_data.data()),
            test_data.size()
        ),
        1
    ) << "HMAC update failed";

    size_t mac_len = 0;
    ASSERT_EQ(EVP_MAC_final(mctx.get(), nullptr, &mac_len, 0), 1);
    ASSERT_GT(mac_len, 0u);

    std::vector<unsigned char> mac_output(mac_len);
    ASSERT_EQ(EVP_MAC_final(mctx.get(), mac_output.data(), &mac_len, mac_output.size()), 1)
        << "HMAC final failed";
    mac_output.resize(mac_len);

    EXPECT_EQ(mac_output.size(), 32u) << "HMAC-SHA256 should produce 32 bytes";
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file hmac_tests.cpp
///
/// HMAC tests via the OpenSSL EVP MAC API.  The azihsm provider's HMAC
/// implementation expects a masked key file path (not raw key bytes) as the
/// `key` parameter.  A masked key is obtained by first performing an ECDH
/// derivation (derive_masked_key_file helper) and then using HKDF to derive
/// an HMAC key, matching the pattern used by the CLI integration tests.

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

class hmac : public ::testing::Test
{
  protected:
    ProviderCtx prov_;

    /// Derive an HMAC masked key file via ECDH + HKDF.
    /// Returns the path to the HMAC key file (caller must unlink).
    std::string derive_hmac_key_file(const char *digest_name, int digest_bits)
    {
        // Step 1: ECDH → masked shared secret file
        std::string ecdh_file = derive_masked_key_file(prov_.libctx());
        if (ecdh_file.empty())
        {
            return "";
        }

        // Step 2: HKDF → masked HMAC key file
        char hkdf_path[] = "/tmp/azihsm_test_hmac_key_XXXXXX";
        int fd = mkstemp(hkdf_path);
        if (fd < 0)
        {
            ::unlink(ecdh_file.c_str());
            return "";
        }
        ::close(fd);
        ::unlink(hkdf_path);

        EvpKdfPtr kdf(EVP_KDF_fetch(prov_.libctx(), "HKDF", ProviderCtx::propquery()));
        if (!kdf)
        {
            ::unlink(ecdh_file.c_str());
            return "";
        }

        EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
        if (!kctx)
        {
            ::unlink(ecdh_file.c_str());
            return "";
        }

        char digest_buf[16];
        std::strncpy(digest_buf, digest_name, sizeof(digest_buf) - 1);
        digest_buf[sizeof(digest_buf) - 1] = '\0';

        char derived_type[] = "hmac";
        uint32_t derived_bits = static_cast<uint32_t>(digest_bits);

        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_buf, 0),
            OSSL_PARAM_utf8_string("azihsm.ikm_file",
                                   const_cast<char *>(ecdh_file.c_str()), 0),
            OSSL_PARAM_utf8_string("output_file", hkdf_path, 0),
            OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
            OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
            OSSL_PARAM_END,
        };

        // keylen is required but the actual output goes to the file
        unsigned char dummy[4096];
        int rc = EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params);
        ::unlink(ecdh_file.c_str());

        if (rc != 1)
        {
            ::unlink(hkdf_path);
            return "";
        }

        return std::string(hkdf_path);
    }

    /// Compute HMAC with the given digest and masked key file.
    std::vector<unsigned char> compute_hmac(
        const char *digest_name,
        const std::string &key_file,
        const void *data,
        size_t data_len
    )
    {
        EvpMacPtr mac(EVP_MAC_fetch(prov_.libctx(), "HMAC", ProviderCtx::propquery()));
        if (!mac)
        {
            return {};
        }

        EvpMacCtxPtr mctx(EVP_MAC_CTX_new(mac.get()));
        if (!mctx)
        {
            return {};
        }

        char digest_buf[16];
        std::strncpy(digest_buf, digest_name, sizeof(digest_buf) - 1);
        digest_buf[sizeof(digest_buf) - 1] = '\0';

        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_buf, 0),
            OSSL_PARAM_octet_string(
                OSSL_MAC_PARAM_KEY,
                const_cast<char *>(key_file.c_str()),
                key_file.size()
            ),
            OSSL_PARAM_END,
        };

        if (EVP_MAC_init(mctx.get(), nullptr, 0, params) != 1)
        {
            return {};
        }
        if (EVP_MAC_update(mctx.get(), static_cast<const unsigned char *>(data), data_len) != 1)
        {
            return {};
        }

        size_t out_len = 0;
        if (EVP_MAC_final(mctx.get(), nullptr, &out_len, 0) != 1)
        {
            return {};
        }

        std::vector<unsigned char> result(out_len);
        if (EVP_MAC_final(mctx.get(), result.data(), &out_len, result.size()) != 1)
        {
            return {};
        }
        result.resize(out_len);
        return result;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// HMAC-SHA256 produces a 32-byte MAC.
TEST_F(hmac, sha256)
{
    std::string key_file = derive_hmac_key_file("SHA256", 256);
    ASSERT_FALSE(key_file.empty()) << "Failed to derive HMAC key";
    TempFileGuard guard(key_file.c_str());

    const std::string data = "HMAC test data";
    auto mac = compute_hmac("SHA256", key_file, data.data(), data.size());
    ASSERT_EQ(mac.size(), 32u) << "HMAC-SHA256 should produce 32 bytes";
}

/// HMAC-SHA384 produces a 48-byte MAC.
TEST_F(hmac, sha384)
{
    std::string key_file = derive_hmac_key_file("SHA384", 384);
    ASSERT_FALSE(key_file.empty()) << "Failed to derive HMAC key";
    TempFileGuard guard(key_file.c_str());

    const std::string data = "HMAC test data";
    auto mac = compute_hmac("SHA384", key_file, data.data(), data.size());
    ASSERT_EQ(mac.size(), 48u) << "HMAC-SHA384 should produce 48 bytes";
}

/// HMAC-SHA512 produces a 64-byte MAC.
TEST_F(hmac, sha512)
{
    std::string key_file = derive_hmac_key_file("SHA512", 512);
    ASSERT_FALSE(key_file.empty()) << "Failed to derive HMAC key";
    TempFileGuard guard(key_file.c_str());

    const std::string data = "HMAC test data";
    auto mac = compute_hmac("SHA512", key_file, data.data(), data.size());
    ASSERT_EQ(mac.size(), 64u) << "HMAC-SHA512 should produce 64 bytes";
}

/// Same key and data produce the same MAC (deterministic).
TEST_F(hmac, deterministic)
{
    std::string key_file = derive_hmac_key_file("SHA256", 256);
    ASSERT_FALSE(key_file.empty());
    TempFileGuard guard(key_file.c_str());

    const std::string data = "deterministic HMAC input";
    auto mac1 = compute_hmac("SHA256", key_file, data.data(), data.size());
    auto mac2 = compute_hmac("SHA256", key_file, data.data(), data.size());
    ASSERT_FALSE(mac1.empty());
    EXPECT_EQ(mac1, mac2);
}

/// Different data produces a different MAC.
TEST_F(hmac, different_data_different_mac)
{
    std::string key_file = derive_hmac_key_file("SHA256", 256);
    ASSERT_FALSE(key_file.empty());
    TempFileGuard guard(key_file.c_str());

    const std::string data_a = "data A";
    const std::string data_b = "data B";
    auto mac_a = compute_hmac("SHA256", key_file, data_a.data(), data_a.size());
    auto mac_b = compute_hmac("SHA256", key_file, data_b.data(), data_b.size());
    ASSERT_FALSE(mac_a.empty());
    ASSERT_FALSE(mac_b.empty());
    EXPECT_NE(mac_a, mac_b);
}

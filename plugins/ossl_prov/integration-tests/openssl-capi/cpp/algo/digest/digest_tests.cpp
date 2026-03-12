// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file digest_tests.cpp
///
/// Streaming digest tests via the OpenSSL EVP API.  The azihsm provider only
/// supports streaming (init/update/final), not one-shot digest operations.

#include <algorithm>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class digest : public ::testing::Test
{
  protected:
    ProviderCtx prov_;

    /// Helper: compute a streaming digest and return the result.
    std::vector<unsigned char> compute_digest(const char *algo, const void *data, size_t len)
    {
        EvpMdPtr md(EVP_MD_fetch(prov_.libctx(), algo, ProviderCtx::propquery()));
        if (!md)
        {
            return {};
        }

        EvpMdCtxPtr ctx(EVP_MD_CTX_new());
        if (!ctx)
        {
            return {};
        }

        if (EVP_DigestInit_ex2(ctx.get(), md.get(), nullptr) != 1)
        {
            return {};
        }
        if (EVP_DigestUpdate(ctx.get(), data, len) != 1)
        {
            return {};
        }

        unsigned int out_len = 0;
        std::vector<unsigned char> result(static_cast<size_t>(EVP_MD_get_size(md.get())));
        if (EVP_DigestFinal_ex(ctx.get(), result.data(), &out_len) != 1)
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

/// SHA-256 produces a 32-byte non-zero hash.
TEST_F(digest, sha256)
{
    const std::string input = "digest test data";
    auto hash = compute_digest("SHA256", input.data(), input.size());
    ASSERT_EQ(hash.size(), 32u);
    EXPECT_FALSE(std::all_of(hash.begin(), hash.end(), [](unsigned char b) { return b == 0; }))
        << "Hash should not be all zeros";
}

/// SHA-384 produces a 48-byte hash.
TEST_F(digest, sha384)
{
    const std::string input = "digest test data";
    auto hash = compute_digest("SHA384", input.data(), input.size());
    ASSERT_EQ(hash.size(), 48u);
}

/// SHA-512 produces a 64-byte hash.
TEST_F(digest, sha512)
{
    const std::string input = "digest test data";
    auto hash = compute_digest("SHA512", input.data(), input.size());
    ASSERT_EQ(hash.size(), 64u);
}

/// Same input produces the same hash (deterministic).
TEST_F(digest, deterministic)
{
    const std::string input = "deterministic hash input";
    auto hash1 = compute_digest("SHA256", input.data(), input.size());
    auto hash2 = compute_digest("SHA256", input.data(), input.size());
    ASSERT_FALSE(hash1.empty());
    EXPECT_EQ(hash1, hash2);
}

/// Different inputs produce different hashes.
TEST_F(digest, different_input_different_hash)
{
    const std::string input_a = "input A";
    const std::string input_b = "input B";
    auto hash_a = compute_digest("SHA256", input_a.data(), input_a.size());
    auto hash_b = compute_digest("SHA256", input_b.data(), input_b.size());
    ASSERT_FALSE(hash_a.empty());
    ASSERT_FALSE(hash_b.empty());
    EXPECT_NE(hash_a, hash_b);
}

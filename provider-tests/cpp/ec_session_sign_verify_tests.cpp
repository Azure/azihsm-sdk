// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file ec_session_sign_verify_tests.cpp
///
/// Round-trip sign / verify tests that use **session-based** EC keys via the
/// OpenSSL EVP API.  Session keys are ephemeral (never written to disk) and
/// therefore cannot be tested through the OpenSSL command-line tool.

#include <cstring>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string>
#include <vector>

#include "utils/keygen_helpers.hpp"
#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

// ---------------------------------------------------------------------------
// Test parameters
// ---------------------------------------------------------------------------

struct EcSessionTestCase
{
    const char *curve;  // "P-256", "P-384", "P-521"
    const char *digest; // "SHA256", "SHA384", "SHA512"
    const char *label;  // Human-readable label for SCOPED_TRACE
};

static const EcSessionTestCase kTestCases[] = {
    { "P-256", "SHA256", "P-256 / SHA-256" },
    { "P-384", "SHA384", "P-384 / SHA-384" },
    { "P-521", "SHA512", "P-521 / SHA-512" },
};

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class EC_SessionKeyRoundTrip : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Generate a session key for each curve, sign random data, then verify.
TEST_F(EC_SessionKeyRoundTrip, sign_verify_all_curves)
{
    for (const auto &tc : kTestCases)
    {
        SCOPED_TRACE(tc.label);

        // 1. Generate session key
        auto pkey = generate_ec_session_key(prov_.libctx(), tc.curve);
        ASSERT_NE(pkey, nullptr) << "keygen failed for " << tc.curve;

        // 2. Prepare test data
        const std::string message = std::string("round-trip test data for ") + tc.label;
        const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
        const size_t msg_len = message.size();

        // 3. Sign ---------------------------------------------------------
        EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
        ASSERT_NE(sign_ctx, nullptr);

        ASSERT_EQ(
            EVP_DigestSignInit_ex(
                sign_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        ) << "DigestSignInit failed";

        // Query required signature length
        size_t sig_len = 0;
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
        ASSERT_GT(sig_len, 0u);

        std::vector<unsigned char> signature(sig_len);
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1)
            << "DigestSign failed";
        signature.resize(sig_len);

        // 4. Verify -------------------------------------------------------
        EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
        ASSERT_NE(verify_ctx, nullptr);

        ASSERT_EQ(
            EVP_DigestVerifyInit_ex(
                verify_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        ) << "DigestVerifyInit failed";

        EXPECT_EQ(
            EVP_DigestVerify(
                verify_ctx.get(),
                signature.data(),
                signature.size(),
                msg_ptr,
                msg_len
            ),
            1
        ) << "DigestVerify failed — signature did not verify";

        // 5. Negative — tampered data must NOT verify ----------------------
        std::string tampered = message;
        tampered[0] ^= 0xFF;
        const auto *tampered_ptr = reinterpret_cast<const unsigned char *>(tampered.data());

        EvpMdCtxPtr neg_ctx(EVP_MD_CTX_new());
        ASSERT_NE(neg_ctx, nullptr);
        ASSERT_EQ(
            EVP_DigestVerifyInit_ex(
                neg_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        );

        EXPECT_NE(
            EVP_DigestVerify(
                neg_ctx.get(),
                signature.data(),
                signature.size(),
                tampered_ptr,
                tampered.size()
            ),
            1
        ) << "DigestVerify should fail with tampered data";
    }
}

/// Signing with one session key and verifying with a different session key
/// must fail.
TEST_F(EC_SessionKeyRoundTrip, verify_fails_with_wrong_key)
{
    auto key_a = generate_ec_session_key(prov_.libctx(), "P-256");
    auto key_b = generate_ec_session_key(prov_.libctx(), "P-256");
    ASSERT_NE(key_a, nullptr);
    ASSERT_NE(key_b, nullptr);

    const std::string message = "cross-key verification must fail";
    const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
    const size_t msg_len = message.size();

    // Sign with key_a
    EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
    ASSERT_NE(sign_ctx, nullptr);
    ASSERT_EQ(
        EVP_DigestSignInit_ex(
            sign_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            key_a.get(),
            nullptr
        ),
        1
    );

    size_t sig_len = 0;
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
    std::vector<unsigned char> signature(sig_len);
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1);
    signature.resize(sig_len);

    // Verify with key_b — must fail
    EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
    ASSERT_NE(verify_ctx, nullptr);
    ASSERT_EQ(
        EVP_DigestVerifyInit_ex(
            verify_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            key_b.get(),
            nullptr
        ),
        1
    );

    EXPECT_NE(
        EVP_DigestVerify(verify_ctx.get(), signature.data(), signature.size(), msg_ptr, msg_len),
        1
    ) << "Verification with wrong key should fail";
}

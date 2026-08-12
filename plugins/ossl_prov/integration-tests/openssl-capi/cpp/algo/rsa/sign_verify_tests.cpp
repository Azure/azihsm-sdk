// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file sign_verify_tests.cpp
///
/// Round-trip sign / verify tests that use **session-based** RSA keys via the
/// OpenSSL EVP API.  The HSM cannot generate RSA keys natively, so each test
/// generates an RSA key with the default provider, exports it to DER, and
/// imports it into the azihsm provider with azihsm.session=true.

#include <cstdio>
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
// Test fixture
// ---------------------------------------------------------------------------

class rsa_sign_verify : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

/// Fixture for tests that must run against each selectable RSA key form.
/// The parameter is the azihsm.key_kind value ("RSA" or "RSA-CRT").
class rsa_sign_verify_kind : public ::testing::TestWithParam<const char *>
{
  protected:
    ProviderCtx prov_;
};

INSTANTIATE_TEST_SUITE_P(
    key_kinds,
    rsa_sign_verify_kind,
    ::testing::Values("RSA", "RSA-CRT"),
    [](const ::testing::TestParamInfo<const char *> &info) {
        return std::string(info.param) == "RSA-CRT" ? "rsa_crt" : "rsa";
    }
);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Round-trip sign / verify with PKCS#1 v1.5 padding (default), against both
/// the plain and the CRT stored key form.
TEST_P(rsa_sign_verify_kind, sign_verify_pkcs1)
{
    auto pkey = generate_rsa_session_key(prov_.libctx(), 2048, "digitalSignature", GetParam());
    ASSERT_NE(pkey, nullptr) << "RSA session key generation failed";

    const std::string message = "RSA PKCS#1 v1.5 round-trip test data";
    const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
    const size_t msg_len = message.size();

    // Sign ----------------------------------------------------------------
    EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
    ASSERT_NE(sign_ctx, nullptr);

    ASSERT_EQ(
        EVP_DigestSignInit_ex(
            sign_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    ) << "DigestSignInit failed";

    size_t sig_len = 0;
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
    ASSERT_GT(sig_len, 0u);

    std::vector<unsigned char> signature(sig_len);
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1)
        << "DigestSign failed";
    signature.resize(sig_len);

    // Verify --------------------------------------------------------------
    EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
    ASSERT_NE(verify_ctx, nullptr);

    ASSERT_EQ(
        EVP_DigestVerifyInit_ex(
            verify_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    ) << "DigestVerifyInit failed";

    EXPECT_EQ(
        EVP_DigestVerify(verify_ctx.get(), signature.data(), signature.size(), msg_ptr, msg_len),
        1
    ) << "DigestVerify failed — signature did not verify";
}

/// PKCS#1 v1.5: tampered data must NOT verify.  Runs on the default key form
/// (RSA-CRT); the stored form is not what is under test here.
TEST_F(rsa_sign_verify, pkcs1_rejects_tampered_data)
{
    auto pkey = generate_rsa_session_key(prov_.libctx());
    ASSERT_NE(pkey, nullptr) << "RSA session key generation failed";

    const std::string message = "RSA PKCS#1 v1.5 tamper test data";
    const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
    const size_t msg_len = message.size();

    // Sign
    EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
    ASSERT_NE(sign_ctx, nullptr);
    ASSERT_EQ(
        EVP_DigestSignInit_ex(
            sign_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    );

    size_t sig_len = 0;
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
    std::vector<unsigned char> signature(sig_len);
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1);
    signature.resize(sig_len);

    // Tamper with data
    std::string tampered = message;
    tampered[0] ^= 0xFF;
    const auto *tampered_ptr = reinterpret_cast<const unsigned char *>(tampered.data());

    // Verify must fail
    EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
    ASSERT_NE(verify_ctx, nullptr);
    ASSERT_EQ(
        EVP_DigestVerifyInit_ex(
            verify_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    );

    EXPECT_NE(
        EVP_DigestVerify(
            verify_ctx.get(),
            signature.data(),
            signature.size(),
            tampered_ptr,
            tampered.size()
        ),
        1
    ) << "DigestVerify should fail with tampered data";
}

/// Round-trip sign / verify with RSA-PSS padding, against both the plain and
/// the CRT stored key form.
TEST_P(rsa_sign_verify_kind, sign_verify_pss)
{
    auto pkey = generate_rsa_session_key(prov_.libctx(), 2048, "digitalSignature", GetParam());
    ASSERT_NE(pkey, nullptr) << "RSA session key generation failed";

    const std::string message = "RSA-PSS round-trip test data";
    const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
    const size_t msg_len = message.size();

    // Sign with PSS padding -----------------------------------------------
    EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
    ASSERT_NE(sign_ctx, nullptr);

    EVP_PKEY_CTX *sign_pctx = nullptr;
    ASSERT_EQ(
        EVP_DigestSignInit_ex(
            sign_ctx.get(),
            &sign_pctx,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    ) << "DigestSignInit failed";
    ASSERT_NE(sign_pctx, nullptr);

    // Use OSSL_PARAM to set PSS padding — the legacy EVP_PKEY_CTX_set_rsa_padding
    // API does not route through the provider's set_ctx_params handler.
    char pss_sign[] = "pss";
    OSSL_PARAM pss_sign_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, pss_sign, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(sign_pctx, pss_sign_params), 1)
        << "Failed to set PSS padding for signing";

    size_t sig_len = 0;
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
    ASSERT_GT(sig_len, 0u);

    std::vector<unsigned char> signature(sig_len);
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1)
        << "DigestSign with PSS failed";
    signature.resize(sig_len);

    // Verify with PSS padding ---------------------------------------------
    EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
    ASSERT_NE(verify_ctx, nullptr);

    EVP_PKEY_CTX *verify_pctx = nullptr;
    ASSERT_EQ(
        EVP_DigestVerifyInit_ex(
            verify_ctx.get(),
            &verify_pctx,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    ) << "DigestVerifyInit failed";
    ASSERT_NE(verify_pctx, nullptr);

    char pss_verify[] = "pss";
    OSSL_PARAM pss_verify_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, pss_verify, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(verify_pctx, pss_verify_params), 1)
        << "Failed to set PSS padding for verification";

    EXPECT_EQ(
        EVP_DigestVerify(verify_ctx.get(), signature.data(), signature.size(), msg_ptr, msg_len),
        1
    ) << "DigestVerify with PSS failed — signature did not verify";
}

/// RSA-PSS: tampered data must NOT verify.  Runs on the default key form
/// (RSA-CRT); the stored form is not what is under test here.
TEST_F(rsa_sign_verify, pss_rejects_tampered_data)
{
    auto pkey = generate_rsa_session_key(prov_.libctx());
    ASSERT_NE(pkey, nullptr) << "RSA session key generation failed";

    const std::string message = "RSA-PSS tamper test data";
    const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
    const size_t msg_len = message.size();

    // Sign with PSS
    EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
    ASSERT_NE(sign_ctx, nullptr);

    EVP_PKEY_CTX *sign_pctx = nullptr;
    ASSERT_EQ(
        EVP_DigestSignInit_ex(
            sign_ctx.get(),
            &sign_pctx,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    );
    ASSERT_NE(sign_pctx, nullptr);

    char pss_sign[] = "pss";
    OSSL_PARAM pss_sign_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, pss_sign, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(sign_pctx, pss_sign_params), 1);

    size_t sig_len = 0;
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
    std::vector<unsigned char> signature(sig_len);
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1);
    signature.resize(sig_len);

    // Tamper with data
    std::string tampered = message;
    tampered[0] ^= 0xFF;
    const auto *tampered_ptr = reinterpret_cast<const unsigned char *>(tampered.data());

    // Verify with PSS must fail
    EvpMdCtxPtr neg_ctx(EVP_MD_CTX_new());
    ASSERT_NE(neg_ctx, nullptr);

    EVP_PKEY_CTX *neg_pctx = nullptr;
    ASSERT_EQ(
        EVP_DigestVerifyInit_ex(
            neg_ctx.get(),
            &neg_pctx,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            pkey.get(),
            nullptr
        ),
        1
    );
    char pss_neg[] = "pss";
    OSSL_PARAM pss_neg_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, pss_neg, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(neg_pctx, pss_neg_params), 1);

    EXPECT_NE(
        EVP_DigestVerify(
            neg_ctx.get(),
            signature.data(),
            signature.size(),
            tampered_ptr,
            tampered.size()
        ),
        1
    ) << "DigestVerify with PSS should fail with tampered data";
}

/// Signing with one RSA session key and verifying with a different RSA session
/// key must fail.  Runs on the default key form (RSA-CRT); the stored form is
/// not what is under test here.
TEST_F(rsa_sign_verify, verify_fails_with_wrong_key)
{
    auto key_a = generate_rsa_session_key(prov_.libctx());
    auto key_b = generate_rsa_session_key(prov_.libctx());
    ASSERT_NE(key_a, nullptr);
    ASSERT_NE(key_b, nullptr);

    const std::string message = "cross-key RSA verification must fail";
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
    ) << "Verification with wrong RSA key should fail";
}

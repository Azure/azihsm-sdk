// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file enc_dec_tests.cpp
///
/// Round-trip encrypt / decrypt tests that use **session-based** RSA keys with
/// RSA-OAEP padding via the OpenSSL EVP API.  The HSM cannot generate RSA keys
/// natively, so each test generates an RSA key with the default provider,
/// exports it to DER, and imports it into the azihsm provider with
/// azihsm.session=true and azihsm.key_usage=keyEncipherment.

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

class rsa_enc_dec : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Round-trip: encrypt with public key, decrypt with private key, compare.
/// Explicitly sets OAEP padding mode; the OAEP digest and MGF1 digest are
/// left at their OpenSSL defaults.
TEST_F(rsa_enc_dec, encrypt_decrypt_oaep)
{
    auto pkey = generate_rsa_session_key(prov_.libctx(), 2048, "keyEncipherment");
    ASSERT_NE(pkey, nullptr) << "RSA encryption session key generation failed";

    const std::string plaintext = "RSA-OAEP round-trip test payload";
    const auto *pt_ptr = reinterpret_cast<const unsigned char *>(plaintext.data());
    const size_t pt_len = plaintext.size();

    // Encrypt -------------------------------------------------------------
    EvpPkeyCtxPtr enc_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), pkey.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(enc_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(enc_ctx.get()), 1) << "encrypt_init failed";

    // Explicitly set OAEP padding mode via OSSL_PARAM (consistent with PSS
    // test approach — avoid legacy EVP_PKEY_CTX_set_rsa_padding API).
    char oaep_mode[] = "oaep";
    OSSL_PARAM enc_pad_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, oaep_mode, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(enc_ctx.get(), enc_pad_params), 1)
        << "Failed to set OAEP padding for encryption";

    // Query ciphertext length
    size_t ct_len = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(enc_ctx.get(), nullptr, &ct_len, pt_ptr, pt_len), 1);
    ASSERT_GT(ct_len, 0u);

    std::vector<unsigned char> ciphertext(ct_len);
    ASSERT_EQ(EVP_PKEY_encrypt(enc_ctx.get(), ciphertext.data(), &ct_len, pt_ptr, pt_len), 1)
        << "EVP_PKEY_encrypt failed";
    ciphertext.resize(ct_len);

    // Ciphertext must differ from plaintext
    ASSERT_NE(std::string(ciphertext.begin(), ciphertext.end()), plaintext);

    // Decrypt -------------------------------------------------------------
    EvpPkeyCtxPtr dec_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), pkey.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(dec_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(dec_ctx.get()), 1) << "decrypt_init failed";

    char oaep_mode_dec[] = "oaep";
    OSSL_PARAM dec_pad_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, oaep_mode_dec, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(dec_ctx.get(), dec_pad_params), 1)
        << "Failed to set OAEP padding for decryption";

    // Query decrypted length
    size_t dec_len = 0;
    ASSERT_EQ(
        EVP_PKEY_decrypt(dec_ctx.get(), nullptr, &dec_len, ciphertext.data(), ciphertext.size()),
        1
    );
    ASSERT_GT(dec_len, 0u);

    std::vector<unsigned char> decrypted(dec_len);
    ASSERT_EQ(
        EVP_PKEY_decrypt(
            dec_ctx.get(),
            decrypted.data(),
            &dec_len,
            ciphertext.data(),
            ciphertext.size()
        ),
        1
    ) << "EVP_PKEY_decrypt failed";
    decrypted.resize(dec_len);

    // Decrypted output must match original plaintext
    EXPECT_EQ(std::string(decrypted.begin(), decrypted.end()), plaintext)
        << "Decrypted data does not match original plaintext";
}

/// Encrypting with key_a and decrypting with key_b must fail.
TEST_F(rsa_enc_dec, decrypt_fails_with_wrong_key)
{
    auto key_a = generate_rsa_session_key(prov_.libctx(), 2048, "keyEncipherment");
    auto key_b = generate_rsa_session_key(prov_.libctx(), 2048, "keyEncipherment");
    ASSERT_NE(key_a, nullptr);
    ASSERT_NE(key_b, nullptr);

    const std::string plaintext = "cross-key RSA decryption must fail";
    const auto *pt_ptr = reinterpret_cast<const unsigned char *>(plaintext.data());
    const size_t pt_len = plaintext.size();

    // Encrypt with key_a (OAEP)
    EvpPkeyCtxPtr enc_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), key_a.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(enc_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(enc_ctx.get()), 1);

    char oaep_enc[] = "oaep";
    OSSL_PARAM enc_pad_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, oaep_enc, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(enc_ctx.get(), enc_pad_params), 1)
        << "Failed to set OAEP padding for encryption";

    size_t ct_len = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(enc_ctx.get(), nullptr, &ct_len, pt_ptr, pt_len), 1);
    std::vector<unsigned char> ciphertext(ct_len);
    ASSERT_EQ(EVP_PKEY_encrypt(enc_ctx.get(), ciphertext.data(), &ct_len, pt_ptr, pt_len), 1);
    ciphertext.resize(ct_len);

    // Decrypt with key_b (OAEP) — must fail
    EvpPkeyCtxPtr dec_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), key_b.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(dec_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(dec_ctx.get()), 1);

    char oaep_dec[] = "oaep";
    OSSL_PARAM dec_pad_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, oaep_dec, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(dec_ctx.get(), dec_pad_params), 1)
        << "Failed to set OAEP padding for decryption";

    size_t dec_len = 0;
    // Size query may succeed even with wrong key
    EVP_PKEY_decrypt(dec_ctx.get(), nullptr, &dec_len, ciphertext.data(), ciphertext.size());
    if (dec_len == 0)
    {
        dec_len = ciphertext.size();
    }

    std::vector<unsigned char> decrypted(dec_len);
    int rc = EVP_PKEY_decrypt(
        dec_ctx.get(),
        decrypted.data(),
        &dec_len,
        ciphertext.data(),
        ciphertext.size()
    );

    // Either the decrypt call itself fails, or it produces garbled output
    if (rc == 1)
    {
        decrypted.resize(dec_len);
        EXPECT_NE(std::string(decrypted.begin(), decrypted.end()), plaintext)
            << "Decryption with wrong key should not produce original plaintext";
    }
    // rc != 1 means the decrypt call failed, which is the expected outcome
}


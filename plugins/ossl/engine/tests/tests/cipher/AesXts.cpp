
// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmCiphers.hpp"
#include <openssl/rand.h>
#include <cstring>

static void setup_key(AziHsmAesCipherCtx &aes_ctx, AziHsmEngine &azihsm_engine, bool keygen)
{
    if (keygen)
    {
        REQUIRE(aes_ctx.keygen(1) == 1);
    }
    else
    {
        // Generate random key
        std::vector<unsigned char> aes_key(32);
        REQUIRE(RAND_bytes(aes_key.data(), aes_key.size()) == 1);
        std::vector<unsigned char> iv(32);
        REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        REQUIRE(unwrapping_key.size() > 0);

        // Create wrapped data
        std::vector<unsigned char> wrapped_blob_key = azihsm_engine.wrapTargetKey(unwrapping_key, aes_key);
        REQUIRE(wrapped_blob_key.size() > 0);
        std::vector<unsigned char> wrapped_blob_iv = azihsm_engine.wrapTargetKey(unwrapping_key, iv);
        REQUIRE(wrapped_blob_iv.size() > 0);

        // Import key
        REQUIRE(azihsm_engine.unwrapAesXts(aes_ctx.getCtx(), wrapped_blob_key, wrapped_blob_iv) == 1);
    }
}

TEST_CASE("AZIHSM AES XTS Ciphers", "[AziHsmAesXts]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const EVP_CIPHER *cipher;

    SECTION("Test AES-XTS init ctx with deleted key")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *key = aes_ctx.getCurrentKey();

        std::vector<unsigned char> old_key_copy;
        for (int i = 0; i < 8; i++)
        {
            old_key_copy.push_back(key[i]);
        }

        // Reset CTX to test another key and cipher
        REQUIRE(aes_ctx.init(e, NID_aes_192_cbc, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, old_key_copy.data(), nullptr) == 0);
    }

    SECTION("Test AES-XTS Empty Ctx copy")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);

        // Copy CTX
        AziHsmAesCipherCtx aes_ctx_copy = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);
    }

    SECTION("Test AES-XTS Ctx Copy")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Copy CTX
        AziHsmAesCipherCtx aes_ctx_copy = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);
    }

    SECTION("Test AES-XTS Encrypt/Decrypt")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        std::vector<unsigned char> iv(16);
        REQUIRE(RAND_bytes(iv.data(), 16) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, iv.data()) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Padding is enabled. So account for an extra block size in the data
        std::vector<unsigned char> plain_data(64 * 1024);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);
    }

    SECTION("Test AES-XTS Encrypt/Decrypt Unaligned data")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *plain_text = (const unsigned char *)"I solemnly swear that I am up to no good........";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text;
        std::vector<unsigned char> recovered_text;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);

        REQUIRE(aes_ctx.encrypt(plain_text, ptext_len, iv.data(), cipher_text) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_text.data(), cipher_text.size(), iv.data(), recovered_text) == 1);
        REQUIRE(std::memcmp(plain_text, recovered_text.data(), ptext_len) == 0);
    }

    SECTION("Test AES-XTS Encrypt/Decrypt Corrupt data")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        std::vector<unsigned char> iv(16);
        REQUIRE(RAND_bytes(iv.data(), 16) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, iv.data()) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Padding is enabled. So account for an extra block size in the data
        std::vector<unsigned char> plain_data(512);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data) == 1);

        // corrupt the cipher data
        cipher_data[0] = cipher_data[0] ^ 0x01;

        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) != 0);
    }

    SECTION("Test AES-XTS Encrypt/Decrypt mismatch key")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        std::vector<unsigned char> iv(16);
        REQUIRE(RAND_bytes(iv.data(), 16) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, iv.data()) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Padding is enabled. So account for an extra block size in the data
        std::vector<unsigned char> plain_data(512);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data) == 1);

        // replace the key with a new key
        setup_key(aes_ctx, azihsm_engine, true);

        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) != 0);
    }

    SECTION("Test AES-XTS Encrypt/Decrypt mismatch tweak")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        std::vector<unsigned char> iv1(16);
        REQUIRE(RAND_bytes(iv1.data(), 16) == 1);
        std::vector<unsigned char> iv2(16);
        REQUIRE(RAND_bytes(iv2.data(), 16) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, iv1.data()) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Padding is enabled. So account for an extra block size in the data
        std::vector<unsigned char> plain_data(512);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv1.data(), cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv2.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) != 0);
    }

    SECTION("Test Invalid Key Length")
    {
        AziHsmAesCipherCtx aes_ctx;
        std::vector<unsigned char> invalid_key(24); // 192 bits, invalid for AES-XTS
        REQUIRE(RAND_bytes(invalid_key.data(), invalid_key.size()) == 1);
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, invalid_key.data(), nullptr) == 0); // Expected failure
    }

    SECTION("Test Null IV on Encrypt/Decrypt")
    {
        AziHsmAesCipherCtx aes_ctx;
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> plain_data(512);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        // Encrypt with null IV, which should fail in XTS mode
        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), nullptr, cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), nullptr, recovered_data) == 1);
    }

    SECTION("Test Empty Data Encryption")
    {
        AziHsmAesCipherCtx aes_ctx;
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> empty_data;
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;

        REQUIRE(aes_ctx.encrypt(empty_data.data(), empty_data.size(), nullptr, cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), nullptr, recovered_data) == 1);
        REQUIRE(recovered_data.size() == 0); // Ensure output is also empty
    }

    SECTION("Test Reinitialize Context without Clearing")
    {
        AziHsmAesCipherCtx aes_ctx;
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Reinitialize with a different cipher without clearing
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
    }

    SECTION("Test Encrypt/Decrypt with Repeated Calls")
    {
        AziHsmAesCipherCtx aes_ctx;
        std::vector<unsigned char> iv(16);
        REQUIRE(RAND_bytes(iv.data(), 16) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, iv.data()) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> plain_data(256);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        // First encryption/decryption
        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);

        // Second encryption/decryption without reinitializing
        cipher_data.clear();
        recovered_data.clear();
        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);
    }

    SECTION("Encrypt/decrypt with a wrapped key")
    {
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx.init(e, NID_aes_256_xts, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, false);

        // Padding is enabled. So account for an extra block size in the data
        std::vector<unsigned char> plain_data(64 * 1024);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), nullptr, cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), nullptr, recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);
    }
}

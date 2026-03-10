// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmCiphers.hpp"
#include <openssl/rand.h>
#include <cstring>

#define AZIHSM_AES_GCM_AAD_SIZE 32
#define AZIHSM_AES_GCM_TAG_SIZE 16

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

        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        REQUIRE(unwrapping_key.size() > 0);

        // Create wrapped data
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, aes_key);
        REQUIRE(wrapped_blob.size() > 0);

        // Import key
        REQUIRE(azihsm_engine.unwrapAes(aes_ctx.getCtx(), NID_aes_256_gcm, wrapped_blob) == 1);
    }
}

TEST_CASE("AZIHSM AES GCM Ciphers", "[AziHsmAesGcm]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const EVP_CIPHER *cipher;
#ifdef AZIHSM_GCM
    SECTION("Test AES-GCM init ctx with deleted key")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
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

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, old_key_copy.data(), nullptr) == 0);
    }

    SECTION("Test AES-GCM Empty Ctx copy")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);

        // Copy CTX
        AziHsmAesCipherCtx aes_ctx_copy = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);
    }

    SECTION("Test AES-GCM Ctx Copy")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Copy CTX
        AziHsmAesCipherCtx aes_ctx_copy = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);
    }

    SECTION("Test AES-GCM Set/Get tag")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> tag1(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag1) == 1);
        REQUIRE(tag1.size() == 16);

        std::vector<unsigned char> tag2(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(RAND_bytes(tag2.data(), AZIHSM_AES_GCM_TAG_SIZE) == 1);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag2) == 1);

        std::vector<unsigned char> tag3(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag3) == 1);
        REQUIRE(tag3 == tag2);
    }

    SECTION("Test AES-GCM Set/Get IV len")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> empty;
        int iv_len2 = 16;
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_IVLEN, iv_len2, empty) == 0);

        int iv_len1 = 12;
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_IVLEN, iv_len1, empty) == 1);

        int iv_len3 = 0;
        std::vector<unsigned char> iv(sizeof(iv_len3));
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_GET_IVLEN, 0, iv) == 1);
        memcpy(&iv_len3, iv.data(), iv.size());
        REQUIRE(iv_len3 == iv_len1);
    }

    SECTION("Test AES-GCM Set TLS1 AAD")
    {
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        std::vector<unsigned char> tls1_aad(EVP_AEAD_TLS1_AAD_LEN);
        REQUIRE(RAND_bytes(tls1_aad.data(), EVP_AEAD_TLS1_AAD_LEN) == 1);

        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_TLS1_AAD, EVP_AEAD_TLS1_AAD_LEN, tls1_aad) == 1);
    }

    SECTION("Test AES-GCM encrypt/decrypt No AAD")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> plain_data(2000);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> empty_aad;

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);

        // encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_data.data(), plain_data.size(), iv.data(), empty_aad, cipher_data) == 1);

        // Get tag
        tag.resize(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);

        // decrypt
        REQUIRE(aes_ctx.auth_decrypt(cipher_data.data(), cipher_data.size(), iv.data(), empty_aad, recovered_data) == 1);

        // Compare
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);
    }

    SECTION("Test AES-GCM encrypt/decrypt")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *plain_text = (const unsigned char *)"A secret is a secret until it's not until it is ";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text(ptext_len);
        std::vector<unsigned char> recovered_text(ptext_len);
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // set AAD and encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_text, ptext_len, iv.data(), aad, cipher_text) == 1);

        // Get tag - unnecessary though.
        tag.resize(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag) == 1);

        // set AAD and decrypt
        REQUIRE(aes_ctx.auth_decrypt(cipher_text.data(), cipher_text.size(), iv.data(), aad, recovered_text) == 1);

        // Compare
        REQUIRE(std::memcmp(plain_text, recovered_text.data(), ptext_len) == 0);
    }

    SECTION("Test AES-GCM encrypt/decrypt corrput data")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> plain_data(128);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // encrypt with aad1
        REQUIRE(aes_ctx.auth_encrypt(plain_data.data(), plain_data.size(), iv.data(), aad, cipher_data) == 1);

        // corrupt cipher data
        cipher_data[0] = cipher_data[0] ^ 0x1;

        // decrypt with aad2 - should fail
        REQUIRE(aes_ctx.auth_decrypt(cipher_data.data(), cipher_data.size(), iv.data(), aad, recovered_data) == 0);
    }

    SECTION("Test AES-GCM encrypt/decrypt mismatch key")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *plain_text = (const unsigned char *)"A secret is a secret until it's not until it is ";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text(ptext_len);
        std::vector<unsigned char> recovered_text(ptext_len);
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // set AAD and encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_text, ptext_len, iv.data(), aad, cipher_text) == 1);

        // Get tag
        tag.resize(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);

        // Replace key by a new one.
        setup_key(aes_ctx, azihsm_engine, true);

        // Restore tag
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag) == 1);

        // set IV, AAD and decrypt
        // aad, iv and tag are same but key is different
        REQUIRE(aes_ctx.auth_decrypt(cipher_text.data(), cipher_text.size(), iv.data(), aad, recovered_text) == 0);
    }

    SECTION("Test AES-GCM encrypt/decrypt mismatch IV")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *plain_text = (const unsigned char *)"A secret is a secret until it's not until it is ";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text(ptext_len);
        std::vector<unsigned char> recovered_text(ptext_len);
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv1(iv_len), iv2(iv_len);
        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv1.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(iv2.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // set IV1, AAD and encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_text, ptext_len, iv1.data(), aad, cipher_text) == 1);

        // set IV2, AAD and decrypt
        // aad, tag and key are same but iv is different
        REQUIRE(aes_ctx.auth_decrypt(cipher_text.data(), cipher_text.size(), iv2.data(), aad, recovered_text) == 0);
    }

    SECTION("Test AES-GCM encrypt/decrypt mismatch Tag")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *plain_text = (const unsigned char *)"A secret is a secret until it's not until it is ";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text(ptext_len);
        std::vector<unsigned char> recovered_text(ptext_len);
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // set IV1, AAD and encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_text, ptext_len, iv.data(), aad, cipher_text) == 1);

        // Get tag
        tag.resize(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);

        // Flip a bit in tag
        tag[0] = tag[0] ^ 0x1;

        // Restore tag
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag) == 1);

        // set IV2, AAD and decrypt
        // aad, tag and key are same but iv is different
        REQUIRE(aes_ctx.auth_decrypt(cipher_text.data(), cipher_text.size(), iv.data(), aad, recovered_text) == 0);
    }

    SECTION("Test AES-GCM encrypt/decrypt mismatch AAD")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        const unsigned char *plain_text = (const unsigned char *)"A secret is a secret until it's not until it is ";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text(ptext_len);
        std::vector<unsigned char> recovered_text(ptext_len);
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> aad1(AZIHSM_AES_GCM_AAD_SIZE), aad2(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad1.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);
        REQUIRE(RAND_bytes(aad2.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // set IV1, AAD and encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_text, ptext_len, iv.data(), aad1, cipher_text) == 1);

        // set IV2, AAD and decrypt
        // aad, tag and key are same but iv is different
        REQUIRE(aes_ctx.auth_decrypt(cipher_text.data(), cipher_text.size(), iv.data(), aad2, recovered_text) == 0);
    }

    SECTION("AES-GCM Encrypt/Decrypt with Empty Plaintext")
    {
        AziHsmAesCipherCtx aes_ctx;
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> cipher_data, recovered_data, tag(AZIHSM_AES_GCM_TAG_SIZE), iv(12);
        REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        REQUIRE(aes_ctx.auth_encrypt(nullptr, 0, iv.data(), aad, cipher_data) == 1);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);
        REQUIRE(cipher_data.empty());

        ////JIRA 30240647
        /// There are some nuances between OpenSSL 1.1.1 and OpenSSL 3.0.0 in handling len = 0 for custom ciphers (GCM and XTS in our case).
        /// OpenSSL 3.0 sends a 0 len decrypt request to the engine, and the engine returns an error, causing this API to return 0.
        /// Conversely, OpenSSL 1.1.1 checks for 0 len and returns 1 before sending the request to the engine.
#ifdef OPENSSL_3
        REQUIRE(aes_ctx.auth_decrypt(cipher_data.data(), cipher_data.size(), iv.data(), aad, recovered_data) == 0);
#else
        REQUIRE(aes_ctx.auth_decrypt(cipher_data.data(), cipher_data.size(), iv.data(), aad, recovered_data) == 1);
#endif

        // REQUIRE(recovered_data.empty());
    }

    SECTION("AES-GCM Encrypt/Decrypt with Large Plaintext Size")
    {
        AziHsmAesCipherCtx aes_ctx;
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        size_t max_size = 1 << 20; // 1MB example
        std::vector<unsigned char> plain_data(max_size, 'A'), cipher_data, recovered_data, iv(12), tag(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

        REQUIRE(aes_ctx.auth_encrypt(plain_data.data(), plain_data.size(), iv.data(), {}, cipher_data) == 1);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);
        REQUIRE(aes_ctx.auth_decrypt(cipher_data.data(), cipher_data.size(), iv.data(), {}, recovered_data) == 1);

        REQUIRE(plain_data == recovered_data);
    }

    SECTION("AES-GCM Double Encryption/Decryption Check")
    {
        AziHsmAesCipherCtx aes_ctx;
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        std::vector<unsigned char> plain_data(128, 'C'), cipher_data1, recovered_data1, cipher_data2, iv(12), tag(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

        // First encryption
        REQUIRE(aes_ctx.auth_encrypt(plain_data.data(), plain_data.size(), iv.data(), {}, cipher_data1) == 1);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);

        // Decryption of first cipher text
        REQUIRE(aes_ctx.auth_decrypt(cipher_data1.data(), cipher_data1.size(), iv.data(), {}, recovered_data1) == 1);
        REQUIRE(plain_data == recovered_data1);

        // Second encryption of recovered data
        REQUIRE(aes_ctx.auth_encrypt(recovered_data1.data(), recovered_data1.size(), iv.data(), {}, cipher_data2) == 1);
        REQUIRE(cipher_data1 == cipher_data2);
    }

    SECTION("Encrypt/decrypt with a wrapped key")
    {
        // Generate random IV
        std::vector<unsigned char> iv(16);
        REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx.init(e, NID_aes_256_gcm, 1, nullptr, iv.data()) == 1);
        setup_key(aes_ctx, azihsm_engine, false);

        // Padding is enabled. So account for an extra block size in the data
        std::vector<unsigned char> plain_data(1008);
        std::vector<unsigned char> cipher_data;
        std::vector<unsigned char> recovered_data;
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        REQUIRE(aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data) == 1);
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);
    }
#else
    SECTION("Test AES-GCM encrypt/decrypt with builtin implementation")
    {
        // Allocate CTX
        AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

        // Init ctx with key for encrypting
        REQUIRE(aes_ctx.init(nullptr, NID_aes_256_gcm, 1, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.keygen(1) == 1);

        const unsigned char *plain_text = (const unsigned char *)"A secret is a secret until it's not until it is ";
        int ptext_len = strlen((const char *)plain_text);
        std::vector<unsigned char> cipher_text(ptext_len);
        std::vector<unsigned char> recovered_text(ptext_len);
        std::vector<unsigned char> tag;
        int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
        std::vector<unsigned char> iv(iv_len);
        std::vector<unsigned char> aad(AZIHSM_AES_GCM_AAD_SIZE);

        REQUIRE(RAND_bytes(iv.data(), iv_len) == 1);
        REQUIRE(RAND_bytes(aad.data(), AZIHSM_AES_GCM_AAD_SIZE) == 1);

        // set AAD and encrypt
        REQUIRE(aes_ctx.auth_encrypt(plain_text, ptext_len, iv.data(), aad, cipher_text) == 1);

        // Get tag.
        tag.resize(AZIHSM_AES_GCM_TAG_SIZE);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_GET_TAG, tag.size(), tag) == 1);

        // Reinit for decrypting
        REQUIRE(aes_ctx.init(nullptr, NID_aes_256_gcm, 0, nullptr, nullptr) == 1);
        REQUIRE(aes_ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, AZIHSM_AES_GCM_TAG_SIZE, tag) == 1);

        // set AAD and decrypt
        REQUIRE(aes_ctx.auth_decrypt(cipher_text.data(), cipher_text.size(), iv.data(), aad, recovered_text) == 1);

        // Compare
        REQUIRE(std::memcmp(plain_text, recovered_text.data(), ptext_len) == 0);
    }

#endif // AZIHSM_GCM
}

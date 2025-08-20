// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmCiphers.hpp"
#include <catch2/catch_test_macros.hpp>
#include <stdexcept>
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
        int nid_type = aes_ctx.getNid();
        size_t key_size;
        switch (nid_type)
        {
        case NID_aes_128_cbc:
            key_size = 16;
            break;
        case NID_aes_192_cbc:
            key_size = 24;
            break;
        case NID_aes_256_cbc:
            key_size = 32;
            break;
        default:
            throw std::runtime_error("Invalid cipher type");
        }
        std::vector<unsigned char> aes_key(key_size);
        REQUIRE(RAND_bytes(aes_key.data(), aes_key.size()) == 1);

        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        REQUIRE(unwrapping_key.size() > 0);

        // Create wrapped data
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, aes_key);
        REQUIRE(wrapped_blob.size() > 0);

        // Import key
        REQUIRE(azihsm_engine.unwrapAes(aes_ctx.getCtx(), nid_type, wrapped_blob) == 1);
    }
}

// Combined function to initialize the engine, context, generate the IV, prepare the plain data, and perform encryption
static int initialize_and_encrypt(
    int nid_type,
    int data_size,
    AziHsmAesCipherCtx &aes_ctx,
    std::vector<unsigned char> &iv,
    std::vector<unsigned char> &plain_data,
    std::vector<unsigned char> &cipher_data,
    ENGINE *&e,
    bool use_unaligned_data = false,
    bool keygen = true)
{
    // Initialize the engine
    AziHsmEngine azihsm_engine = get_test_engine();
    e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    // Initialize the context and generate an IV
    REQUIRE(aes_ctx.init(e, nid_type, 1, nullptr, iv.data()) == 1);
    setup_key(aes_ctx, azihsm_engine, keygen);

    int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
    iv.resize(iv_len);
    REQUIRE(RAND_bytes(iv.data(), iv.size()) == 1);

    // Prepare the plain data buffer
    const unsigned char *unaligned_text = reinterpret_cast<const unsigned char *>(
        "All we have to decide is what to do with the time that is given us.");

    if (use_unaligned_data)
    {
        // Use unaligned data
        int ptext_len = strlen(reinterpret_cast<const char *>(unaligned_text));
        plain_data.assign(unaligned_text, unaligned_text + ptext_len);
    }
    else
    {
        // Use standard aligned data
        plain_data.resize(data_size);
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);
    }

    // Encrypt the data

    return aes_ctx.encrypt(plain_data.data(), plain_data.size(), iv.data(), cipher_data);
}

// Helper function to perform decryption and validate the recovered data
static void decrypt_and_validate(
    AziHsmAesCipherCtx &aes_ctx,
    const std::vector<unsigned char> &cipher_data,
    const std::vector<unsigned char> &iv,
    const std::vector<unsigned char> &plain_data,
    bool decrypt_success_flag = true)
{
    std::vector<unsigned char> recovered_data;
    if (decrypt_success_flag)
    {
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1);
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) == 0);
    }
    else
    {
        REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 0);
    }
}

// Function for handling decryption with a copied context
void decrypt_with_copied_context(
    int nid_type,
    int data_size,
    bool use_unaligned_data = false,
    bool keygen = true)
{
    // Combined initialization and encryption
    AziHsmAesCipherCtx aes_ctx;
    std::vector<unsigned char> iv, plain_data, cipher_data;
    ENGINE *e = nullptr;
    int ret = initialize_and_encrypt(
        nid_type, data_size, aes_ctx, iv, plain_data, cipher_data, e, use_unaligned_data, keygen);

    if (data_size <= 1024)
    {
        REQUIRE(ret == 1);
    }
    else
    {
        REQUIRE(ret == 0);
        return;
    }

    // Copy the original context
    AziHsmAesCipherCtx aes_ctx_copy;
    REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);

    // Decrypt using the copied context and validate
    bool decrypt_flag = (data_size < 1024);

    decrypt_and_validate(aes_ctx_copy, cipher_data, iv, plain_data, decrypt_flag);
}

// Function for handling decryption with the wrong IV
static void decrypt_with_wrong_iv(int nid_type, int data_size)
{
    // Combined initialization and encryption
    AziHsmAesCipherCtx aes_ctx;
    std::vector<unsigned char> iv, plain_data, cipher_data;
    ENGINE *e = nullptr;
    REQUIRE(initialize_and_encrypt(nid_type, data_size, aes_ctx, iv, plain_data, cipher_data, e) == 1);

    int iv_len = EVP_CIPHER_CTX_iv_length(aes_ctx.getCtx());
    // Use a different IV
    std::vector<unsigned char> new_iv(iv_len);
    REQUIRE(RAND_bytes(new_iv.data(), new_iv.size()) == 1);

    // Decrypt using the wrong IV and validate that the data does not match
    std::vector<unsigned char> recovered_data;
    REQUIRE(aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), new_iv.data(), recovered_data) == 1);
    REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) != 0);
}

// Function for handling decryption with the wrong key
static void decrypt_with_wrong_key(int nid_type, int data_size)
{
    // Combined initialization and encryption
    AziHsmAesCipherCtx aes_ctx;
    std::vector<unsigned char> iv, plain_data, cipher_data;
    ENGINE *e = nullptr;
    REQUIRE(initialize_and_encrypt(nid_type, data_size, aes_ctx, iv, plain_data, cipher_data, e) == 1);

    // Reinitialize the context with a different key
    REQUIRE(aes_ctx.init(e, nid_type, 1, nullptr, nullptr) == 1);
    REQUIRE(aes_ctx.keygen(1) == 1);

    // Decrypt with the wrong key and validate that the data does not match
    std::vector<unsigned char> recovered_data;
    if (aes_ctx.decrypt(cipher_data.data(), cipher_data.size(), iv.data(), recovered_data) == 1)
    {
        REQUIRE(std::memcmp(plain_data.data(), recovered_data.data(), plain_data.size()) != 0);
    }
}

// Main function for a standard AES CBC test with an option for unaligned data
void run_standard_aes_cbc_test(
    int nid_type,
    int data_size,
    bool use_unaligned_data = false,
    bool keygen = true)
{
    // Combined initialization and encryption with the unaligned data flag
    AziHsmAesCipherCtx aes_ctx;
    std::vector<unsigned char> iv, plain_data, cipher_data;
    ENGINE *e = nullptr;
    int ret = initialize_and_encrypt(
        nid_type, data_size, aes_ctx, iv, plain_data, cipher_data, e, use_unaligned_data, keygen);

    if (data_size <= 1024)
    {
        REQUIRE(ret == 1);
    }
    else
    {
        REQUIRE(ret == 0);
        return;
    }

    // Decrypt and validate
    bool decrypt_flag = (data_size < 1024);
    decrypt_and_validate(aes_ctx, cipher_data, iv, plain_data, decrypt_flag);
}

TEST_CASE("AZIHSM AES CBC Ciphers ctx init", "[AziHsmAesCbcInit]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const EVP_CIPHER *cipher;
    // Allocate CTX
    AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();

    SECTION("Test AES-CBC init ctx with deleted key")
    {
        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, nullptr) == 1);
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

        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, old_key_copy.data(), nullptr) == 0);
    }

    SECTION("Test AES Empty Ctx copy")
    {
        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, nullptr) == 1);

        // Copy CTX
        AziHsmAesCipherCtx aes_ctx_copy = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);
    }

    SECTION("Test AES-CBC Ctx Copy")
    {
        REQUIRE(aes_ctx.init(e, NID_aes_128_cbc, 1, nullptr, nullptr) == 1);
        setup_key(aes_ctx, azihsm_engine, true);

        // Copy CTX
        AziHsmAesCipherCtx aes_ctx_copy = AziHsmAesCipherCtx();
        REQUIRE(aes_ctx_copy.copy(aes_ctx) == 1);
    }
}

TEST_CASE("AZIHSM AES CBC Ciphers", "[AziHsmAesCbc]")
{
    // Test cases for AES-128-CBC with different scenarios
    SECTION("AES-128-CBC with Different Data Sizes and Scenarios")
    {
        int nid = NID_aes_128_cbc;

        // Standard tests

        run_standard_aes_cbc_test(nid, 128);
        run_standard_aes_cbc_test(nid, 512);
        // need to take account of the padding of block size of 16, 1008 1024-16
        run_standard_aes_cbc_test(nid, 1008);

        run_standard_aes_cbc_test(nid, 1024);

        // Unwrap
        run_standard_aes_cbc_test(nid, 128, false, false);

        // invalid data len
        run_standard_aes_cbc_test(nid, 2048);

        // Test with unaligned data
        run_standard_aes_cbc_test(nid, 0, true);

        // Test with wrong key scenario
        decrypt_with_wrong_key(nid, 128);

        // Test with wrong IV scenario
        decrypt_with_wrong_iv(nid, 128);

        // Test with copied context
        //
        decrypt_with_copied_context(nid, 128);
        decrypt_with_copied_context(nid, 512);
        decrypt_with_copied_context(nid, 1008);

        decrypt_with_copied_context(nid, 1024);

        decrypt_with_copied_context(nid, 2048);

        // unaligned data
        decrypt_with_copied_context(nid, 0, true);
    }

    // Test cases for AES-192-CBC with different scenarios
    SECTION("AES-192-CBC with Different Data Sizes and Scenarios")
    {
        int nid = NID_aes_192_cbc;
        // Standard tests

        run_standard_aes_cbc_test(nid, 128);
        run_standard_aes_cbc_test(nid, 512);
        // need to take account of the padding of block size of 16, 1008 1024-16
        run_standard_aes_cbc_test(nid, 1008);

        run_standard_aes_cbc_test(nid, 1024);

        // Unwrap
        run_standard_aes_cbc_test(nid, 128, false, false);

        // invalid data len
        run_standard_aes_cbc_test(nid, 2048);

        // Test with unaligned data
        run_standard_aes_cbc_test(nid, 0, true);

        // Test with wrong key scenario
        decrypt_with_wrong_key(nid, 128);

        // Test with wrong IV scenario
        decrypt_with_wrong_iv(nid, 128);

        // Test with copied context
        //
        decrypt_with_copied_context(nid, 128);
        decrypt_with_copied_context(nid, 512);
        decrypt_with_copied_context(nid, 1008);

        decrypt_with_copied_context(nid, 1024);

        decrypt_with_copied_context(nid, 2048);

        // unaligned data
        decrypt_with_copied_context(nid, 0, true);
    }

    // Test cases for AES-256-CBC with different scenarios
    SECTION("AES-256-CBC with Different Data Sizes and Scenarios")
    {
        int nid = NID_aes_256_cbc;
        // Standard tests

        run_standard_aes_cbc_test(nid, 128);
        run_standard_aes_cbc_test(nid, 512);
        // need to take account of the padding of block size of 16, 1008 1024-16
        run_standard_aes_cbc_test(nid, 1008);

        run_standard_aes_cbc_test(nid, 1024);

        // Unwrap
        run_standard_aes_cbc_test(nid, 128, false, false);

        // invalid data len
        run_standard_aes_cbc_test(nid, 2048);

        // Test with unaligned data
        run_standard_aes_cbc_test(nid, 0, true);

        // Test with wrong key scenario
        decrypt_with_wrong_key(nid, 128);

        // Test with wrong IV scenario
        decrypt_with_wrong_iv(nid, 128);

        // Test with copied context
        //
        decrypt_with_copied_context(nid, 128);
        decrypt_with_copied_context(nid, 512);
        decrypt_with_copied_context(nid, 1008);

        decrypt_with_copied_context(nid, 1024);

        decrypt_with_copied_context(nid, 2048);

        // unaligned data
        decrypt_with_copied_context(nid, 0, true);
    }
}

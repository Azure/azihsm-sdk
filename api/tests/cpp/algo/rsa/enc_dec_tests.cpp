// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/key_import.hpp"
#include "utils/key_props.hpp"
#include "utils/rsa_keygen.hpp"

class azihsm_rsa_encrypt_decrypt : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Imports the hardcoded RSA-2048 key pair as an encrypt/decrypt key using RSA key unwrap.
static azihsm_status import_unwrapped_rsa_keypair_for_enc_dec(
    azihsm_handle session,
    const key_props &import_props,
    auto_key &unwrapped_priv_key,
    auto_key &unwrapped_pub_key
)
{
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;

    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );

    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    if (wrapping_priv_key.get() == 0 || wrapping_pub_key.get() == 0)
    {
        return AZIHSM_STATUS_INVALID_KEY;
    }

    return import_keypair(
        wrapping_pub_key.get(),
        wrapping_priv_key.get(),
        rsa_private_key_der,
        import_props,
        unwrapped_priv_key.get_ptr(),
        unwrapped_pub_key.get_ptr()
    );
}

// Builds an RSA PKCS#1 v1.5 encryption/decryption algorithm descriptor.
static azihsm_algo make_rsa_pkcs_algo()
{
    azihsm_algo algo = {};
    algo.id = AZIHSM_ALGO_ID_RSA_PKCS;
    algo.params = nullptr;
    algo.len = 0;
    return algo;
}

// Builds RSA OAEP parameters using SHA-256 for both OAEP hash and MGF1 hash.
static azihsm_algo_rsa_pkcs_oaep_params make_oaep_sha256_params()
{
    azihsm_algo_rsa_pkcs_oaep_params params = {};
    params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    params.label = nullptr;
    return params;
}

// Builds RSA OAEP parameters using SHA-384 for both OAEP hash and MGF1 hash.
static azihsm_algo_rsa_pkcs_oaep_params make_oaep_sha384_params()
{
    azihsm_algo_rsa_pkcs_oaep_params params = {};
    params.hash_algo_id = AZIHSM_ALGO_ID_SHA384;
    params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA384;
    params.label = nullptr;
    return params;
}

// Builds RSA OAEP parameters using SHA-1 for both OAEP hash and MGF1 hash.
static azihsm_algo_rsa_pkcs_oaep_params make_oaep_sha1_params()
{
    azihsm_algo_rsa_pkcs_oaep_params params = {};
    params.hash_algo_id = AZIHSM_ALGO_ID_SHA1;
    params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA1;
    params.label = nullptr;
    return params;
}

// Builds RSA OAEP parameters using SHA-512 for both OAEP hash and MGF1 hash.
static azihsm_algo_rsa_pkcs_oaep_params make_oaep_sha512_params()
{
    azihsm_algo_rsa_pkcs_oaep_params params = {};
    params.hash_algo_id = AZIHSM_ALGO_ID_SHA512;
    params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA512;
    params.label = nullptr;
    return params;
}

// Builds an RSA OAEP algorithm descriptor from the provided OAEP parameters.
static azihsm_algo make_oaep_algo(azihsm_algo_rsa_pkcs_oaep_params &params)
{
    azihsm_algo algo = {};
    algo.id = AZIHSM_ALGO_ID_RSA_PKCS_OAEP;
    algo.params = &params;
    algo.len = sizeof(params);
    return algo;
}

// Builds RSA-2048 import properties with configurable encrypt/decrypt usage flags.
static key_props rsa_import_props(bool encrypt, bool decrypt)
{
    key_props props = {
        .key_kind = AZIHSM_KEY_KIND_RSA,
        .key_size_bits = 2048,
        .session_key = true,
        .sign = false,
        .verify = false,
        .encrypt = encrypt,
        .decrypt = decrypt,
    };
    return props;
}

// Verifies RSA OAEP encrypt/decrypt round-trip succeeds with an unwrapped RSA key pair.
TEST_F(azihsm_rsa_encrypt_decrypt, encrypt_decrypt_oaep_with_unwrapped_key)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        auto_key unwrapped_priv_key;
        auto_key unwrapped_pub_key;
        key_props import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = false,
            .verify = false,
            .encrypt = true,
            .decrypt = true,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            unwrapped_priv_key.get_ptr(),
            unwrapped_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unwrapped_priv_key.get(), 0);
        ASSERT_NE(unwrapped_pub_key.get(), 0);

        // Step 3: Encrypt test data with the unwrapped public key
        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        azihsm_algo_rsa_pkcs_oaep_params encrypt_oaep_params = {};
        encrypt_oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        encrypt_oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
        encrypt_oaep_params.label = nullptr;

        azihsm_algo encrypt_algo = {};
        encrypt_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_OAEP;
        encrypt_algo.params = &encrypt_oaep_params;
        encrypt_algo.len = sizeof(encrypt_oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256); // RSA 2048 = 256 bytes
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err =
            azihsm_crypt_encrypt(&encrypt_algo, unwrapped_pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        // Step 4: Decrypt the ciphertext with the unwrapped private key
        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(
            &encrypt_algo,
            unwrapped_priv_key,
            &ciphertext_buf,
            &decrypted_buf
        );
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        // Step 6: Verify the decrypted data matches the original plaintext
        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(unwrapped_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_STATUS_SUCCESS);
        auto del_pub_err = azihsm_key_delete(unwrapped_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_STATUS_SUCCESS);
    });
}

// Verifies RSA PKCS#1 v1.5 encrypt/decrypt round-trip succeeds with an unwrapped RSA key pair.
TEST_F(azihsm_rsa_encrypt_decrypt, encrypt_decrypt_pkcs1_with_unwrapped_key)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        auto_key unwrapped_priv_key;
        auto_key unwrapped_pub_key;
        key_props import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = false,
            .verify = false,
            .encrypt = true,
            .decrypt = true,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            unwrapped_priv_key.get_ptr(),
            unwrapped_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unwrapped_priv_key.get(), 0);
        ASSERT_NE(unwrapped_pub_key.get(), 0);

        // Step 3: Encrypt test data with the unwrapped public key
        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        azihsm_algo encrypt_algo = {};
        encrypt_algo.id = AZIHSM_ALGO_ID_RSA_PKCS;
        encrypt_algo.params = nullptr;
        encrypt_algo.len = 0;

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256); // RSA 2048 = 256 bytes
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err =
            azihsm_crypt_encrypt(&encrypt_algo, unwrapped_pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        // Step 4: Decrypt the ciphertext with the unwrapped private key
        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(
            &encrypt_algo,
            unwrapped_priv_key,
            &ciphertext_buf,
            &decrypted_buf
        );
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        // Step 6: Verify the decrypted data matches the original plaintext
        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(unwrapped_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_STATUS_SUCCESS);
        auto del_pub_err = azihsm_key_delete(unwrapped_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_STATUS_SUCCESS);
    });
}

// Verifies RSA OAEP SHA-256 encryption rejects plaintext larger than the RSA-2048 OAEP limit.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_sha256_plaintext_too_large_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);

        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);

        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // One byte over RSA-2048 OAEP SHA-256 max plaintext.
        std::vector<uint8_t> plaintext_data(191, 0x41);

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_INTERNAL_ERROR);
    });
}

// Verifies RSA PKCS#1 v1.5 encryption rejects plaintext larger than the RSA-2048 PKCS#1 limit.
TEST_F(azihsm_rsa_encrypt_decrypt, pkcs1_plaintext_too_large_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);

        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // One byte over RSA-2048 PKCS#1 v1.5 max plaintext.
        std::vector<uint8_t> plaintext_data(246, 0x42);

        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_INTERNAL_ERROR);
    });
}

// Verifies RSA encryption rejects a ciphertext output buffer smaller than the RSA modulus size.
TEST_F(azihsm_rsa_encrypt_decrypt, encrypt_rejects_small_ciphertext_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);

        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        const char *plaintext = "small buffer test";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        // RSA-2048 ciphertext must be 256 bytes, so this should be too small.
        std::vector<uint8_t> ciphertext_data(255);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(ciphertext_buf.len, 256u);
    });
}

// Verifies RSA decryption rejects a plaintext output buffer that is too small.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_rejects_small_plaintext_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);

        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        // One byte too small for the required RSA-2048 plaintext output buffer (modulus size).
        std::vector<uint8_t> decrypted_data(255);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(decrypted_buf.len, 256u);
    });
}

// Verifies RSA OAEP decryption rejects ciphertext modified after encryption.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_rejects_corrupted_oaep_ciphertext)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);

        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        // Flip one byte after encryption.
        ciphertext_data[0] ^= 0x01;

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INTERNAL_ERROR);
    });
}

// Verifies RSA OAEP decryption rejects ciphertext decrypted with a different OAEP hash.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_rejects_oaep_hash_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto encrypt_params = make_oaep_sha256_params();
        auto encrypt_algo = make_oaep_algo(encrypt_params);

        auto decrypt_params = make_oaep_sha384_params();
        auto decrypt_algo = make_oaep_algo(decrypt_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err =
            azihsm_crypt_encrypt(&encrypt_algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err =
            azihsm_crypt_decrypt(&decrypt_algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INTERNAL_ERROR);
    });
}

// Verifies RSA decryption rejects using the public key instead of the private key.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_with_public_key_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, pub_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// Verifies RSA OAEP SHA-256 accepts plaintext at the maximum RSA-2048 OAEP limit.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_sha256_max_plaintext_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        // RSA-2048 OAEP SHA-256 max plaintext:
        // k - 2*hLen - 2 = 256 - 2*32 - 2 = 190 bytes.
        std::vector<uint8_t> plaintext_data(190, 0x41);

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_buf.len, 256u);

        // Use modulus-sized output buffer. The API appears to require 256 bytes
        // even though the final plaintext length is only 190 bytes.
        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

// Verifies RSA PKCS#1 v1.5 accepts plaintext at the maximum RSA-2048 PKCS#1 limit.
TEST_F(azihsm_rsa_encrypt_decrypt, pkcs1_max_plaintext_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // RSA-2048 PKCS#1 v1.5 max plaintext:
        // k - 11 = 256 - 11 = 245 bytes.
        std::vector<uint8_t> plaintext_data(245, 0x42);

        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_buf.len, 256u);

        // Use modulus-sized output buffer. The API appears to require 256 bytes
        // even though the final plaintext length is only 245 bytes.
        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

// Verifies RSA PKCS#1 v1.5 supports encrypting and decrypting empty plaintext.
TEST_F(azihsm_rsa_encrypt_decrypt, pkcs1_empty_plaintext_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> plaintext_data;

        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};

        plaintext_buf.ptr = plaintext_data.empty() ? nullptr : plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_buf.len, 256u);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, 0u);
    });
}

// Verifies RSA decryption rejects an empty ciphertext buffer.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_rejects_empty_ciphertext)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = nullptr;
        ciphertext_buf.len = 0;

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies RSA decryption rejects ciphertext shorter than the RSA modulus size.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_rejects_truncated_ciphertext)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        const char *plaintext = "truncate test";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        ciphertext_buf.len -= 1;

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies RSA decryption rejects ciphertext when decrypted with a mismatched padding scheme.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_rejects_wrong_padding_scheme)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
        const char *plaintext = "padding mismatch";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto encrypt_algo = make_rsa_pkcs_algo();

        auto oaep_params = make_oaep_sha256_params();
        auto decrypt_algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err =
            azihsm_crypt_encrypt(&encrypt_algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err =
            azihsm_crypt_decrypt(&decrypt_algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INTERNAL_ERROR);
    });
}

// Verifies RSA PKCS#1 v1.5 encryption produces different ciphertexts for the same plaintext.
TEST_F(azihsm_rsa_encrypt_decrypt, pkcs1_encryption_is_non_deterministic)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "same input";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_one(256);
        azihsm_buffer ciphertext_one_buf = {};
        ciphertext_one_buf.ptr = ciphertext_one.data();
        ciphertext_one_buf.len = static_cast<uint32_t>(ciphertext_one.size());

        std::vector<uint8_t> ciphertext_two(256);
        azihsm_buffer ciphertext_two_buf = {};
        ciphertext_two_buf.ptr = ciphertext_two.data();
        ciphertext_two_buf.len = static_cast<uint32_t>(ciphertext_two.size());

        auto encrypt_one_err =
            azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_one_buf);
        ASSERT_EQ(encrypt_one_err, AZIHSM_STATUS_SUCCESS);

        auto encrypt_two_err =
            azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_two_buf);
        ASSERT_EQ(encrypt_two_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(ciphertext_one_buf.len, ciphertext_two_buf.len);
        ASSERT_NE(
            0,
            memcmp(ciphertext_one_buf.ptr, ciphertext_two_buf.ptr, ciphertext_one_buf.len)
        );
    });
}

// Verifies RSA OAEP encryption produces different ciphertexts for the same plaintext.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_encryption_is_non_deterministic)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "same input";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto oaep_params = make_oaep_sha256_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_one(256);
        azihsm_buffer ciphertext_one_buf = {};
        ciphertext_one_buf.ptr = ciphertext_one.data();
        ciphertext_one_buf.len = static_cast<uint32_t>(ciphertext_one.size());

        std::vector<uint8_t> ciphertext_two(256);
        azihsm_buffer ciphertext_two_buf = {};
        ciphertext_two_buf.ptr = ciphertext_two.data();
        ciphertext_two_buf.len = static_cast<uint32_t>(ciphertext_two.size());

        auto encrypt_one_err =
            azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_one_buf);
        ASSERT_EQ(encrypt_one_err, AZIHSM_STATUS_SUCCESS);

        auto encrypt_two_err =
            azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_two_buf);
        ASSERT_EQ(encrypt_two_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(ciphertext_one_buf.len, ciphertext_two_buf.len);
        ASSERT_NE(
            0,
            memcmp(ciphertext_one_buf.ptr, ciphertext_two_buf.ptr, ciphertext_one_buf.len)
        );
    });
}

// Verifies the same RSA key pair can be used independently with PKCS#1 v1.5 and OAEP.
TEST_F(azihsm_rsa_encrypt_decrypt, same_key_supports_pkcs1_and_oaep)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *pkcs_plaintext = "pkcs1";
        std::vector<uint8_t> pkcs_plaintext_data(
            pkcs_plaintext,
            pkcs_plaintext + strlen(pkcs_plaintext)
        );

        auto pkcs_algo = make_rsa_pkcs_algo();

        azihsm_buffer pkcs_plaintext_buf = {};
        pkcs_plaintext_buf.ptr = pkcs_plaintext_data.data();
        pkcs_plaintext_buf.len = static_cast<uint32_t>(pkcs_plaintext_data.size());

        std::vector<uint8_t> pkcs_ciphertext_data(256);
        azihsm_buffer pkcs_ciphertext_buf = {};
        pkcs_ciphertext_buf.ptr = pkcs_ciphertext_data.data();
        pkcs_ciphertext_buf.len = static_cast<uint32_t>(pkcs_ciphertext_data.size());

        auto pkcs_encrypt_err =
            azihsm_crypt_encrypt(&pkcs_algo, pub_key, &pkcs_plaintext_buf, &pkcs_ciphertext_buf);
        ASSERT_EQ(pkcs_encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> pkcs_decrypted_data(256);
        azihsm_buffer pkcs_decrypted_buf = {};
        pkcs_decrypted_buf.ptr = pkcs_decrypted_data.data();
        pkcs_decrypted_buf.len = static_cast<uint32_t>(pkcs_decrypted_data.size());

        auto pkcs_decrypt_err =
            azihsm_crypt_decrypt(&pkcs_algo, priv_key, &pkcs_ciphertext_buf, &pkcs_decrypted_buf);
        ASSERT_EQ(pkcs_decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(pkcs_decrypted_buf.len, pkcs_plaintext_buf.len);
        ASSERT_EQ(
            0,
            memcmp(pkcs_decrypted_buf.ptr, pkcs_plaintext_buf.ptr, pkcs_decrypted_buf.len)
        );

        const char *oaep_plaintext = "oaep";
        std::vector<uint8_t> oaep_plaintext_data(
            oaep_plaintext,
            oaep_plaintext + strlen(oaep_plaintext)
        );

        auto oaep_params = make_oaep_sha256_params();
        auto oaep_algo = make_oaep_algo(oaep_params);

        azihsm_buffer oaep_plaintext_buf = {};
        oaep_plaintext_buf.ptr = oaep_plaintext_data.data();
        oaep_plaintext_buf.len = static_cast<uint32_t>(oaep_plaintext_data.size());

        std::vector<uint8_t> oaep_ciphertext_data(256);
        azihsm_buffer oaep_ciphertext_buf = {};
        oaep_ciphertext_buf.ptr = oaep_ciphertext_data.data();
        oaep_ciphertext_buf.len = static_cast<uint32_t>(oaep_ciphertext_data.size());

        auto oaep_encrypt_err =
            azihsm_crypt_encrypt(&oaep_algo, pub_key, &oaep_plaintext_buf, &oaep_ciphertext_buf);
        ASSERT_EQ(oaep_encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> oaep_decrypted_data(256);
        azihsm_buffer oaep_decrypted_buf = {};
        oaep_decrypted_buf.ptr = oaep_decrypted_data.data();
        oaep_decrypted_buf.len = static_cast<uint32_t>(oaep_decrypted_data.size());

        auto oaep_decrypt_err =
            azihsm_crypt_decrypt(&oaep_algo, priv_key, &oaep_ciphertext_buf, &oaep_decrypted_buf);
        ASSERT_EQ(oaep_decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(oaep_decrypted_buf.len, oaep_plaintext_buf.len);
        ASSERT_EQ(
            0,
            memcmp(oaep_decrypted_buf.ptr, oaep_plaintext_buf.ptr, oaep_decrypted_buf.len)
        );
    });
}

// Verifies the same RSA ciphertext can be decrypted successfully more than once.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_same_ciphertext_twice_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "repeat decrypt";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_one(256);
        azihsm_buffer decrypted_one_buf = {};
        decrypted_one_buf.ptr = decrypted_one.data();
        decrypted_one_buf.len = static_cast<uint32_t>(decrypted_one.size());

        auto decrypt_one_err =
            azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_one_buf);
        ASSERT_EQ(decrypt_one_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_two(256);
        azihsm_buffer decrypted_two_buf = {};
        decrypted_two_buf.ptr = decrypted_two.data();
        decrypted_two_buf.len = static_cast<uint32_t>(decrypted_two.size());

        auto decrypt_two_err =
            azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_two_buf);
        ASSERT_EQ(decrypt_two_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_one_buf.len, plaintext_buf.len);
        ASSERT_EQ(decrypted_two_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_one_buf.ptr, plaintext_buf.ptr, decrypted_one_buf.len));
        ASSERT_EQ(0, memcmp(decrypted_two_buf.ptr, plaintext_buf.ptr, decrypted_two_buf.len));
    });
}

// Verifies RSA decryption succeeds when using a fresh algorithm descriptor instance.
TEST_F(azihsm_rsa_encrypt_decrypt, decrypt_with_new_algo_instance_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "stateless test";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto encrypt_algo = make_rsa_pkcs_algo();
        auto decrypt_algo = make_rsa_pkcs_algo();

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err =
            azihsm_crypt_encrypt(&encrypt_algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err =
            azihsm_crypt_decrypt(&decrypt_algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

// Verifies RSA OAEP SHA-512 encrypt/decrypt round-trip succeeds.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_sha512_encrypt_decrypt_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "oaep sha512";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto oaep_params = make_oaep_sha512_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

// Verifies RSA OAEP SHA-512 accepts plaintext at the maximum RSA-2048 OAEP limit.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_sha512_max_plaintext_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // RSA-2048 OAEP SHA512 max plaintext:
        // 256 - 2*64 - 2 = 126 bytes.
        std::vector<uint8_t> plaintext_data(126, 0x42);

        auto oaep_params = make_oaep_sha512_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

// Verifies RSA OAEP SHA-512 encryption rejects plaintext larger than the hash-dependent OAEP limit.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_sha512_plaintext_too_large_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // One byte over RSA-2048 OAEP SHA512 max plaintext.
        std::vector<uint8_t> plaintext_data(127, 0x42);

        auto oaep_params = make_oaep_sha512_params();
        auto algo = make_oaep_algo(oaep_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_INTERNAL_ERROR);
    });
}

// Verifies RSA OAEP decryption rejects ciphertext when decrypt parameters use an unsupported or
// mismatched SHA-1 hash.
TEST_F(azihsm_rsa_encrypt_decrypt, oaep_sha512_to_sha1_hash_mismatch_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto props = rsa_import_props(true, true);
        auto import_err =
            import_unwrapped_rsa_keypair_for_enc_dec(session, props, priv_key, pub_key);
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *plaintext = "oaep sha512 sha1 mismatch";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        auto encrypt_params = make_oaep_sha512_params();
        auto encrypt_algo = make_oaep_algo(encrypt_params);

        auto decrypt_params = make_oaep_sha1_params();
        auto decrypt_algo = make_oaep_algo(decrypt_params);

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err =
            azihsm_crypt_encrypt(&encrypt_algo, pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err =
            azihsm_crypt_decrypt(&decrypt_algo, priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

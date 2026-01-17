// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils.hpp"

class azihsm_rsa_encrypt_decrypt : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_rsa_encrypt_decrypt, encrypt_decrypt_oaep_with_unwrapped_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err =
            generate_rsa_unwrapping_keypair(session.get(), wrapping_priv_key.get_ptr(), wrapping_pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey unwrapped_priv_key;
        AutoKey unwrapped_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = false,
            .verify = false,
            .encrypt = true,
            .decrypt = true,
        };
        auto import_err = import_keypair(wrapping_pub_key.get(), wrapping_priv_key.get(), rsa_private_key_der,
                                         import_props, unwrapped_priv_key.get_ptr(), unwrapped_pub_key.get_ptr());
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
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

        auto encrypt_err = azihsm_crypt_encrypt(&encrypt_algo, unwrapped_pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_ERROR_SUCCESS);

        // Step 4: Decrypt the ciphertext with the unwrapped private key
        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&encrypt_algo, unwrapped_priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_ERROR_SUCCESS);

        // Step 6: Verify the decrypted data matches the original plaintext
        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(unwrapped_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(unwrapped_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_rsa_encrypt_decrypt, encrypt_decrypt_pkcs1_with_unwrapped_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err =
            generate_rsa_unwrapping_keypair(session.get(), wrapping_priv_key.get_ptr(), wrapping_pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey unwrapped_priv_key;
        AutoKey unwrapped_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = false,
            .verify = false,
            .encrypt = true,
            .decrypt = true,
        };
        auto import_err = import_keypair(wrapping_pub_key.get(), wrapping_priv_key.get(), rsa_private_key_der,
                                         import_props, unwrapped_priv_key.get_ptr(), unwrapped_pub_key.get_ptr());
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(unwrapped_priv_key.get(), 0);
        ASSERT_NE(unwrapped_pub_key.get(), 0);

        // Step 3: Encrypt test data with the unwrapped public key
        const char *plaintext = "Hello, RSA encryption!";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + strlen(plaintext));

        azihsm_algo encrypt_algo = {};
        encrypt_algo.id = AZIHSM_ALGO_ID_RSA_PKCS; // [TODO] Confirm the algorithm ID
        encrypt_algo.params = nullptr;
        encrypt_algo.len = 0;

        azihsm_buffer plaintext_buf = {};
        plaintext_buf.ptr = plaintext_data.data();
        plaintext_buf.len = static_cast<uint32_t>(plaintext_data.size());

        std::vector<uint8_t> ciphertext_data(256); // RSA 2048 = 256 bytes
        azihsm_buffer ciphertext_buf = {};
        ciphertext_buf.ptr = ciphertext_data.data();
        ciphertext_buf.len = static_cast<uint32_t>(ciphertext_data.size());

        auto encrypt_err = azihsm_crypt_encrypt(&encrypt_algo, unwrapped_pub_key, &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(encrypt_err, AZIHSM_ERROR_SUCCESS);

        // Step 4: Decrypt the ciphertext with the unwrapped private key
        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf = {};
        decrypted_buf.ptr = decrypted_data.data();
        decrypted_buf.len = static_cast<uint32_t>(decrypted_data.size());

        auto decrypt_err = azihsm_crypt_decrypt(&encrypt_algo, unwrapped_priv_key, &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(decrypt_err, AZIHSM_ERROR_SUCCESS);

        // Step 6: Verify the decrypted data matches the original plaintext
        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(unwrapped_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(unwrapped_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}
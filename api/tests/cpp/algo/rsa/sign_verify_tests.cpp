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

class azihsm_rsa_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_rsa_sign_verify, sign_verify_pkcs_sha256_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);

        // Step 3: Prepare test data
        const char *test_data = "Test RSA PKCS#1 v1.5 SHA-256 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        // Step 4: Setup PKCS#1 SHA-256 algorithm
        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_SHA256;
        sign_algo.params = nullptr;
        sign_algo.len = 0;

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256); // RSA 2048 = 256 bytes signature
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 5: Sign with the imported private key
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);
        ASSERT_LE(sig_buf.len, 256);

        // Step 6: Verify with the imported public key
        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 7: Test verification fails with modified data
        std::vector<uint8_t> modified_data = data_to_sign;
        modified_data[0] ^= 0xFF; // Flip bits in first byte

        azihsm_buffer modified_buf = {};
        modified_buf.ptr = modified_data.data();
        modified_buf.len = static_cast<uint32_t>(modified_data.size());

        auto verify_fail_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &modified_buf, &verify_sig_buf);
        ASSERT_NE(verify_fail_err, AZIHSM_ERROR_SUCCESS);

        // Step 8: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_rsa_sign_verify, sign_verify_pkcs_sha1_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);

        // Step 3: Test data and algorithm
        const char *test_data = "Test RSA PKCS#1 v1.5 SHA-1 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_SHA1;
        sign_algo.params = nullptr;
        sign_algo.len = 0;

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 4: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_rsa_sign_verify, sign_verify_pkcs_sha384_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);

        // Step 3: Test data and algorithm
        const char *test_data = "Test RSA PKCS#1 v1.5 SHA-384 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_SHA384;
        sign_algo.params = nullptr;
        sign_algo.len = 0;

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 4: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_rsa_sign_verify, sign_verify_pkcs_sha512_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);

        // Step 3: Test data and algorithm
        const char *test_data = "Test RSA PKCS#1 v1.5 SHA-512 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_SHA512;
        sign_algo.params = nullptr;
        sign_algo.len = 0;

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 4: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS SHA-256 sign and verify test
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_sha256_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);

        // Step 3: Prepare test data
        const char *test_data = "Test RSA PSS SHA-256 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        // Step 4: Setup PSS SHA-256 algorithm with parameters
        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA256;
        pss_params.salt_len = 32; // SHA-256 produces 32 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256;
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256); // RSA 2048 = 256 bytes signature
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 5: Sign with the imported private key
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);
        ASSERT_LE(sig_buf.len, 256);

        // Step 6: Verify with the imported public key
        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 7: Test verification fails with modified data
        std::vector<uint8_t> modified_data = data_to_sign;
        modified_data[0] ^= 0xFF; // Flip bits in first byte

        azihsm_buffer modified_buf = {};
        modified_buf.ptr = modified_data.data();
        modified_buf.len = static_cast<uint32_t>(modified_data.size());

        auto verify_fail_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &modified_buf, &verify_sig_buf);
        ASSERT_NE(verify_fail_err, AZIHSM_ERROR_SUCCESS);

        // Step 8: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS SHA-1 sign and verify test
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_sha1_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);

        // Step 3: Test data and algorithm
        const char *test_data = "Test RSA PSS SHA-1 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA1;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA1;
        pss_params.salt_len = 20; // SHA-1 produces 20 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1;
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 4: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS SHA-384 sign and verify test
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_sha384_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);

        // Step 3: Test data and algorithm
        const char *test_data = "Test RSA PSS SHA-384 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA384;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA384;
        pss_params.salt_len = 48; // SHA-384 produces 48 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384;
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 4: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS SHA-512 sign and verify test
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_sha512_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);

        // Step 3: Test data and algorithm
        const char *test_data = "Test RSA PSS SHA-512 signing";
        std::vector<uint8_t> data_to_sign(test_data, test_data + strlen(test_data));

        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA512;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA512;
        pss_params.salt_len = 64; // SHA-512 produces 64 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512;
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = data_to_sign.data();
        data_buf.len = static_cast<uint32_t>(data_to_sign.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 4: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 5: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS direct (pre-hashed) sign and verify test
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_prehashed_sha256_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);

        // Step 3: Prepare pre-hashed data (SHA-256 hash = 32 bytes)
        std::vector<uint8_t> hashed_data(32, 0xAB); // 32 bytes all initialized to 0xAB

        // Step 4: Setup PSS algorithm for pre-hashed data (AZIHSM_ALGO_ID_RSA_PKCS_PSS)
        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA256;
        pss_params.salt_len = 32; // SHA-256 produces 32 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS; // Direct PSS, not PSS_SHA256
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = hashed_data.data();
        data_buf.len = static_cast<uint32_t>(hashed_data.size());

        std::vector<uint8_t> signature_data(256); // RSA 2048 = 256 bytes signature
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 5: Sign with the imported private key using pre-hashed data
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);
        ASSERT_LE(sig_buf.len, 256);

        // Step 6: Verify with the imported public key
        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 7: Test verification fails with modified hash
        std::vector<uint8_t> modified_hash = hashed_data;
        modified_hash[0] ^= 0xFF; // Flip bits in first byte

        azihsm_buffer modified_buf = {};
        modified_buf.ptr = modified_hash.data();
        modified_buf.len = static_cast<uint32_t>(modified_hash.size());

        auto verify_fail_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &modified_buf, &verify_sig_buf);
        ASSERT_NE(verify_fail_err, AZIHSM_ERROR_SUCCESS);

        // Step 8: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS direct (pre-hashed) sign and verify test with SHA-384
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_prehashed_sha384_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);

        // Step 3: Prepare pre-hashed data (SHA-384 hash = 48 bytes)
        std::vector<uint8_t> hashed_data(48, 0xCD); // 48 bytes all initialized to 0xCD

        // Step 4: Setup PSS algorithm for pre-hashed data
        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA384;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA384;
        pss_params.salt_len = 48; // SHA-384 produces 48 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS; // Direct PSS
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = hashed_data.data();
        data_buf.len = static_cast<uint32_t>(hashed_data.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 5: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 6: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS direct (pre-hashed) sign and verify test with SHA-512
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_prehashed_sha512_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);

        // Step 3: Prepare pre-hashed data (SHA-512 hash = 64 bytes)
        std::vector<uint8_t> hashed_data(64, 0xEF); // 64 bytes all initialized to 0xEF

        // Step 4: Setup PSS algorithm for pre-hashed data
        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA512;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA512;
        pss_params.salt_len = 64; // SHA-512 produces 64 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS; // Direct PSS
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = hashed_data.data();
        data_buf.len = static_cast<uint32_t>(hashed_data.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 5: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 6: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// RSA PSS direct (pre-hashed) sign and verify test with SHA-1
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_prehashed_sha1_with_imported_key)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        AutoKey wrapping_priv_key;
        AutoKey wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session.get(),
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Step 2: Import the hardcoded RSA key pair
        AutoKey imported_priv_key;
        AutoKey imported_pub_key;
        KeyProps import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_ERROR_SUCCESS);

        // Step 3: Prepare pre-hashed data (SHA-1 hash = 20 bytes)
        std::vector<uint8_t> hashed_data(20, 0x9A); // 20 bytes all initialized to 0x9A

        // Step 4: Setup PSS algorithm for pre-hashed data
        azihsm_algo_rsa_pkcs_pss_params pss_params = {};
        pss_params.hash_algo_id = AZIHSM_ALGO_ID_SHA1;
        pss_params.mgf_id = AZIHSM_MGF1_ID_SHA1;
        pss_params.salt_len = 20; // SHA-1 produces 20 bytes

        azihsm_algo sign_algo = {};
        sign_algo.id = AZIHSM_ALGO_ID_RSA_PKCS_PSS; // Direct PSS
        sign_algo.params = &pss_params;
        sign_algo.len = sizeof(pss_params);

        azihsm_buffer data_buf = {};
        data_buf.ptr = hashed_data.data();
        data_buf.len = static_cast<uint32_t>(hashed_data.size());

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = {};
        sig_buf.ptr = signature_data.data();
        sig_buf.len = static_cast<uint32_t>(signature_data.size());

        // Step 5: Sign and verify
        auto sign_err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        azihsm_buffer verify_sig_buf = {};
        verify_sig_buf.ptr = signature_data.data();
        verify_sig_buf.len = sig_buf.len;

        auto verify_err =
            azihsm_crypt_verify(&sign_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);

        // Step 6: Test the key deletion
        auto del_priv_err = azihsm_key_delete(imported_priv_key.release());
        ASSERT_EQ(del_priv_err, AZIHSM_ERROR_SUCCESS);
        auto del_pub_err = azihsm_key_delete(imported_pub_key.release());
        ASSERT_EQ(del_pub_err, AZIHSM_ERROR_SUCCESS);
    });
}
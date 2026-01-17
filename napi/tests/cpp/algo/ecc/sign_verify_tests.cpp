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

class azihsm_ecc_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_ecc_sign_verify, sign_verify_ecdsa_p256)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Prepare test data (pre-hashed for ECDSA)
        std::vector<uint8_t> hash(32, 0x42);

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        // Sign
        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 64);

        // Verify
        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &hash_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_verify_ecdsa_sha256_p256)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Prepare test data (raw message)
        const char *message = "Test message for ECDSA SHA-256";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Sign
        std::vector<uint8_t> signature(64);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 64);

        // Verify
        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_verify_ecdsa_sha384_p384)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P384, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message for ECDSA SHA-384";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA384;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(96);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 96);

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_verify_ecdsa_sha512_p521)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P521, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message for ECDSA SHA-512";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA512;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(132);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 132);

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, verify_fails_with_invalid_signature)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);

        // Corrupt signature
        signature[0] ^= 0xFF;

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_INVALID_SIGNATURE);
    });
}

TEST_F(azihsm_ecc_sign_verify, verify_fails_with_wrong_data)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Original message";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);

        // Different data
        const char *wrong_message = "Different message";
        std::vector<uint8_t> wrong_data(wrong_message, wrong_message + strlen(wrong_message));
        azihsm_buffer wrong_data_buf{wrong_data.data(), static_cast<uint32_t>(wrong_data.size())};

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &wrong_data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_INVALID_SIGNATURE);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_buffer_too_small)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> hash(32, 0x42);

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(32); // Too small, should be 64
        azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_BUFFER_TOO_SMALL);
        ASSERT_EQ(sig_buf.len, 64); // Updated with required size
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_null_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> hash(32, 0x42);
        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        err = azihsm_crypt_sign(nullptr, priv_key.get(), &hash_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_invalid_key_handle)
{
    std::vector<uint8_t> hash(32, 0x42);

    azihsm_algo algo{};
    algo.id = AZIHSM_ALGO_ID_ECDSA;
    algo.params = nullptr;
    algo.len = 0;

    std::vector<uint8_t> signature(64);
    azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
    azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

    auto err = azihsm_crypt_sign(&algo, 0xDEADBEEF, &hash_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(azihsm_ecc_sign_verify, sign_unsupported_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> hash(32, 0x42);

        azihsm_algo algo{};
        algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_UNSUPPORTED_ALGORITHM);
    });
}

TEST_F(azihsm_ecc_sign_verify, wrong_key_type_for_sign)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> hash(32, 0x42);

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        // Try to sign with public key
        err = azihsm_crypt_sign(&algo, pub_key.get(), &hash_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
    });
}

TEST_F(azihsm_ecc_sign_verify, wrong_key_type_for_verify)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> hash(32, 0x42);
        std::vector<uint8_t> signature(64, 0x00);

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer hash_buf{hash.data(), static_cast<uint32_t>(hash.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        // Try to verify with private key
        err = azihsm_crypt_verify(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_verify_ecdsa_sha256_p256)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Prepare test data in chunks
        const char *chunk1 = "Hello, ";
        const char *chunk2 = "streaming ";
        const char *chunk3 = "ECDSA!";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize streaming sign
        azihsm_handle sign_ctx = 0;
        auto sign_init_err = azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx);
        ASSERT_EQ(sign_init_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(sign_ctx, 0);

        // Update with data chunks
        azihsm_buffer chunk1_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(chunk1)),
                                 static_cast<uint32_t>(strlen(chunk1))};
        auto update1_err = azihsm_crypt_sign_update(sign_ctx, &chunk1_buf);
        ASSERT_EQ(update1_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk2_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(chunk2)),
                                 static_cast<uint32_t>(strlen(chunk2))};
        auto update2_err = azihsm_crypt_sign_update(sign_ctx, &chunk2_buf);
        ASSERT_EQ(update2_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk3_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(chunk3)),
                                 static_cast<uint32_t>(strlen(chunk3))};
        auto update3_err = azihsm_crypt_sign_update(sign_ctx, &chunk3_buf);
        ASSERT_EQ(update3_err, AZIHSM_ERROR_SUCCESS);

        // Finalize sign
        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        auto sign_final_err = azihsm_crypt_sign_final(sign_ctx, &sig_buf);
        ASSERT_EQ(sign_final_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 64);

        // Initialize streaming verify
        azihsm_handle verify_ctx = 0;
        auto verify_init_err = azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx);
        ASSERT_EQ(verify_init_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(verify_ctx, 0);

        // Update with same data chunks
        auto verify_update1_err = azihsm_crypt_verify_update(verify_ctx, &chunk1_buf);
        ASSERT_EQ(verify_update1_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update2_err = azihsm_crypt_verify_update(verify_ctx, &chunk2_buf);
        ASSERT_EQ(verify_update2_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update3_err = azihsm_crypt_verify_update(verify_ctx, &chunk3_buf);
        ASSERT_EQ(verify_update3_err, AZIHSM_ERROR_SUCCESS);

        // Finalize verify
        auto verify_final_err = azihsm_crypt_verify_final(verify_ctx, &sig_buf);
        ASSERT_EQ(verify_final_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_verify_ecdsa_sha384_p384)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P384, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message for streaming ECDSA SHA-384";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA384;
        algo.params = nullptr;
        algo.len = 0;

        // Streaming sign
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_ERROR_SUCCESS);

        azihsm_buffer msg_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                              static_cast<uint32_t>(strlen(message))};
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);

        std::vector<uint8_t> signature(96);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 96);

        // Streaming verify
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_final(verify_ctx, &sig_buf), AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_verify_ecdsa_sha512_p521)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P521, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message for streaming ECDSA SHA-512";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA512;
        algo.params = nullptr;
        algo.len = 0;

        // Streaming sign
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_ERROR_SUCCESS);

        azihsm_buffer msg_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                              static_cast<uint32_t>(strlen(message))};
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);

        std::vector<uint8_t> signature(132);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 132);

        // Streaming verify
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_final(verify_ctx, &sig_buf), AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_verify_fails_with_invalid_signature)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Sign with streaming
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_ERROR_SUCCESS);

        azihsm_buffer msg_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                              static_cast<uint32_t>(strlen(message))};
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_ERROR_SUCCESS);

        // Corrupt signature
        signature[0] ^= 0xFF;

        // Verify with streaming
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);

        // Verification should fail with corrupted signature
        auto verify_err = azihsm_crypt_verify_final(verify_ctx, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_INVALID_SIGNATURE);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_verify_fails_with_wrong_data)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Original message";
        const char *wrong_message = "Different message";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Sign original message
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_ERROR_SUCCESS);

        azihsm_buffer msg_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                              static_cast<uint32_t>(strlen(message))};
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_ERROR_SUCCESS);

        // Verify with different message
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx), AZIHSM_ERROR_SUCCESS);

        azihsm_buffer wrong_msg_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(wrong_message)),
                                    static_cast<uint32_t>(strlen(wrong_message))};
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &wrong_msg_buf), AZIHSM_ERROR_SUCCESS);

        // Verification should fail
        auto verify_err = azihsm_crypt_verify_final(verify_ctx, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_INVALID_SIGNATURE);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_final_buffer_too_small)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test message";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_ERROR_SUCCESS);

        azihsm_buffer msg_buf{const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                              static_cast<uint32_t>(strlen(message))};
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_ERROR_SUCCESS);

        // Buffer too small
        std::vector<uint8_t> signature(32); // Should be 64
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        err = azihsm_crypt_sign_final(sign_ctx, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_BUFFER_TOO_SMALL);
        ASSERT_EQ(sig_buf.len, 64); // Updated with required size
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_consistency_with_single_shot)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        const char *message = "Test consistency";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Single-shot sign
        std::vector<uint8_t> single_shot_sig(64);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer single_sig_buf{single_shot_sig.data(), static_cast<uint32_t>(single_shot_sig.size())};
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &data_buf, &single_sig_buf), AZIHSM_ERROR_SUCCESS);

        // Streaming sign
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &data_buf), AZIHSM_ERROR_SUCCESS);

        std::vector<uint8_t> streaming_sig(64);
        azihsm_buffer streaming_sig_buf{streaming_sig.data(), static_cast<uint32_t>(streaming_sig.size())};
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &streaming_sig_buf), AZIHSM_ERROR_SUCCESS);

        // Both signatures should verify successfully (they may differ due to random k)
        ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &data_buf, &single_sig_buf), AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &data_buf, &streaming_sig_buf), AZIHSM_ERROR_SUCCESS);
    });
}
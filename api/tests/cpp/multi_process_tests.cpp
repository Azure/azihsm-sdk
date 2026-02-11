// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/wait.h>
#endif

#include "algo/ecc/helpers.hpp"
#include "algo/hmac/helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/part_init_config.hpp"
#include "utils/utils.hpp"
#include "utils/multi_process.hpp"

namespace
{
static std::vector<uint8_t> get_part_prop_bytes(azihsm_handle part, azihsm_part_prop_id id)
{
    azihsm_part_prop prop = { id, nullptr, 0 };
    auto err = azihsm_part_get_prop(part, &prop);
    EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    std::vector<uint8_t> buffer(prop.len);
    prop.val = buffer.data();
    err = azihsm_part_get_prop(part, &prop);
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
    buffer.resize(prop.len);
    return buffer;
}

static std::vector<uint8_t> get_key_prop_bytes(azihsm_handle key, azihsm_key_prop_id id)
{
    azihsm_key_prop prop = { id, nullptr, 0 };
    auto err = azihsm_key_get_prop(key, &prop);
    EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    std::vector<uint8_t> buffer(prop.len);
    prop.val = buffer.data();
    err = azihsm_key_get_prop(key, &prop);
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
    buffer.resize(prop.len);
    return buffer;
}
} // namespace

class azihsm_multi_process_parent : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
    azihsm_handle part_handle = 0;
    azihsm_handle sess_handle = 0;
    azihsm_handle symmetric_key = 0;
    azihsm_str path_str = { nullptr, 0 };
    std::array<uint8_t, 48> obk{};
    std::vector<uint8_t> bmk;
    std::vector<uint8_t> seed;


    void SetUp() override
    {}

    void TearDown() override
    {
        // Clean up handles if they were opened
        if (sess_handle != 0)
        {
            azihsm_sess_close(sess_handle);
            sess_handle = 0;
        }
        if (part_handle != 0)
        {
            azihsm_part_close(part_handle);
            part_handle = 0;
        }
        if (symmetric_key != 0)
        {
            azihsm_key_delete(symmetric_key);
            symmetric_key = 0;
        }
    }

    void parent_common_setup(std::vector<azihsm_char> &path) {
        path_str = { path.data(), static_cast<uint32_t>(path.size()) };
        part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        std::random_device rd;
        for (auto &b : obk)
        {
            b = static_cast<uint8_t>(rd());
        }
        azihsm_buffer obk_buf = { obk.data(), static_cast<uint32_t>(obk.size()) };
        azihsm_owner_backup_key_config backup_config{};
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = &obk_buf;

        err = azihsm_part_init(part_handle, &creds, nullptr, nullptr, &backup_config);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        bmk = get_part_prop_bytes(part_handle, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY);

        seed.resize(48);
        for (auto &b : seed)
        {
            b = static_cast<uint8_t>(rd());
        }
        azihsm_buffer seed_buf = { seed.data(), static_cast<uint32_t>(seed.size()) };

        sess_handle = 0;
        err = azihsm_sess_open(part_handle, &api_rev, &creds, &seed_buf, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    }
};

class azihsm_multi_process_child : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
    cross_process_test_params test_params;
    azihsm_handle part_handle = 0;
    azihsm_handle sess_handle = 0;
    azihsm_str path_str = { nullptr, 0 };

    void SetUp() override
    {}

    void TearDown() override
    {
        // Clean up handles if they were opened
        if (sess_handle != 0)
        {
            azihsm_sess_close(sess_handle);
            sess_handle = 0;
        }
        if (part_handle != 0)
        {
            azihsm_part_close(part_handle);
            part_handle = 0;
        }
    }

    void child_common_setup() {
        test_params = get_cross_process_test_params();

        ASSERT_EQ(test_params.path_bytes.size() % sizeof(azihsm_char), 0u);
        std::vector<azihsm_char> path_chars(test_params.path_bytes.size() / sizeof(azihsm_char));
        std::memcpy(path_chars.data(), test_params.path_bytes.data(), test_params.path_bytes.size());

        path_str = { path_chars.data(), static_cast<uint32_t>(path_chars.size()) };

        part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));
        azihsm_api_rev api_rev{ 1, 0 };

        auto reset_err = azihsm_part_reset(part_handle);
        ASSERT_EQ(reset_err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer bmk_buf = { test_params.bmk.data(), static_cast<uint32_t>(test_params.bmk.size()) };
        azihsm_buffer obk_buf = { test_params.obk.data(), static_cast<uint32_t>(test_params.obk.size()) };

        azihsm_owner_backup_key_config backup_config{};
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = &obk_buf;
        auto init_err = azihsm_part_init(part_handle, &creds, &bmk_buf, nullptr, &backup_config);
        ASSERT_EQ(init_err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer seed_buf = { test_params.seed.data(), static_cast<uint32_t>(test_params.seed.size()) };

        sess_handle = 0;
        err = azihsm_sess_open(part_handle, &api_rev, &creds, &seed_buf, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto bmk_actual = get_part_prop_bytes(part_handle, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY);
        ASSERT_EQ(bmk_actual, test_params.bmk);
    }
};

TEST_F(azihsm_multi_process_parent, ecc_sign_verify_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            sess_handle,
            AZIHSM_ECC_CURVE_P256,
            false,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto masked_key = get_key_prop_bytes(priv_key.get(), AZIHSM_KEY_PROP_ID_MASKED_KEY);

        std::vector<uint8_t> message(64, 0x2A);
        azihsm_buffer msg_buf = { message.data(), static_cast<uint32_t>(message.size()) };

        azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };

        azihsm_buffer sig_buf = { nullptr, 0 };
        err = azihsm_crypt_sign(&sign_algo, priv_key.get(), &msg_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();
        err = azihsm_crypt_sign(&sign_algo, priv_key.get(), &msg_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> path_bytes(
            reinterpret_cast<uint8_t *>(path.data()),
            reinterpret_cast<uint8_t *>(path.data()) + (path.size() * sizeof(azihsm_char))
        );
        cross_process_test_params params(
            "azihsm_multi_process_child.ecc_sign_verify_cross_process",
            path_bytes,
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            signature,
            masked_key
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0)
            << "If running on real hardware, set AZIHSM_DISABLE_MULTI_PROCESS_TESTS=1 to skip";
    });
}

TEST_F(azihsm_multi_process_child, ecc_sign_verify_cross_process)
{
    child_common_setup();

    azihsm_buffer masked_buf = { test_params.masked_key.data(), static_cast<uint32_t>(test_params.masked_key.size()) };
    auto_key priv_key;
    auto_key pub_key;
    auto err = azihsm_key_unmask_pair(
        sess_handle,
        AZIHSM_KEY_KIND_ECC,
        &masked_buf,
        priv_key.get_ptr(),
        pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };
    azihsm_buffer msg_buf = { test_params.message.data(), static_cast<uint32_t>(test_params.message.size()) };
    azihsm_buffer sig_buf = { test_params.signature_or_ciphertext.data(), static_cast<uint32_t>(test_params.signature_or_ciphertext.size()) };
    err = azihsm_crypt_verify(&sign_algo, pub_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

TEST_F(azihsm_multi_process_parent, aes_cbc_sign_verify_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        // Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 128;
        bool is_session = false;  // Must be false to allow backup/restore across processes
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        };

        azihsm_key_prop_list prop_list{
            .props = props_vec.data(),
            .count = static_cast<uint32_t>(props_vec.size())
        };
        symmetric_key = 0;
        auto err = azihsm_key_gen(sess_handle, &keygen_algo, &prop_list, &symmetric_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(symmetric_key, 0);
        auto masked_key = get_key_prop_bytes(symmetric_key, AZIHSM_KEY_PROP_ID_MASKED_KEY);

        // Message must be multiple of AES block size (16 bytes)
        std::vector<uint8_t> message(64, 0x2A);
        azihsm_buffer msg_buf = { message.data(), static_cast<uint32_t>(message.size()) };

        // Generate IV for AES-CBC
        std::random_device rd;
        uint8_t iv[16] = { 0 };
        for (size_t i = 0; i < sizeof(iv); ++i)
        {
            iv[i] = static_cast<uint8_t>(rd());
        }
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        
        azihsm_algo encrypt_algo{};
        encrypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
        encrypt_algo.params = &cbc_params;
        encrypt_algo.len = sizeof(cbc_params);

        // Encrypt the message
        azihsm_buffer ciphertext_buf = { nullptr, 0 };
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> ciphertext(ciphertext_buf.len);
        ciphertext_buf.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> path_bytes(
            reinterpret_cast<uint8_t *>(path.data()),
            reinterpret_cast<uint8_t *>(path.data()) + (path.size() * sizeof(azihsm_char))
        );
        cross_process_test_params params(
            "azihsm_multi_process_child.aes_cbc_sign_verify_cross_process",
            path_bytes,
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            ciphertext,
            masked_key,
            std::vector<uint8_t>(iv, iv + sizeof(iv))  // Pass IV for AES-CBC
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0)
            << "If running on real hardware, set AZIHSM_DISABLE_MULTI_PROCESS_TESTS=1 to skip";
    });
}

TEST_F(azihsm_multi_process_child, aes_cbc_sign_verify_cross_process)
{
    child_common_setup();

    // Unmask the AES key (symmetric key, no key pair)
    azihsm_buffer masked_buf = { test_params.masked_key.data(), static_cast<uint32_t>(test_params.masked_key.size()) };
    auto_key aes_key;
    auto err = azihsm_key_unmask(sess_handle, AZIHSM_KEY_KIND_AES, &masked_buf, aes_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Set up CBC params with the IV for decryption
    ASSERT_TRUE(test_params.iv.has_value()) << "IV is required for AES-CBC";
    azihsm_algo_aes_cbc_params cbc_params{};
    std::memcpy(cbc_params.iv, test_params.iv->data(), std::min(sizeof(cbc_params.iv), test_params.iv->size()));
    
    azihsm_algo decrypt_algo{};
    decrypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
    decrypt_algo.params = &cbc_params;
    decrypt_algo.len = sizeof(cbc_params);

    // Decrypt the ciphertext
    azihsm_buffer ciphertext_buf = { test_params.signature_or_ciphertext.data(), static_cast<uint32_t>(test_params.signature_or_ciphertext.size()) };
    azihsm_buffer plaintext_buf = { nullptr, 0 };

    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

    std::vector<uint8_t> plaintext(plaintext_buf.len);
    plaintext_buf.ptr = plaintext.data();
    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Verify decrypted plaintext matches original message
    ASSERT_EQ(plaintext.size(), test_params.message.size());
    ASSERT_EQ(plaintext, test_params.message);
}

TEST_F(azihsm_multi_process_parent, hmac_sign_verify_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        // Generate EC key pairs and derive HMAC-SHA256 key
        // Note: The derived key must be non-session to support backup/restore
        EcdhKeyPairSet key_pairs;
        auto err = key_pairs.generate(sess_handle, AZIHSM_ECC_CURVE_P256);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Derive HMAC key with non-session property (is_session = false)
        auto_key hmac_key;
        err = derive_hmac_key_via_ecdh_hkdf(
            sess_handle,
            key_pairs.priv_key_a.handle,
            key_pairs.pub_key_b.handle,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            hmac_key.handle,
            AZIHSM_ECC_CURVE_P256,
            nullptr,
            false  // is_session = false for cross-process backup/restore
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(hmac_key.get(), 0);

        // Get masked key for transfer
        auto masked_key = get_key_prop_bytes(hmac_key.get(), AZIHSM_KEY_PROP_ID_MASKED_KEY);

        // Sign a message with HMAC-SHA256
        std::vector<uint8_t> message(64, 0x2A);
        azihsm_buffer msg_buf = { message.data(), static_cast<uint32_t>(message.size()) };

        azihsm_algo hmac_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };

        azihsm_buffer mac_buf = { nullptr, 0 };
        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &msg_buf, &mac_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> mac(mac_buf.len);
        mac_buf.ptr = mac.data();
        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &msg_buf, &mac_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> path_bytes(
            reinterpret_cast<uint8_t *>(path.data()),
            reinterpret_cast<uint8_t *>(path.data()) + (path.size() * sizeof(azihsm_char))
        );
        cross_process_test_params params(
            "azihsm_multi_process_child.hmac_sign_verify_cross_process",
            path_bytes,
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            mac,
            masked_key
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0)
            << "If running on real hardware, set AZIHSM_DISABLE_MULTI_PROCESS_TESTS=1 to skip";
    });
}

TEST_F(azihsm_multi_process_child, hmac_sign_verify_cross_process)
{
    child_common_setup();

    // Unmask the HMAC key
    azihsm_buffer masked_buf = { test_params.masked_key.data(), static_cast<uint32_t>(test_params.masked_key.size()) };
    auto_key hmac_key;
    auto err = azihsm_key_unmask(sess_handle, AZIHSM_KEY_KIND_HMAC_SHA256, &masked_buf, hmac_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Verify the HMAC signature
    azihsm_algo hmac_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };
    azihsm_buffer msg_buf = { test_params.message.data(), static_cast<uint32_t>(test_params.message.size()) };
    azihsm_buffer mac_buf = { test_params.signature_or_ciphertext.data(), static_cast<uint32_t>(test_params.signature_or_ciphertext.size()) };
    err = azihsm_crypt_verify(&hmac_algo, hmac_key.get(), &msg_buf, &mac_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

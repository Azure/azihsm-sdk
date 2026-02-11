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

class azihsm_multi_process : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_multi_process, ecc_sign_verify_cross_process_parent)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_str path_str = { path.data(), static_cast<uint32_t>(path.size()) };
        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        auto part_guard = scope_guard::make_scope_exit([&] {
            ASSERT_EQ(azihsm_part_close(part_handle), AZIHSM_STATUS_SUCCESS);
        });

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        PartInitConfig init_config{};
        make_part_init_config(part_handle, init_config);
        err = azihsm_part_init(
            part_handle,
            &creds,
            nullptr,
            nullptr,
            &init_config.backup_config,
            &init_config.pota_endorsement
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto bmk = get_part_prop_bytes(part_handle, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY);

        std::random_device rd;
        std::array<uint8_t, 48> seed{};
        for (auto &b : seed)
        {
            b = static_cast<uint8_t>(rd());
        }
        azihsm_buffer seed_buf = { seed.data(), static_cast<uint32_t>(seed.size()) };

        azihsm_handle sess_handle = 0;
        err = azihsm_sess_open(part_handle, &api_rev, &creds, &seed_buf, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto sess_guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });

        auto_key priv_key;
        auto_key pub_key;
        err = generate_ecc_keypair(
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
            "azihsm_multi_process.ecc_sign_verify_cross_process_child",
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

TEST_F(azihsm_multi_process, ecc_sign_verify_cross_process_child)
{
    auto test_params = get_cross_process_test_params();

    ASSERT_EQ(test_params.path_bytes.size() % sizeof(azihsm_char), 0u);
    std::vector<azihsm_char> path_chars(test_params.path_bytes.size() / sizeof(azihsm_char));
    std::memcpy(path_chars.data(), test_params.path_bytes.data(), test_params.path_bytes.size());

    azihsm_str path_str = { path_chars.data(), static_cast<uint32_t>(path_chars.size()) };

    azihsm_handle part_handle = 0;
    auto err = azihsm_part_open(&path_str, &part_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    auto part_guard = scope_guard::make_scope_exit([&] {
        ASSERT_EQ(azihsm_part_close(part_handle), AZIHSM_STATUS_SUCCESS);
    });

    azihsm_credentials creds{};
    std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));
    azihsm_api_rev api_rev{ 1, 0 };

    // Reset partition before initialization to clear any previous state
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

    azihsm_handle sess_handle = 0;
    err = azihsm_sess_open(part_handle, &api_rev, &creds, &seed_buf, &sess_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    auto sess_guard = scope_guard::make_scope_exit([&] {
        ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
    });

    auto bmk_actual = get_part_prop_bytes(part_handle, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY);
    ASSERT_EQ(bmk_actual, test_params.bmk);

    azihsm_buffer masked_buf = { test_params.masked_key.data(), static_cast<uint32_t>(test_params.masked_key.size()) };
    auto_key priv_key;
    auto_key pub_key;
    err = azihsm_key_unmask_pair(
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
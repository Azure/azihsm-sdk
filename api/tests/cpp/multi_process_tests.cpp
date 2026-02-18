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
#include "algo/rsa/helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/key_import.hpp"
#include "utils/key_props.hpp"
#include "utils/part_init_config.hpp"
#include "utils/utils.hpp"
#include "utils/multi_process.hpp"
#include "utils/rsa_keygen.hpp"

// See utils/multi_process.hpp for a description of multi-process tests.

namespace
{
constexpr size_t TEST_MESSAGE_SIZE = 64;
constexpr uint8_t TEST_MESSAGE_FILL_BYTE = 0x2A;
constexpr const char CHILD_PROCESS_SKIP_MSG[] = "This test should only run when invoked by the parent test";
constexpr size_t GCM_TAG_SIZE = 16;
constexpr size_t AES_CBC_IV_SIZE = 16;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_XTS_TWEAK_SIZE = 16;
constexpr uint8_t TEST_AAD[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

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

static std::vector<uint8_t> path_to_bytes(const std::vector<azihsm_char>& path)
{
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(path.data()),
        reinterpret_cast<const uint8_t*>(path.data()) + (path.size() * sizeof(azihsm_char))
    );
}

static azihsm_buffer create_buffer(std::vector<uint8_t>& data)
{
    return azihsm_buffer{ data.data(), static_cast<uint32_t>(data.size()) };
}

static azihsm_status generate_symmetric_key(
    azihsm_handle sess_handle,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits,
    azihsm_handle* key_handle)
{
    azihsm_algo keygen_algo = { algo_id, nullptr, 0 };
    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool is_session = false;  // Must be false to allow backup/restore across processes
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> props_vec = {
        { AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) },
        { AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) },
        { AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) },
        { AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) },
        { AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) },
        { AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) }
    };

    azihsm_key_prop_list prop_list{
        props_vec.data(),
        static_cast<uint32_t>(props_vec.size())
    };

    return azihsm_key_gen(sess_handle, &keygen_algo, &prop_list, key_handle);
}

template<size_t N>
static void generate_random_bytes(uint8_t (&buffer)[N])
{
    std::random_device rd;
    for (size_t i = 0; i < N; ++i)
    {
        buffer[i] = static_cast<uint8_t>(rd());
    }
}

static std::vector<uint8_t> get_masked_key(azihsm_handle key)
{
    return get_key_prop_bytes(key, AZIHSM_KEY_PROP_ID_MASKED_KEY);
}
} // namespace

class azihsm_multi_process_parent : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
    azihsm_handle part_handle = 0;
    azihsm_handle sess_handle = 0;
    azihsm_handle symmetric_key = 0;
    std::array<uint8_t, 48> obk{};
    std::vector<uint8_t> bmk;
    std::vector<uint8_t> seed;


    void SetUp() override
    {}

    void TearDown() override
    {
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
        azihsm_str path_str = { path.data(), static_cast<uint32_t>(path.size()) };
        part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(creds.id));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(creds.pin));

        std::random_device rd;
        for (auto &b : obk)
        {
            b = static_cast<uint8_t>(rd());
        }
        azihsm_buffer obk_buf = { obk.data(), static_cast<uint32_t>(obk.size()) };
        azihsm_owner_backup_key_config backup_config{};
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = &obk_buf;
        PartInitConfig init_config{};
        make_part_init_config(part_handle, init_config);
        err = azihsm_part_init(
            part_handle,
            &creds,
            nullptr,
            nullptr,
            &backup_config,
            &init_config.pota_endorsement
        );
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

    void SetUp() override
    {}

    void TearDown() override
    {
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
        azihsm_str path_str = { path_chars.data(), static_cast<uint32_t>(path_chars.size()) };

        part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(creds.id));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(creds.pin));
        azihsm_api_rev api_rev{ 1, 0 };

        auto reset_err = azihsm_part_reset(part_handle);
        ASSERT_EQ(reset_err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer bmk_buf = { test_params.bmk.data(), static_cast<uint32_t>(test_params.bmk.size()) };
        azihsm_buffer obk_buf = { test_params.obk.data(), static_cast<uint32_t>(test_params.obk.size()) };

        azihsm_owner_backup_key_config backup_config{};
        backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
        backup_config.owner_backup_key = &obk_buf;
        PartInitConfig init_config{};
        make_part_init_config(part_handle, init_config);
        auto init_err = azihsm_part_init(
            part_handle,
            &creds,
            &bmk_buf,
            nullptr,
            &backup_config,
            &init_config.pota_endorsement
        );
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

        auto masked_key = get_masked_key(priv_key.get());

        std::vector<uint8_t> message(TEST_MESSAGE_SIZE, TEST_MESSAGE_FILL_BYTE);
        auto msg_buf = create_buffer(message);

        azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };

        azihsm_buffer sig_buf = { nullptr, 0 };
        err = azihsm_crypt_sign(&sign_algo, priv_key.get(), &msg_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();
        err = azihsm_crypt_sign(&sign_algo, priv_key.get(), &msg_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        cross_process_test_params params(
            "azihsm_multi_process_child.ecc_sign_verify_cross_process",
            path_to_bytes(path),
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            signature,
            masked_key
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0);
    });
}

TEST_F(azihsm_multi_process_child, ecc_sign_verify_cross_process)
{
    if (!is_child_process()) {
        GTEST_SKIP() << CHILD_PROCESS_SKIP_MSG;
    }
    child_common_setup();

    auto masked_buf = create_buffer(test_params.masked_key);
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
    auto msg_buf = create_buffer(test_params.message);
    auto sig_buf = create_buffer(test_params.signature_or_ciphertext);
    err = azihsm_crypt_verify(&sign_algo, pub_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

TEST_F(azihsm_multi_process_parent, aes_cbc_encrypt_decrypt_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        symmetric_key = 0;
        auto err = generate_symmetric_key(
            sess_handle,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            128,
            &symmetric_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(symmetric_key, 0);
        auto masked_key = get_masked_key(symmetric_key);

        // Message must be multiple of AES block size (16 bytes)
        std::vector<uint8_t> message(TEST_MESSAGE_SIZE, TEST_MESSAGE_FILL_BYTE);
        auto msg_buf = create_buffer(message);

        uint8_t iv[AES_CBC_IV_SIZE] = { 0 };
        generate_random_bytes(iv);
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(cbc_params.iv));
        
        azihsm_algo encrypt_algo{};
        encrypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
        encrypt_algo.params = &cbc_params;
        encrypt_algo.len = sizeof(cbc_params);

        azihsm_buffer ciphertext_buf = { nullptr, 0 };
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        std::vector<uint8_t> ciphertext(ciphertext_buf.len);
        ciphertext_buf.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        cross_process_test_params params(
            "azihsm_multi_process_child.aes_cbc_encrypt_decrypt_cross_process",
            path_to_bytes(path),
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            ciphertext,
            masked_key,
            std::vector<uint8_t>(iv, iv + sizeof(cbc_params.iv))
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0);
    });
}

TEST_F(azihsm_multi_process_child, aes_cbc_encrypt_decrypt_cross_process)
{
    if (!is_child_process()) {
        GTEST_SKIP() << CHILD_PROCESS_SKIP_MSG;
    }
    child_common_setup();

    auto masked_buf = create_buffer(test_params.masked_key);
    auto_key aes_key;
    auto err = azihsm_key_unmask(sess_handle, AZIHSM_KEY_KIND_AES, &masked_buf, aes_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_TRUE(test_params.iv.has_value()) << "IV is required for AES-CBC";
    ASSERT_EQ(test_params.iv->size(), AES_CBC_IV_SIZE);
    azihsm_algo_aes_cbc_params cbc_params{};
    std::memcpy(cbc_params.iv, test_params.iv->data(), AES_CBC_IV_SIZE);
    
    azihsm_algo decrypt_algo{};
    decrypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
    decrypt_algo.params = &cbc_params;
    decrypt_algo.len = sizeof(cbc_params);

    auto ciphertext_buf = create_buffer(test_params.signature_or_ciphertext);
    azihsm_buffer plaintext_buf = { nullptr, 0 };

    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    std::vector<uint8_t> plaintext(plaintext_buf.len);
    plaintext_buf.ptr = plaintext.data();
    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(plaintext.size(), test_params.message.size());
    ASSERT_EQ(plaintext, test_params.message);
}

TEST_F(azihsm_multi_process_parent, aes_gcm_encrypt_decrypt_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        symmetric_key = 0;
        auto err = generate_symmetric_key(
            sess_handle,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256,
            &symmetric_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        auto masked_key = get_masked_key(symmetric_key);

        std::vector<uint8_t> message(TEST_MESSAGE_SIZE, TEST_MESSAGE_FILL_BYTE);
        std::vector<uint8_t> aad(TEST_AAD, TEST_AAD + sizeof(TEST_AAD));

        uint8_t iv[AES_GCM_IV_SIZE];
        generate_random_bytes(iv);

        auto aad_buf = create_buffer(aad);
        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(gcm_params.iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &aad_buf;

        azihsm_algo encrypt_algo = { AZIHSM_ALGO_ID_AES_GCM, &gcm_params, sizeof(gcm_params) };

        auto msg_buf = create_buffer(message);
        azihsm_buffer ciphertext_buf = { nullptr, 0 };
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        std::vector<uint8_t> ciphertext(ciphertext_buf.len);
        ciphertext_buf.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> tag(gcm_params.tag, gcm_params.tag + sizeof(gcm_params.tag));

        cross_process_test_params params(
            "azihsm_multi_process_child.aes_gcm_encrypt_decrypt_cross_process",
            path_to_bytes(path),
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            ciphertext,
            masked_key,
            std::vector<uint8_t>(iv, iv + sizeof(gcm_params.iv)),
            tag,
            aad
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0);
    });
}

TEST_F(azihsm_multi_process_child, aes_gcm_encrypt_decrypt_cross_process)
{
    if (!is_child_process()) {
        GTEST_SKIP() << CHILD_PROCESS_SKIP_MSG;
    }
    child_common_setup();

    auto masked_buf = create_buffer(test_params.masked_key);
    auto_key aes_key;
    auto err = azihsm_key_unmask(sess_handle, AZIHSM_KEY_KIND_AES_GCM, &masked_buf, aes_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_TRUE(test_params.iv.has_value()) << "IV is required for AES-GCM";
    ASSERT_TRUE(test_params.tag.has_value()) << "Tag is required for AES-GCM";
    ASSERT_TRUE(test_params.aad.has_value()) << "AAD is expected for this test";
    ASSERT_EQ(test_params.iv->size(), AES_GCM_IV_SIZE);
    ASSERT_EQ(test_params.tag->size(), GCM_TAG_SIZE);

    auto aad_buf = create_buffer(*test_params.aad);
    azihsm_algo_aes_gcm_params gcm_params{};
    std::memcpy(gcm_params.iv, test_params.iv->data(), AES_GCM_IV_SIZE);
    std::memcpy(gcm_params.tag, test_params.tag->data(), GCM_TAG_SIZE);
    gcm_params.aad = &aad_buf;

    azihsm_algo decrypt_algo = { AZIHSM_ALGO_ID_AES_GCM, &gcm_params, sizeof(gcm_params) };

    auto ciphertext_buf = create_buffer(test_params.signature_or_ciphertext);
    azihsm_buffer plaintext_buf = { nullptr, 0 };

    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    std::vector<uint8_t> plaintext(plaintext_buf.len);
    plaintext_buf.ptr = plaintext.data();
    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(plaintext.size(), test_params.message.size());
    ASSERT_EQ(plaintext, test_params.message);
}

TEST_F(azihsm_multi_process_parent, aes_xts_encrypt_decrypt_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        symmetric_key = 0;
        auto err = generate_symmetric_key(
            sess_handle,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512,
            &symmetric_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        auto masked_key = get_masked_key(symmetric_key);

        std::vector<uint8_t> message(TEST_MESSAGE_SIZE, TEST_MESSAGE_FILL_BYTE);

        uint8_t tweak[AES_XTS_TWEAK_SIZE] = { 0 };
        generate_random_bytes(tweak);

        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, tweak, sizeof(xts_params.sector_num));
        xts_params.data_unit_length = static_cast<uint32_t>(message.size());

        azihsm_algo encrypt_algo = { AZIHSM_ALGO_ID_AES_XTS, &xts_params, sizeof(xts_params) };

        auto msg_buf = create_buffer(message);
        azihsm_buffer ciphertext_buf = { nullptr, 0 };
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        std::vector<uint8_t> ciphertext(ciphertext_buf.len);
        ciphertext_buf.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&encrypt_algo, symmetric_key, &msg_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        cross_process_test_params params(
            "azihsm_multi_process_child.aes_xts_encrypt_decrypt_cross_process",
            path_to_bytes(path),
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            ciphertext,
            masked_key,
            std::vector<uint8_t>(tweak, tweak + sizeof(tweak))  // Pass tweak via iv field
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0);
    });
}

TEST_F(azihsm_multi_process_child, aes_xts_encrypt_decrypt_cross_process)
{
    if (!is_child_process()) {
        GTEST_SKIP() << CHILD_PROCESS_SKIP_MSG;
    }
    child_common_setup();

    auto masked_buf = create_buffer(test_params.masked_key);
    auto_key aes_key;
    auto err = azihsm_key_unmask(sess_handle, AZIHSM_KEY_KIND_AES_XTS, &masked_buf, aes_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_TRUE(test_params.iv.has_value()) << "Tweak is required for AES-XTS";
    ASSERT_EQ(test_params.iv->size(), AES_XTS_TWEAK_SIZE);

    azihsm_algo_aes_xts_params xts_params{};
    std::memcpy(xts_params.sector_num, test_params.iv->data(), AES_XTS_TWEAK_SIZE);
    xts_params.data_unit_length = static_cast<uint32_t>(test_params.signature_or_ciphertext.size());

    azihsm_algo decrypt_algo = { AZIHSM_ALGO_ID_AES_XTS, &xts_params, sizeof(xts_params) };

    auto ciphertext_buf = create_buffer(test_params.signature_or_ciphertext);
    azihsm_buffer plaintext_buf = { nullptr, 0 };

    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    std::vector<uint8_t> plaintext(plaintext_buf.len);
    plaintext_buf.ptr = plaintext.data();
    err = azihsm_crypt_decrypt(&decrypt_algo, aes_key.get(), &ciphertext_buf, &plaintext_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(plaintext.size(), test_params.message.size());
    ASSERT_EQ(plaintext, test_params.message);
}

TEST_F(azihsm_multi_process_parent, hmac_sign_verify_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        EcdhKeyPairSet key_pairs;
        auto err = key_pairs.generate(sess_handle, AZIHSM_ECC_CURVE_P256);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

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

        auto masked_key = get_masked_key(hmac_key.get());

        std::vector<uint8_t> message(TEST_MESSAGE_SIZE, TEST_MESSAGE_FILL_BYTE);
        auto msg_buf = create_buffer(message);

        azihsm_algo hmac_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };

        azihsm_buffer mac_buf = { nullptr, 0 };
        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &msg_buf, &mac_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        std::vector<uint8_t> mac(mac_buf.len);
        mac_buf.ptr = mac.data();
        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &msg_buf, &mac_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        cross_process_test_params params(
            "azihsm_multi_process_child.hmac_sign_verify_cross_process",
            path_to_bytes(path),
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            mac,
            masked_key
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0);
    });
}

TEST_F(azihsm_multi_process_child, hmac_sign_verify_cross_process)
{
    if (!is_child_process()) {
        GTEST_SKIP() << CHILD_PROCESS_SKIP_MSG;
    }
    child_common_setup();

    auto masked_buf = create_buffer(test_params.masked_key);
    auto_key hmac_key;
    auto err = azihsm_key_unmask(sess_handle, AZIHSM_KEY_KIND_HMAC_SHA256, &masked_buf, hmac_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    azihsm_algo hmac_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };
    auto msg_buf = create_buffer(test_params.message);
    auto mac_buf = create_buffer(test_params.signature_or_ciphertext);
    err = azihsm_crypt_verify(&hmac_algo, hmac_key.get(), &msg_buf, &mac_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

TEST_F(azihsm_multi_process_parent, rsa_sign_verify_cross_process)
{
    part_list_.for_each_part([this](std::vector<azihsm_char> &path) {
        parent_common_setup(path);

        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            sess_handle,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        key_props import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = false,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto_key imported_priv_key;
        auto_key imported_pub_key;
        err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto masked_key = get_masked_key(imported_priv_key.get());

        std::vector<uint8_t> message(TEST_MESSAGE_SIZE, TEST_MESSAGE_FILL_BYTE);
        auto msg_buf = create_buffer(message);

        azihsm_algo sign_algo = { AZIHSM_ALGO_ID_RSA_PKCS_SHA256, nullptr, 0 };

        azihsm_buffer sig_buf = { nullptr, 0 };
        err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &msg_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();
        err = azihsm_crypt_sign(&sign_algo, imported_priv_key.get(), &msg_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        cross_process_test_params params(
            "azihsm_multi_process_child.rsa_sign_verify_cross_process",
            path_to_bytes(path),
            bmk,
            std::vector<uint8_t>(obk.begin(), obk.end()),
            std::vector<uint8_t>(seed.begin(), seed.end()),
            message,
            signature,
            masked_key
        );
        int rc = run_child_test(params);
        ASSERT_EQ(rc, 0);
    });
}

TEST_F(azihsm_multi_process_child, rsa_sign_verify_cross_process)
{
    if (!is_child_process()) {
        GTEST_SKIP() << CHILD_PROCESS_SKIP_MSG;
    }
    child_common_setup();

    auto masked_buf = create_buffer(test_params.masked_key);
    auto_key priv_key;
    auto_key pub_key;
    auto err = azihsm_key_unmask_pair(
        sess_handle,
        AZIHSM_KEY_KIND_RSA,
        &masked_buf,
        priv_key.get_ptr(),
        pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_RSA_PKCS_SHA256, nullptr, 0 };
    auto msg_buf = create_buffer(test_params.message);
    auto sig_buf = create_buffer(test_params.signature_or_ciphertext);
    err = azihsm_crypt_verify(&sign_algo, pub_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

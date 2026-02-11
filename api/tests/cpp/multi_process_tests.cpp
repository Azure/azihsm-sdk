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

namespace
{
constexpr const char *kHelperEnv = "AZIHSM_HELPER_INPUT";
constexpr const char *kTmpPrefix = "azihsm_multi_proc_";

static void write_u32(std::ofstream &out, uint32_t v)
{
    out.write(reinterpret_cast<const char *>(&v), sizeof(v));
}

static uint32_t read_u32(std::ifstream &in)
{
    uint32_t v = 0;
    in.read(reinterpret_cast<char *>(&v), sizeof(v));
    return v;
}

static void write_blob(std::ofstream &out, const std::vector<uint8_t> &data)
{
    write_u32(out, static_cast<uint32_t>(data.size()));
    if (!data.empty())
    {
        out.write(reinterpret_cast<const char *>(data.data()), data.size());
    }
}

static std::vector<uint8_t> read_blob(std::ifstream &in)
{
    uint32_t len = read_u32(in);
    std::vector<uint8_t> data(len);
    if (len != 0)
    {
        in.read(reinterpret_cast<char *>(data.data()), len);
    }
    return data;
}

static std::string self_exe_path()
{
#if defined(_WIN32)
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    buffer.resize(size);
    return std::string(buffer.begin(), buffer.end());
#else
    return std::filesystem::read_symlink("/proc/self/exe").string();
#endif
}

static int run_child_test(const std::filesystem::path &input_path, const std::string &gtest_filter)
{
#if defined(_WIN32)
    _putenv_s(kHelperEnv, input_path.string().c_str());
#else
    setenv(kHelperEnv, input_path.string().c_str(), 1);
#endif

    std::string cmd = "\"" + self_exe_path() + "\" --gtest_filter=" + gtest_filter;
    int rc = std::system(cmd.c_str());

#if defined(_WIN32)
    _putenv_s(kHelperEnv, "");
#else
    unsetenv(kHelperEnv);
    if (rc != -1)
    {
        rc = WEXITSTATUS(rc);
    }
#endif

    return rc;
}

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

static void cleanup_temp_files()
{
    std::error_code ec;
    auto tmp_dir = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return;
    }

    for (const auto &entry : std::filesystem::directory_iterator(tmp_dir, ec))
    {
        if (ec)
        {
            break;
        }
        if (!entry.is_regular_file(ec))
        {
            continue;
        }
        const auto name = entry.path().filename().string();
        if (name.rfind(kTmpPrefix, 0) == 0 && entry.path().extension() == ".bin")
        {
            std::filesystem::remove(entry.path(), ec);
        }
    }
}
} // namespace

class azihsm_multi_process : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_multi_process, ecc_sign_verify_cross_process_parent)
{
    cleanup_temp_files();
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

        auto tmp_path =
            std::filesystem::temp_directory_path() /
            ("azihsm_multi_proc_" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".bin");

        std::ofstream out(tmp_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        write_blob(out, path_bytes);
        write_blob(out, bmk);
        auto *obk_ptr = static_cast<uint8_t *>(init_config.backup_config.owner_backup_key->ptr);
        write_blob(
            out,
            std::vector<uint8_t>(obk_ptr, obk_ptr + init_config.backup_config.owner_backup_key->len)
        );
        write_blob(out, std::vector<uint8_t>(seed.begin(), seed.end()));
        write_blob(out, message);
        write_blob(out, signature);
        write_blob(out, masked_key);
        out.close();

        int rc =
            run_child_test(tmp_path, "azihsm_multi_process.ecc_sign_verify_cross_process_child");
        ASSERT_EQ(rc, 0)
            << "If running on real hardware, set AZIHSM_DISABLE_MULTI_PROCESS_TESTS=1 to skip";

        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
    });
}

TEST_F(azihsm_multi_process, ecc_sign_verify_cross_process_child)
{
    const char *input_path = std::getenv(kHelperEnv);
    if (input_path == nullptr || input_path[0] == '\0')
    {
        GTEST_SKIP();
    }

    ASSERT_TRUE(std::filesystem::exists(input_path)) << "Missing input file: " << input_path;

    std::ifstream in(input_path, std::ios::binary);
    if (!in.is_open())
    {
        ADD_FAILURE() << "Failed to open input file: " << input_path << " errno=" << errno << " ("
                      << std::strerror(errno) << ")";
        return;
    }

    auto path_bytes = read_blob(in);
    auto bmk = read_blob(in);
    auto obk = read_blob(in);
    auto seed = read_blob(in);
    auto message = read_blob(in);
    auto signature = read_blob(in);
    auto masked_key = read_blob(in);

    ASSERT_EQ(path_bytes.size() % sizeof(azihsm_char), 0u);
    std::vector<azihsm_char> path_chars(path_bytes.size() / sizeof(azihsm_char));
    std::memcpy(path_chars.data(), path_bytes.data(), path_bytes.size());

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

    azihsm_buffer bmk_buf = { bmk.data(), static_cast<uint32_t>(bmk.size()) };

    PartInitConfig init_config{};
    make_part_init_config(part_handle, init_config);
    // Override OBK with the deserialized key from parent process
    azihsm_buffer obk_buf = { obk.data(), static_cast<uint32_t>(obk.size()) };
    init_config.backup_config.source = AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER;
    init_config.backup_config.owner_backup_key = &obk_buf;

    auto init_err = azihsm_part_init(
        part_handle,
        &creds,
        &bmk_buf,
        nullptr,
        &init_config.backup_config,
        &init_config.pota_endorsement
    );
    ASSERT_EQ(init_err, AZIHSM_STATUS_SUCCESS);

    azihsm_buffer seed_buf = { seed.data(), static_cast<uint32_t>(seed.size()) };

    azihsm_handle sess_handle = 0;
    err = azihsm_sess_open(part_handle, &api_rev, &creds, &seed_buf, &sess_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    auto sess_guard = scope_guard::make_scope_exit([&] {
        ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
    });

    auto bmk_actual = get_part_prop_bytes(part_handle, AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY);
    ASSERT_EQ(bmk_actual, bmk);

    azihsm_buffer masked_buf = { masked_key.data(), static_cast<uint32_t>(masked_key.size()) };
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
    azihsm_buffer msg_buf = { message.data(), static_cast<uint32_t>(message.size()) };
    azihsm_buffer sig_buf = { signature.data(), static_cast<uint32_t>(signature.size()) };

    err = azihsm_crypt_verify(&sign_algo, pub_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}
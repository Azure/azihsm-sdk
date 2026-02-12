// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "multi_process.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/wait.h>
#endif

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

static void write_to_file(const std::string &file_path, const cross_process_test_params & params) {
    std::ofstream out(file_path, std::ios::binary);
    if (!out.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + file_path);
    }
    write_blob(out, std::vector<uint8_t>(params.test_name.begin(), params.test_name.end()));
    write_blob(out, params.path_bytes);
    write_blob(out, params.bmk);
    write_blob(out, params.obk);
    write_blob(out, params.seed);
    write_blob(out, params.message);
    write_blob(out, params.signature_or_ciphertext);
    write_blob(out, params.masked_key);
    
    // Write optional IV with a flag
    if (params.iv.has_value()) {
        write_u32(out, 1);  // Has value
        write_blob(out, params.iv.value());
    } else {
        write_u32(out, 0);  // No value
    }
    
    // Write optional tag with a flag
    if (params.tag.has_value()) {
        write_u32(out, 1);  // Has value
        write_blob(out, params.tag.value());
    } else {
        write_u32(out, 0);  // No value
    }
    
    // Write optional aad with a flag
    if (params.aad.has_value()) {
        write_u32(out, 1);  // Has value
        write_blob(out, params.aad.value());
    } else {
        write_u32(out, 0);  // No value
    }
    
    out.close();
}

static cross_process_test_params read_from_file(const std::string &file_path) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in.is_open()) {
        throw std::runtime_error("Failed to open file for reading: " + file_path);
    }
    auto test_name_vec = read_blob(in);
    std::string test_name(test_name_vec.begin(), test_name_vec.end());
    auto path_bytes = read_blob(in);
    auto bmk = read_blob(in);
    auto obk = read_blob(in);
    auto seed = read_blob(in);
    auto message = read_blob(in);
    auto signature_or_ciphertext = read_blob(in);
    auto masked_key = read_blob(in);
    
    // Read optional IV
    std::optional<std::vector<uint8_t>> iv;
    uint32_t has_iv = read_u32(in);
    if (has_iv) {
        iv = read_blob(in);
    }
    
    // Read optional tag
    std::optional<std::vector<uint8_t>> tag;
    uint32_t has_tag = read_u32(in);
    if (has_tag) {
        tag = read_blob(in);
    }
    
    // Read optional aad
    std::optional<std::vector<uint8_t>> aad;
    uint32_t has_aad = read_u32(in);
    if (has_aad) {
        aad = read_blob(in);
    }
    
    in.close();
    return cross_process_test_params(
        test_name, path_bytes, bmk, obk, seed, message, signature_or_ciphertext, masked_key, iv, tag, aad
    );
}
} // namespace



// Invoke the specified test in a child process, passing necessary
// parameters via a temporary file.
//
// Returns the exit code of the child process (0 for success, non-zero for failure).
int run_child_test(const cross_process_test_params & params) {
    // Write parameters to a temporary file that the child process can read
    auto tmp_file = std::filesystem::temp_directory_path() / (kTmpPrefix + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".bin");
    write_to_file(tmp_file.string(), params);

    // Set environment variable to pass the file path to the child process
#if defined(_WIN32)
    _putenv_s(kHelperEnv, tmp_file.string().c_str());
#else
    setenv(kHelperEnv, tmp_file.string().c_str(), 1);
#endif

    std::string cmd = "\"" + self_exe_path() + "\" --gtest_filter=" + params.test_name;
    
    std::cout << "\n========================================\n";
    std::cout << "Running child process:\n";
    std::cout << "  Command: " << cmd << "\n";
    std::cout << "  Input file: " << tmp_file << "\n";
    std::cout << "========================================\n" << std::flush;
    
    // Run the child process and wait for it to complete
    int rc = std::system(cmd.c_str());
    
    std::cout << "\n========================================\n";
    std::cout << "Child process completed with exit code: " << rc << "\n";
    std::cout << "========================================\n" << std::flush;

    // Unset the environment variable to avoid affecting other tests
#if defined(_WIN32)
    _putenv_s(kHelperEnv, "");
#else
    unsetenv(kHelperEnv);
    if (rc != -1)
    {
        rc = WEXITSTATUS(rc);
        std::cout << "Extracted exit status: " << rc << "\n" << std::flush;
    }
#endif

    // Clean up the temporary file
    std::error_code ec;
    std::filesystem::remove(tmp_file, ec);

    return rc;
}

// Called by the child process to collect test parameters set by the parent process.
cross_process_test_params get_cross_process_test_params() {
    const char *tmp_file = std::getenv(kHelperEnv);
    if (!tmp_file) {
        throw std::runtime_error("Environment variable " + std::string(kHelperEnv) + " not set");
    }
    return read_from_file(tmp_file);
}

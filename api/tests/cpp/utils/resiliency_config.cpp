// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "resiliency_config.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "handle/test_creds.hpp"
#include "part_init_config.hpp"

#ifdef _WIN32
#define NOMINMAX
// clang-format off
#include <windows.h>
// clang-format on
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

ResiliencyTestCtx::ResiliencyTestCtx()
#ifdef _WIN32
    : lock_handle(INVALID_HANDLE_VALUE)
#else
    : lock_fd(-1)
#endif
{
}

ResiliencyTestCtx::~ResiliencyTestCtx()
{
#ifdef _WIN32
    if (lock_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(lock_handle);
    }
#else
    if (lock_fd >= 0)
    {
        close(lock_fd);
    }
#endif

    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

// File-backed storage callbacks
//
// These implement the azihsm_resiliency_storage_ops vtable using one file
// per key under the ResiliencyTestCtx::temp_dir directory.

static fs::path key_path(void *ctx, const char *key)
{
    auto *test_ctx = static_cast<ResiliencyTestCtx *>(ctx);
    return test_ctx->temp_dir / key;
}

static azihsm_status storage_read(void *ctx, const char *key, azihsm_buffer *output)
{
    auto path = key_path(ctx, key);

    std::error_code ec;
    if (!fs::exists(path, ec))
    {
        return AZIHSM_STATUS_NOT_FOUND;
    }

    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs)
    {
        return AZIHSM_STATUS_NOT_FOUND;
    }

    auto size = static_cast<uint32_t>(ifs.tellg());

    // Size-query call: caller passes null ptr / zero len to learn the size.
    if (output->ptr == nullptr || output->len < size)
    {
        output->len = size;
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    ifs.seekg(0);
    ifs.read(static_cast<char *>(output->ptr), size);
    if (!ifs.good())
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    output->len = size;
    return AZIHSM_STATUS_SUCCESS;
}

static azihsm_status storage_write(void *ctx, const char *key, const azihsm_buffer *data)
{
    auto path = key_path(ctx, key);

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (data->len > 0)
    {
        ofs.write(static_cast<const char *>(data->ptr), static_cast<std::streamsize>(data->len));
    }

    return ofs.good() ? AZIHSM_STATUS_SUCCESS : AZIHSM_STATUS_INTERNAL_ERROR;
}

static azihsm_status storage_clear(void *ctx, const char *key)
{
    auto path = key_path(ctx, key);
    std::error_code ec;
    fs::remove(path, ec);
    // No error if key doesn't exist (matches trait contract).
    return AZIHSM_STATUS_SUCCESS;
}

// Cross-process/thread file lock callbacks
//
// On Linux: flock(LOCK_EX / LOCK_UN)
// On Windows: LockFileEx / UnlockFileEx

static azihsm_status lock_acquire(void *ctx)
{
    auto *test_ctx = static_cast<ResiliencyTestCtx *>(ctx);
#ifdef _WIN32
    // Non-reentrant: caller must not call lock() while already held.
    if (test_ctx->lock_handle != INVALID_HANDLE_VALUE)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    // Open a fresh handle per lock attempt so LockFileEx serializes threads
    // (file locks are per open handle, not per path).
    HANDLE h = CreateFileA(
        test_ctx->lock_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (h == INVALID_HANDLE_VALUE)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    OVERLAPPED ov = {};
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov))
    {
        CloseHandle(h);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    test_ctx->lock_handle = h;
#else
    // Non-reentrant: caller must not call lock() while already held.
    if (test_ctx->lock_fd != -1)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    // Open a fresh fd per lock attempt so flock() serializes threads
    // (flock is per open file description, not per path).
    int fd = open(test_ctx->lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    if (flock(fd, LOCK_EX) != 0)
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    test_ctx->lock_fd = fd;
#endif
    return AZIHSM_STATUS_SUCCESS;
}

static azihsm_status lock_release(void *ctx)
{
    auto *test_ctx = static_cast<ResiliencyTestCtx *>(ctx);
#ifdef _WIN32
    if (test_ctx->lock_handle == INVALID_HANDLE_VALUE)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    OVERLAPPED ov = {};
    if (!UnlockFileEx(test_ctx->lock_handle, 0, 1, 0, &ov))
    {
        CloseHandle(test_ctx->lock_handle);
        test_ctx->lock_handle = INVALID_HANDLE_VALUE;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    if (!CloseHandle(test_ctx->lock_handle))
    {
        test_ctx->lock_handle = INVALID_HANDLE_VALUE;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    test_ctx->lock_handle = INVALID_HANDLE_VALUE;
#else
    if (test_ctx->lock_fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    if (flock(test_ctx->lock_fd, LOCK_UN) != 0)
    {
        close(test_ctx->lock_fd);
        test_ctx->lock_fd = -1;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    if (close(test_ctx->lock_fd) != 0)
    {
        test_ctx->lock_fd = -1;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    test_ctx->lock_fd = -1;
#endif
    return AZIHSM_STATUS_SUCCESS;
}

// POTA endorsement callback — real signing
//
// Signs the SDK-provided PID public key with the hardcoded POTA private
// key, exactly as generate_pota_endorsement() does for the initial init.
// This is required for restore_partition() to succeed: the device
// verifies the POTA endorsement with ECC, so a zeroed signature fails.

static azihsm_status pota_endorse(
    void * /*ctx*/,
    const azihsm_buffer * /*pota_pub_key_der*/,
    const azihsm_buffer *pid_pub_key_der,
    const azihsm_buffer * /*pid_cert_chain_pem*/,
    azihsm_buffer *signature,
    azihsm_buffer *endorsement_pub_key
)
{
    try
    {
        auto endorsement = sign_pota_endorsement(
            static_cast<const uint8_t *>(pid_pub_key_der->ptr),
            pid_pub_key_der->len
        );

        // First call: report required sizes.
        if (signature->ptr == nullptr ||
            signature->len < static_cast<uint32_t>(endorsement.signature.size()) ||
            endorsement_pub_key->ptr == nullptr ||
            endorsement_pub_key->len < static_cast<uint32_t>(endorsement.public_key_der.size()))
        {
            signature->len = static_cast<uint32_t>(endorsement.signature.size());
            endorsement_pub_key->len = static_cast<uint32_t>(endorsement.public_key_der.size());
            return AZIHSM_STATUS_BUFFER_TOO_SMALL;
        }

        // Second call: fill buffers.
        std::memcpy(signature->ptr, endorsement.signature.data(), endorsement.signature.size());
        signature->len = static_cast<uint32_t>(endorsement.signature.size());

        std::memcpy(
            endorsement_pub_key->ptr,
            endorsement.public_key_der.data(),
            endorsement.public_key_der.size()
        );
        endorsement_pub_key->len = static_cast<uint32_t>(endorsement.public_key_der.size());

        return AZIHSM_STATUS_SUCCESS;
    }
    catch (...)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
}

// Dummy OBK provider callback
static constexpr uint32_t TEST_OBK_SIZE = 48;

static azihsm_status obk_get_obk(void * /*ctx*/, azihsm_buffer *obk)
{
    // First call: report required size.
    if (obk->ptr == nullptr || obk->len < TEST_OBK_SIZE)
    {
        obk->len = TEST_OBK_SIZE;
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    // Second call: return the same OBK used for initial partition provisioning.
    // This must match TEST_OBK from test_creds.hpp — if the values differ,
    // restore_partition() will fail because the OBK won't match what the
    // device was provisioned with.
    std::memcpy(obk->ptr, TEST_OBK, TEST_OBK_SIZE);
    obk->len = TEST_OBK_SIZE;
    return AZIHSM_STATUS_SUCCESS;
}

// Helper: compute lock file path

static void open_lock_file(ResiliencyTestCtx &ctx)
{
    ctx.lock_path = (ctx.temp_dir / ".lock").string();
}

void make_resiliency_config_in(ResiliencyTestCtx &ctx, azihsm_resiliency_config &config_out)
{
    open_lock_file(ctx);

    static azihsm_resiliency_storage_ops storage_ops = { storage_read,
                                                         storage_write,
                                                         storage_clear };

    static azihsm_resiliency_lock_ops lock_ops = { lock_acquire, lock_release };

    config_out.ctx = &ctx;
    config_out.storage_ops = storage_ops;
    config_out.lock_ops = lock_ops;

    // When POTA source is TPM, pota_callback_ops must be null.
#ifdef _WIN32
    char *use_tpm = nullptr;
    size_t use_tpm_len = 0;
    _dupenv_s(&use_tpm, &use_tpm_len, "AZIHSM_USE_TPM");
    bool is_tpm = (use_tpm != nullptr);
    free(use_tpm);
#else
    bool is_tpm = (std::getenv("AZIHSM_USE_TPM") != nullptr);
#endif
    config_out.pota_callback_ops = is_tpm ? nullptr : get_pota_callback_ops();
    config_out.obk_callback_ops = is_tpm ? nullptr : get_obk_callback_ops();
}

/// Returns a pointer to the shared POTA callback ops vtable backed by
/// `pota_endorse`. The returned pointer has static lifetime.
const azihsm_pota_callback_ops *get_pota_callback_ops()
{
    static azihsm_pota_callback_ops pota_ops = { pota_endorse };
    return &pota_ops;
}

/// Returns a pointer to the shared OBK callback ops vtable backed by
/// `obk_get_obk`. The returned pointer has static lifetime.
const azihsm_obk_callback_ops *get_obk_callback_ops()
{
    static azihsm_obk_callback_ops obk_ops = { obk_get_obk };
    return &obk_ops;
}

std::unique_ptr<ResiliencyTestCtx> make_resiliency_config(azihsm_resiliency_config &config_out)
{
    // Each call gets a unique directory so parallel tests never interfere.
    static std::atomic<uint32_t> seq{ 0 };
    auto id = std::to_string(seq.fetch_add(1)) + "_" +
              std::to_string(
#ifdef _WIN32
                  GetCurrentProcessId()
#else
                  getpid()
#endif
              );
    auto tmp = fs::temp_directory_path() / (std::string(RESILIENCY_DIR_NAME) + "_" + id);

    // Wipe any stale data from a previous crashed run, then recreate empty.
    std::error_code ec;
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp);

    auto ctx = std::make_unique<ResiliencyTestCtx>();
    ctx->temp_dir = tmp;

    make_resiliency_config_in(*ctx, config_out);

    return ctx;
}
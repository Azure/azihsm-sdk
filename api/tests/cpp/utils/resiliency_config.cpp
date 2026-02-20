// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "resiliency_config.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

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

static azihsm_status storage_read(
    void *ctx, const char *key, azihsm_buffer *output)
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

static azihsm_status storage_write(
    void *ctx, const char *key, const azihsm_buffer *data)
{
    auto path = key_path(ctx, key);

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (data->len > 0)
    {
        ofs.write(static_cast<const char *>(data->ptr),
                  static_cast<std::streamsize>(data->len));
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
    OVERLAPPED ov = {};
    if (!LockFileEx(test_ctx->lock_handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov))
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
#else
    if (flock(test_ctx->lock_fd, LOCK_EX) != 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
#endif
    return AZIHSM_STATUS_SUCCESS;
}

static azihsm_status lock_release(void *ctx)
{
    auto *test_ctx = static_cast<ResiliencyTestCtx *>(ctx);
#ifdef _WIN32
    OVERLAPPED ov = {};
    if (!UnlockFileEx(test_ctx->lock_handle, 0, 1, 0, &ov))
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
#else
    if (flock(test_ctx->lock_fd, LOCK_UN) != 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
#endif
    return AZIHSM_STATUS_SUCCESS;
}

// Dummy POTA endorsement callback
static constexpr uint32_t DUMMY_SIG_SIZE = 96;
static constexpr uint32_t DUMMY_PUB_SIZE = 120;

static azihsm_status pota_endorse(
    void * /*ctx*/,
    const azihsm_buffer * /*pub_key*/,
    azihsm_buffer *signature,
    azihsm_buffer *endorsement_pub_key)
{
    // First call: report required sizes.
    if (signature->ptr == nullptr || signature->len < DUMMY_SIG_SIZE ||
        endorsement_pub_key->ptr == nullptr || endorsement_pub_key->len < DUMMY_PUB_SIZE)
    {
        signature->len = DUMMY_SIG_SIZE;
        endorsement_pub_key->len = DUMMY_PUB_SIZE;
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    // Second call: fill buffers.
    std::memset(signature->ptr, 0, DUMMY_SIG_SIZE);
    std::memset(endorsement_pub_key->ptr, 0, DUMMY_PUB_SIZE);
    signature->len = DUMMY_SIG_SIZE;
    endorsement_pub_key->len = DUMMY_PUB_SIZE;
    return AZIHSM_STATUS_SUCCESS;
}

// ─── Helper: open lock file into ctx ─────────────────────────────

static void open_lock_file(ResiliencyTestCtx &ctx)
{
    ctx.lock_path = (ctx.temp_dir / ".lock").string();

#ifdef _WIN32
    ctx.lock_handle = CreateFileA(
        ctx.lock_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
#else
    ctx.lock_fd = open(ctx.lock_path.c_str(), O_CREAT | O_RDWR, 0600);
#endif
}

void make_resiliency_config_in(
    ResiliencyTestCtx &ctx,
    azihsm_resiliency_config &config_out)
{
    open_lock_file(ctx);

    static azihsm_resiliency_storage_ops storage_ops = {
        storage_read, storage_write, storage_clear};

    static azihsm_resiliency_lock_ops lock_ops = {
        lock_acquire, lock_release};

    static azihsm_pota_callback_ops pota_ops = {
        pota_endorse};

    config_out.ctx = &ctx;
    config_out.storage_ops = storage_ops;
    config_out.lock_ops = lock_ops;
    config_out.pota_callback_ops = &pota_ops;
}

std::unique_ptr<ResiliencyTestCtx> make_resiliency_config(
    azihsm_resiliency_config &config_out)
{
    auto tmp = fs::temp_directory_path() / RESILIENCY_DIR_NAME;

    // Wipe any stale data from a previous crashed run, then recreate empty.
    std::error_code ec;
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp);

    auto ctx = std::make_unique<ResiliencyTestCtx>();
    ctx->temp_dir = tmp;

    make_resiliency_config_in(*ctx, config_out);

    return ctx;
}
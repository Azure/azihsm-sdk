// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// @file resiliency_stress_helpers.hpp
///
/// Shared infrastructure for native C API resiliency stress tests.
///
/// Provides:
///   - resiliency_stress_base: GTest fixture that initialises a partition
///     with resiliency enabled (reusing the existing resiliency_config.hpp
///     storage/lock/POTA/OBK callbacks — the same callback infrastructure
///     used by the OSSL CAPI resiliency tests) and opens a session.
///   - A background Reset thread helper.
///   - Tuning constants aligned with the Rust stress tests
///     (api/tests/src/resiliency/stress/tests.rs) and the OSSL CAPI
///     resiliency tests.
///
/// ## Scope
///
/// These tests cover partition-level and key-operation resiliency under
/// continuous resets, mirroring the Rust stress tests in
/// api/tests/src/resiliency/stress/tests.rs and the OSSL CAPI resiliency
/// tests in plugins/ossl_prov/integration-tests/.

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <azihsm_api.h>

#include "handle/part_list_handle.hpp"
#include "handle/test_creds.hpp"
#include "utils/part_init_config.hpp"
#include "utils/resiliency_config.hpp"
#include "utils/utils.hpp"

/* ------------------------------------------------------------------ */
/*  Tuning constants                                                   */
/* ------------------------------------------------------------------ */

// Aligned with the Rust resiliency stress tests and the OSSL CAPI tests.
// Mock backoff base is 8 ms, so 1 s between resets gives plenty of time
// for recovery while still exercising the retry path.
static constexpr auto RESET_INTERVAL = std::chrono::milliseconds(1000);
static constexpr auto WORKER_SLEEP = std::chrono::milliseconds(10);
static constexpr uint32_t STRESS_OPS = 500;
static constexpr uint32_t NUM_WORKERS = 8;

/* ------------------------------------------------------------------ */
/*  Test fixture                                                       */
/* ------------------------------------------------------------------ */

/// Base fixture for native C API resiliency stress tests.
///
/// For each partition:
///   1. Opens a partition handle.
///   2. Resets the partition to a clean state.
///   3. Initializes with resiliency enabled (using the existing
///      resiliency_config.hpp file-backed storage, flock-based lock,
///      and real POTA signing/OBK callbacks — the same callback
///      infrastructure used by the OSSL CAPI resiliency tests).
///   4. Opens a session.
///
/// Derived test fixtures call run_under_reset() to exercise operations
/// while a background thread fires partition resets.
class resiliency_stress_base : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_;

    /// Helper: open a separate partition handle for issuing resets.
    /// Uses the same path as the main handle but a separate handle so
    /// that reset() does not contend with the main partition's RW lock.
    static azihsm_handle open_reset_handle(const std::vector<azihsm_char> &path)
    {
        azihsm_str path_str = { const_cast<azihsm_char *>(path.data()),
                                static_cast<uint32_t>(path.size()) };
        azihsm_handle h = 0;
        auto err = azihsm_part_open(&path_str, &h, test_api_rev());
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to open reset partition handle. Error: " + std::to_string(err)
            );
        }
        return h;
    }

    /// Helper: open, reset, and init-with-resiliency a partition.
    /// Returns the partition handle (caller must close), session handle
    /// (caller must close), and the resiliency context (caller must keep
    /// alive until after partition close).
    struct InitResult
    {
        azihsm_handle part = 0;
        azihsm_handle session = 0;
        std::unique_ptr<ResiliencyTestCtx> resiliency_ctx;
    };

    static InitResult init_partition_with_resiliency(const std::vector<azihsm_char> &path)
    {
        InitResult r;

        azihsm_str path_str = { const_cast<azihsm_char *>(path.data()),
                                static_cast<uint32_t>(path.size()) };
        auto err = azihsm_part_open(&path_str, &r.part, test_api_rev());
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS) << "part_open failed";
        if (err != AZIHSM_STATUS_SUCCESS)
            return r;

        err = azihsm_part_reset(r.part);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS) << "part_reset failed";
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(r.part);
            r.part = 0;
            return r;
        }

        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        PartInitConfig init_config{};
        make_part_init_config(r.part, init_config);

        azihsm_resiliency_config resiliency_config{};
        r.resiliency_ctx = make_resiliency_config(resiliency_config);

        err = azihsm_part_init(
            r.part,
            &creds,
            nullptr,
            nullptr,
            &init_config.backup_config,
            &init_config.pota_endorsement,
            &resiliency_config
        );
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS) << "part_init with resiliency failed";
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(r.part);
            r.part = 0;
            return r;
        }

        err = azihsm_sess_open(r.part, &creds, nullptr, &r.session);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS) << "sess_open failed";
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(r.part);
            r.part = 0;
            return r;
        }

        return r;
    }

    /// Run `worker_fn` while a background thread fires partition resets.
    ///
    /// @param reset_handle       Separate partition handle used only for resets.
    /// @param worker_fn          Callback that performs the stressed operations;
    ///                           returns the number of successful operations.
    /// @param expected_ops       Total number of operation attempts.
    /// @param max_allowed_fails  Maximum transient failures tolerated (default 0).
    ///                           Some operations (e.g. init_part) may see rare
    ///                           DDI_CMD_FAILURE (-8) when a reset races with
    ///                           the DDI call. These are genuine transient errors
    ///                           that the SDK does not retry (not in the retryable
    ///                           set). A small tolerance avoids flaky tests.
    void run_under_reset(
        azihsm_handle reset_handle,
        const std::function<uint32_t()> &worker_fn,
        uint32_t expected_ops,
        uint32_t max_allowed_fails = 0
    )
    {
        std::atomic<bool> stop{ false };
        std::atomic<uint32_t> reset_count{ 0 };

        std::thread reset_thread([&] {
            while (!stop.load(std::memory_order_relaxed))
            {
                if (azihsm_part_reset(reset_handle) == AZIHSM_STATUS_SUCCESS)
                {
                    reset_count.fetch_add(1, std::memory_order_relaxed);
                }
                std::this_thread::sleep_for(RESET_INTERVAL);
            }
        });

        uint32_t ok_count = worker_fn();

        stop.store(true, std::memory_order_relaxed);
        reset_thread.join();

        uint32_t min_expected = expected_ops - max_allowed_fails;
        EXPECT_GE(ok_count, min_expected) << "Too many operations failed (ok=" << ok_count
                                          << ", min_expected=" << min_expected << ")";
        EXPECT_GT(reset_count.load(), 0u)
            << "Reset thread should have triggered at least one reset";
    }
};

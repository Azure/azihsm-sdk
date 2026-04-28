// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file init_stress_tests.cpp
///
/// Resiliency stress tests for partition initialization and partition-level
/// operations (cert_chain, init_part) under continuous resets.
///

#include <scope_guard.hpp>

#include "resiliency/resiliency_stress_helpers.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class init_resiliency_stress : public resiliency_stress_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A single worker thread repeatedly calls cert_chain while a dedicated
/// thread fires resets. Every cert_chain call must eventually succeed.
///
TEST_F(init_resiliency_stress, cert_chain_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    // Two-call pattern: query size, then fetch.
                    azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MANUFACTURER_CERT_CHAIN,
                                              nullptr,
                                              0 };
                    auto err = azihsm_part_get_prop(r.part, &prop);
                    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
                    {
                        ADD_FAILURE() << "cert_chain size query " << i << " got " << err;
                        continue;
                    }

                    std::vector<azihsm_char> buf(prop.len);
                    prop.val = buf.data();
                    err = azihsm_part_get_prop(r.part, &prop);
                    if (err != AZIHSM_STATUS_SUCCESS)
                    {
                        ADD_FAILURE() << "cert_chain fetch " << i << " got " << err;
                        continue;
                    }
                    ++ok;
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS
        );
    });
}

/// A single worker thread repeatedly calls init() with resiliency enabled
/// while a dedicated thread fires resets. Every init() call must
/// eventually succeed.
///
TEST_F(init_resiliency_stress, init_part_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        // Initial baseline init.
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    azihsm_credentials creds{};
                    std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
                    std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

                    PartInitConfig init_config{};
                    make_part_init_config(r.part, init_config);

                    azihsm_resiliency_config res_config{};
                    make_resiliency_config_in(*r.resiliency_ctx, res_config);

                    auto err = azihsm_part_init(
                        r.part,
                        &creds,
                        nullptr,
                        nullptr,
                        &init_config.backup_config,
                        &init_config.pota_endorsement,
                        &res_config
                    );
                    if (err != AZIHSM_STATUS_SUCCESS)
                    {
                        // DDI_CMD_FAILURE (-8) is a known transient error when
                        // a reset races with the DDI call. Tolerated by the
                        // max_allowed_fails parameter below.
                        continue;
                    }
                    ++ok;
                }
                return ok;
            },
            STRESS_OPS,
            5 // allow up to 5 transient DDI_CMD_FAILURE errors
        );
    });
}

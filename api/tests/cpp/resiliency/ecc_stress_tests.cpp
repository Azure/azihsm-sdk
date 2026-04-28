// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file ecc_stress_tests.cpp
///
/// Resiliency stress tests for ECC sign/verify and ECC key generation
/// under continuous partition resets.
///

#include <scope_guard.hpp>

#include "algo/ecc/helpers.hpp"
#include "handle/session_handle.hpp"
#include "resiliency/resiliency_stress_helpers.hpp"
#include "utils/auto_key.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ecc_resiliency_stress : public resiliency_stress_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// ECC sign under continuous Reset.
///
TEST_F(ecc_resiliency_stress, ecc_sign_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            r.session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                const std::vector<uint8_t> message(64, 0x42);

                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    std::vector<uint8_t> signature;
                    auto sign_err = ecdsa_sign_sha256(priv_key.get(), message, signature);
                    if (sign_err == AZIHSM_STATUS_SUCCESS)
                        ++ok;
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS,
            5
        );
    });
}

/// ECC sign + verify under continuous Reset.
///
TEST_F(ecc_resiliency_stress, ecc_sign_verify_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            r.session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                const std::vector<uint8_t> message(64, 0x42);

                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    std::vector<uint8_t> signature;
                    auto sign_err = ecdsa_sign_sha256(priv_key.get(), message, signature);
                    if (sign_err != AZIHSM_STATUS_SUCCESS)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    auto verify_err = ecdsa_verify_sha256(pub_key.get(), message, signature);
                    if (verify_err == AZIHSM_STATUS_SUCCESS)
                        ++ok;
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS,
            5
        );
    });
}

/// ECC P-256 key-pair generation under continuous Reset.
///
TEST_F(ecc_resiliency_stress, ecc_key_gen_under_reset)
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
                    auto_key priv_key;
                    auto_key pub_key;
                    auto gen_err = generate_ecc_keypair(
                        r.session,
                        AZIHSM_ECC_CURVE_P256,
                        true,
                        priv_key.get_ptr(),
                        pub_key.get_ptr()
                    );
                    if (gen_err == AZIHSM_STATUS_SUCCESS)
                        ++ok;
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS,
            5
        );
    });
}

/// ECC key attestation (key report) under continuous Reset.
///
TEST_F(ecc_resiliency_stress, ecc_key_report_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            r.session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                std::vector<uint8_t> report_data(128, 0x42);

                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    azihsm_buffer report_data_buf = { report_data.data(),
                                                      static_cast<uint32_t>(report_data.size()) };

                    // Size query.
                    azihsm_buffer report_buf = { nullptr, 0 };
                    auto size_err =
                        azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
                    if (size_err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    // Fetch report.
                    std::vector<uint8_t> report(report_buf.len);
                    report_buf.ptr = report.data();
                    auto fetch_err =
                        azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
                    if (fetch_err == AZIHSM_STATUS_SUCCESS)
                        ++ok;
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS,
            5
        );
    });
}

/// ECC key unmask under continuous Reset.
///
TEST_F(ecc_resiliency_stress, ecc_unmask_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        // Generate key and get its masked blob.
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            r.session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> masked_blob;
        err = get_masked_key_blob(priv_key.get(), masked_blob);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(masked_blob.empty());

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    azihsm_buffer masked_buf = { masked_blob.data(),
                                                 static_cast<uint32_t>(masked_blob.size()) };
                    azihsm_handle unmasked_priv = 0;
                    azihsm_handle unmasked_pub = 0;

                    auto unmask_err = azihsm_key_unmask_pair(
                        r.session,
                        AZIHSM_KEY_KIND_ECC,
                        &masked_buf,
                        &unmasked_priv,
                        &unmasked_pub
                    );
                    if (unmask_err == AZIHSM_STATUS_SUCCESS)
                    {
                        azihsm_key_delete(unmasked_priv);
                        azihsm_key_delete(unmasked_pub);
                        ++ok;
                    }
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS,
            5
        );
    });
}

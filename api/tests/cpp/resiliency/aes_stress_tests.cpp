// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file aes_stress_tests.cpp
///
/// Resiliency stress tests for AES-CBC encrypt/decrypt and AES key
/// generation under continuous partition resets.
///

#include <scope_guard.hpp>

#include "algo/aes/helpers.hpp"
#include "handle/key_handle.hpp"
#include "handle/session_handle.hpp"
#include "resiliency/resiliency_stress_helpers.hpp"
#include "utils/auto_key.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class aes_resiliency_stress : public resiliency_stress_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// AES-CBC encrypt under continuous Reset.
///
TEST_F(aes_resiliency_stress, aes_cbc_encrypt_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        // Generate AES-256 key before resets start.
        auto aes_key = generate_aes_key(r.session, 256);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                std::vector<uint8_t> plaintext(32, 0xAB);

                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    azihsm_algo_aes_cbc_params params{};
                    params.iv[0] = static_cast<uint8_t>(i & 0xFF);
                    azihsm_algo algo = { AZIHSM_ALGO_ID_AES_CBC_PAD, &params, sizeof(params) };

                    std::vector<uint8_t> ciphertext;
                    auto err = single_shot_crypt(
                        CryptOperation::Encrypt,
                        aes_key.get(),
                        &algo,
                        plaintext.data(),
                        plaintext.size(),
                        ciphertext
                    );
                    if (err == AZIHSM_STATUS_SUCCESS)
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

/// AES-CBC encrypt + decrypt round-trip under continuous Reset.
///
TEST_F(aes_resiliency_stress, aes_cbc_round_trip_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto aes_key = generate_aes_key(r.session, 256);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                std::vector<uint8_t> plaintext(32, 0xCD);

                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    uint8_t iv_fill = static_cast<uint8_t>(i & 0xFF);

                    // Encrypt.
                    azihsm_algo_aes_cbc_params enc_params{};
                    enc_params.iv[0] = iv_fill;
                    azihsm_algo enc_algo = { AZIHSM_ALGO_ID_AES_CBC_PAD,
                                             &enc_params,
                                             sizeof(enc_params) };
                    std::vector<uint8_t> ciphertext;
                    auto err = single_shot_crypt(
                        CryptOperation::Encrypt,
                        aes_key.get(),
                        &enc_algo,
                        plaintext.data(),
                        plaintext.size(),
                        ciphertext
                    );
                    if (err != AZIHSM_STATUS_SUCCESS)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    // Decrypt.
                    azihsm_algo_aes_cbc_params dec_params{};
                    dec_params.iv[0] = iv_fill;
                    azihsm_algo dec_algo = { AZIHSM_ALGO_ID_AES_CBC_PAD,
                                             &dec_params,
                                             sizeof(dec_params) };
                    std::vector<uint8_t> decrypted;
                    err = single_shot_crypt(
                        CryptOperation::Decrypt,
                        aes_key.get(),
                        &dec_algo,
                        ciphertext.data(),
                        ciphertext.size(),
                        decrypted
                    );
                    if (err != AZIHSM_STATUS_SUCCESS)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    EXPECT_EQ(decrypted, plaintext) << "AES round-trip mismatch " << i;
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

/// AES key generation under continuous Reset.
///
TEST_F(aes_resiliency_stress, key_gen_under_reset)
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
                    azihsm_algo keygen_algo = { AZIHSM_ALGO_ID_AES_KEY_GEN, nullptr, 0 };

                    uint32_t key_class = AZIHSM_KEY_CLASS_SECRET;
                    uint32_t key_kind = AZIHSM_KEY_KIND_AES;
                    uint32_t bits = 256;
                    uint8_t session_flag = 1;
                    uint8_t encrypt_flag = 1;
                    uint8_t decrypt_flag = 1;

                    azihsm_key_prop props[] = {
                        { AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) },
                        { AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) },
                        { AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) },
                        { AZIHSM_KEY_PROP_ID_SESSION, &session_flag, sizeof(session_flag) },
                        { AZIHSM_KEY_PROP_ID_ENCRYPT, &encrypt_flag, sizeof(encrypt_flag) },
                        { AZIHSM_KEY_PROP_ID_DECRYPT, &decrypt_flag, sizeof(decrypt_flag) },
                    };
                    azihsm_key_prop_list prop_list = { props, 6 };

                    azihsm_handle key_handle = 0;
                    auto err = azihsm_key_gen(r.session, &keygen_algo, &prop_list, &key_handle);
                    if (err == AZIHSM_STATUS_SUCCESS)
                    {
                        azihsm_key_delete(key_handle);
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

/// Rapid reset between operations: a single worker alternates between
/// AES-CBC encrypt and an explicit reset, validating recovery.
///
TEST_F(aes_resiliency_stress, rapid_reset_between_ops)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        auto aes_key = generate_aes_key(r.session, 256);

        // No separate reset thread — the worker fires resets itself.
        constexpr uint32_t RAPID_ITERATIONS = 10;
        std::vector<uint8_t> plaintext(32, 0xBB);

        for (uint32_t i = 0; i < RAPID_ITERATIONS; ++i)
        {
            // Fire a reset.
            auto reset_err = azihsm_part_reset(r.part);
            ASSERT_EQ(reset_err, AZIHSM_STATUS_SUCCESS) << "Reset " << i << " failed";

            // Wait for the device to settle.
            std::this_thread::sleep_for(RESET_INTERVAL);

            // The next encrypt must recover via the retry path.
            azihsm_algo_aes_cbc_params params{};
            params.iv[0] = static_cast<uint8_t>(i);
            azihsm_algo algo = { AZIHSM_ALGO_ID_AES_CBC_PAD, &params, sizeof(params) };
            std::vector<uint8_t> ciphertext;
            auto enc_err = single_shot_crypt(
                CryptOperation::Encrypt,
                aes_key.get(),
                &algo,
                plaintext.data(),
                plaintext.size(),
                ciphertext
            );
            ASSERT_EQ(enc_err, AZIHSM_STATUS_SUCCESS)
                << "AES encrypt after reset " << i << " failed: " << enc_err;
        }
    });
}

/// Key deletion after Reset (epoch-aware).
///
TEST_F(aes_resiliency_stress, delete_key_under_reset)
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
                    azihsm_algo keygen_algo = { AZIHSM_ALGO_ID_AES_KEY_GEN, nullptr, 0 };

                    uint32_t key_class = AZIHSM_KEY_CLASS_SECRET;
                    uint32_t key_kind = AZIHSM_KEY_KIND_AES;
                    uint32_t bits = 256;
                    uint8_t session_flag = 1;
                    uint8_t encrypt_flag = 1;
                    uint8_t decrypt_flag = 1;

                    azihsm_key_prop props[] = {
                        { AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) },
                        { AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) },
                        { AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) },
                        { AZIHSM_KEY_PROP_ID_SESSION, &session_flag, sizeof(session_flag) },
                        { AZIHSM_KEY_PROP_ID_ENCRYPT, &encrypt_flag, sizeof(encrypt_flag) },
                        { AZIHSM_KEY_PROP_ID_DECRYPT, &decrypt_flag, sizeof(decrypt_flag) },
                    };
                    azihsm_key_prop_list prop_list = { props, 6 };

                    azihsm_handle key_handle = 0;
                    auto gen_err = azihsm_key_gen(r.session, &keygen_algo, &prop_list, &key_handle);
                    if (gen_err != AZIHSM_STATUS_SUCCESS)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    auto del_err = azihsm_key_delete(key_handle);
                    if (del_err == AZIHSM_STATUS_SUCCESS)
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

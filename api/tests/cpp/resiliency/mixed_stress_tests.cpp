// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file mixed_stress_tests.cpp
///
/// Cross-cutting resiliency stress tests: mixed operations (AES encrypt,
/// ECC sign, key generation) and HMAC operations under continuous
/// partition resets.
///

#include <scope_guard.hpp>

#include "algo/aes/helpers.hpp"
#include "algo/ecc/helpers.hpp"
#include "algo/hmac/helpers.hpp"
#include "handle/key_handle.hpp"
#include "handle/session_handle.hpp"
#include "resiliency/resiliency_stress_helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class mixed_resiliency_stress : public resiliency_stress_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Mixed operations under continuous Reset: AES-CBC encrypt, ECC sign,
/// and ECC keygen are interleaved in the same loop.
///
TEST_F(mixed_resiliency_stress, mixed_ops_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        // Pre-generate keys.
        auto aes_key = generate_aes_key(r.session, 256);
        auto_key ecc_priv;
        auto_key ecc_pub;
        auto err = generate_ecc_keypair(
            r.session,
            AZIHSM_ECC_CURVE_P256,
            true,
            ecc_priv.get_ptr(),
            ecc_pub.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                std::vector<uint8_t> plaintext(32, 0xEF);
                std::vector<uint8_t> message(64, 0x42);

                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    bool iter_ok = true;

                    // AES-CBC encrypt.
                    azihsm_algo_aes_cbc_params params{};
                    params.iv[0] = static_cast<uint8_t>(i & 0xFF);
                    azihsm_algo algo = { AZIHSM_ALGO_ID_AES_CBC_PAD, &params, sizeof(params) };
                    std::vector<uint8_t> ciphertext;
                    auto aes_err = single_shot_crypt(
                        CryptOperation::Encrypt,
                        aes_key.get(),
                        &algo,
                        plaintext.data(),
                        plaintext.size(),
                        ciphertext
                    );
                    if (aes_err != AZIHSM_STATUS_SUCCESS)
                        iter_ok = false;

                    // ECC sign.
                    std::vector<uint8_t> signature;
                    auto sign_err = ecdsa_sign_sha256(ecc_priv.get(), message, signature);
                    if (sign_err != AZIHSM_STATUS_SUCCESS)
                        iter_ok = false;

                    // ECC keygen.
                    auto_key fresh_priv;
                    auto_key fresh_pub;
                    auto gen_err = generate_ecc_keypair(
                        r.session,
                        AZIHSM_ECC_CURVE_P256,
                        true,
                        fresh_priv.get_ptr(),
                        fresh_pub.get_ptr()
                    );
                    if (gen_err != AZIHSM_STATUS_SUCCESS)
                        iter_ok = false;

                    if (iter_ok)
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

/// HMAC sign under continuous Reset.
///
TEST_F(mixed_resiliency_stress, hmac_sign_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        // Generate HMAC key via ECDH + HKDF using derive-capable key pairs.
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;
        auto err = generate_ecdh_keys_and_derive_hmac(
            r.session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    std::string msg_str = "hmac stress " + std::to_string(i);
                    azihsm_buffer data_buf = { reinterpret_cast<uint8_t *>(msg_str.data()),
                                               static_cast<uint32_t>(msg_str.size()) };

                    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };

                    // Size query.
                    azihsm_buffer sig_buf = { nullptr, 0 };
                    auto size_err =
                        azihsm_crypt_sign(&sign_algo, hmac_key.get(), &data_buf, &sig_buf);
                    if (size_err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    std::vector<uint8_t> signature(sig_buf.len);
                    sig_buf.ptr = signature.data();
                    auto sign_err =
                        azihsm_crypt_sign(&sign_algo, hmac_key.get(), &data_buf, &sig_buf);
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

/// HMAC sign + verify under continuous Reset.
///
TEST_F(mixed_resiliency_stress, hmac_sign_verify_under_reset)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { azihsm_sess_close(r.session); });

        // Generate HMAC key via ECDH + HKDF using derive-capable key pairs.
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;
        auto err = generate_ecdh_keys_and_derive_hmac(
            r.session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { azihsm_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    std::string msg_str = "hmac verify stress " + std::to_string(i);
                    azihsm_buffer data_buf = { reinterpret_cast<uint8_t *>(msg_str.data()),
                                               static_cast<uint32_t>(msg_str.size()) };

                    azihsm_algo sign_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };

                    // Sign: size query.
                    azihsm_buffer sig_buf = { nullptr, 0 };
                    auto size_err =
                        azihsm_crypt_sign(&sign_algo, hmac_key.get(), &data_buf, &sig_buf);
                    if (size_err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    std::vector<uint8_t> signature(sig_buf.len);
                    sig_buf.ptr = signature.data();
                    auto sign_err =
                        azihsm_crypt_sign(&sign_algo, hmac_key.get(), &data_buf, &sig_buf);
                    if (sign_err != AZIHSM_STATUS_SUCCESS)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    // Verify.
                    azihsm_algo verify_algo = { AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, 0 };
                    auto verify_err =
                        azihsm_crypt_verify(&verify_algo, hmac_key.get(), &data_buf, &sig_buf);
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

/// Keygen + immediate delete under continuous Reset.
///
TEST_F(mixed_resiliency_stress, keygen_delete_under_reset)
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
                    // Generate an ECC key pair.
                    auto_key priv_key;
                    auto_key pub_key;
                    auto gen_err = generate_ecc_keypair(
                        r.session,
                        AZIHSM_ECC_CURVE_P256,
                        true,
                        priv_key.get_ptr(),
                        pub_key.get_ptr()
                    );
                    if (gen_err != AZIHSM_STATUS_SUCCESS)
                    {
                        std::this_thread::sleep_for(WORKER_SLEEP);
                        continue;
                    }

                    // Immediately delete.
                    auto del_priv = azihsm_key_delete(priv_key.release());
                    auto del_pub = azihsm_key_delete(pub_key.release());
                    if (del_priv == AZIHSM_STATUS_SUCCESS && del_pub == AZIHSM_STATUS_SUCCESS)
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

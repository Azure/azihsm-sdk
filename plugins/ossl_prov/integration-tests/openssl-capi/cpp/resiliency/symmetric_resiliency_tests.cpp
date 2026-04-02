// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file symmetric_resiliency_tests.cpp
///
/// Resiliency stress tests for symmetric / hash operations: digest (SHA),
/// HMAC, and HKDF key derivation — all under concurrent partition resets.

#include <cstdlib>
#include <openssl/kdf.h>
#include <unistd.h>

#include "resiliency_helpers.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class symmetric_resiliency : public resiliency_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// SHA digest operations survive concurrent partition resets.
TEST_F(symmetric_resiliency, digest_survives_resets)
{
    ResetHandle rh(api());

    // Background reset thread.
    std::atomic<bool> stop{ false };
    std::atomic<uint32_t> reset_count{ 0 };

    std::thread reset_thread([&] {
        while (!stop.load())
        {
            if (api().reset(rh.h) == HSM_OK)
                reset_count.fetch_add(1);
            std::this_thread::sleep_for(RESET_INTERVAL);
        }
    });

    // Cycle through SHA variants; digest doesn't need key recovery.
    const char *algos[] = { "SHA256", "SHA384", "SHA512" };
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < STRESS_OPS; ++i)
    {
        bool ok = digest_roundtrip(libctx(), algos[i % 3]);
        EXPECT_TRUE(ok) << "digest op " << i << " (" << algos[i % 3] << ") failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, STRESS_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// HKDF key derivation from an ECDH shared secret survives concurrent resets.
TEST_F(symmetric_resiliency, hkdf_derive_survives_resets)
{
    ResetHandle rh(api());

    std::atomic<bool> stop{ false };
    std::atomic<uint32_t> reset_count{ 0 };

    std::thread reset_thread([&] {
        while (!stop.load())
        {
            if (api().reset(rh.h) == HSM_OK)
                reset_count.fetch_add(1);
            std::this_thread::sleep_for(RESET_INTERVAL);
        }
    });

    constexpr uint32_t NUM_OPS = STRESS_OPS / 4;
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < NUM_OPS; ++i)
    {
        bool ok = false;

        // Produce ECDH shared secret as IKM for HKDF.
        std::string ecdh_file = derive_masked_key_file(libctx(), "P-256");
        if (ecdh_file.empty())
        {
            EXPECT_FALSE(ecdh_file.empty()) << "ECDH " << i << " failed";
            std::this_thread::sleep_for(WORKER_SLEEP);
            continue;
        }

        // Derive an AES-256 key via HKDF.
        char output_path[] = "/tmp/azihsm_resil_hkdf_XXXXXX";
        int fd = mkstemp(output_path);
        if (fd >= 0)
        {
            ::close(fd);
            ::unlink(output_path);

            EvpKdfPtr kdf(EVP_KDF_fetch(libctx(), "HKDF", ProviderCtx::propquery()));
            EvpKdfCtxPtr kctx(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr);
            if (kctx)
            {
                char digest[] = "SHA256";
                char derived_type[] = "aes";
                uint32_t derived_bits = 256;

                OSSL_PARAM params[] = {
                    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
                    OSSL_PARAM_utf8_string(
                        "azihsm.ikm_file",
                        const_cast<char *>(ecdh_file.c_str()),
                        0
                    ),
                    OSSL_PARAM_utf8_string("output_file", output_path, 0),
                    OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
                    OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
                    OSSL_PARAM_END,
                };

                unsigned char dummy[4096];
                ok = EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params) == 1;
            }
            ::unlink(output_path);
        }
        ::unlink(ecdh_file.c_str());

        EXPECT_TRUE(ok) << "HKDF derive " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, NUM_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// HMAC computation with a derived key survives concurrent partition resets.
TEST_F(symmetric_resiliency, hmac_survives_resets)
{
    ResetHandle rh(api());

    std::atomic<bool> stop{ false };
    std::atomic<uint32_t> reset_count{ 0 };

    std::thread reset_thread([&] {
        while (!stop.load())
        {
            if (api().reset(rh.h) == HSM_OK)
                reset_count.fetch_add(1);
            std::this_thread::sleep_for(RESET_INTERVAL);
        }
    });

    constexpr uint32_t NUM_OPS = STRESS_OPS / 4;
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < NUM_OPS; ++i)
    {
        bool ok = false;

        // Derive HMAC key via ECDH → HKDF chain.
        std::string ecdh_file = derive_masked_key_file(libctx(), "P-256");
        if (ecdh_file.empty())
        {
            EXPECT_FALSE(ecdh_file.empty()) << "ECDH " << i << " failed";
            std::this_thread::sleep_for(WORKER_SLEEP);
            continue;
        }

        char hmac_key_path[] = "/tmp/azihsm_resil_hmac_key_XXXXXX";
        int fd = mkstemp(hmac_key_path);
        if (fd >= 0)
        {
            ::close(fd);
            ::unlink(hmac_key_path);

            EvpKdfPtr kdf(EVP_KDF_fetch(libctx(), "HKDF", ProviderCtx::propquery()));
            EvpKdfCtxPtr kctx(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr);
            if (kctx)
            {
                char digest[] = "SHA256";
                char derived_type[] = "hmac";
                uint32_t derived_bits = 256;

                OSSL_PARAM params[] = {
                    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
                    OSSL_PARAM_utf8_string(
                        "azihsm.ikm_file",
                        const_cast<char *>(ecdh_file.c_str()),
                        0
                    ),
                    OSSL_PARAM_utf8_string("output_file", hmac_key_path, 0),
                    OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
                    OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
                    OSSL_PARAM_END,
                };

                unsigned char dummy[4096];
                if (EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params) == 1)
                {
                    // Compute HMAC-SHA256 over test data using the derived key.
                    EvpMacPtr mac(EVP_MAC_fetch(libctx(), "HMAC", ProviderCtx::propquery()));
                    EvpMacCtxPtr mctx(mac ? EVP_MAC_CTX_new(mac.get()) : nullptr);
                    if (mctx)
                    {
                        char mac_digest[] = "SHA256";
                        OSSL_PARAM mac_params[] = {
                            OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, mac_digest, 0),
                            OSSL_PARAM_octet_string(
                                OSSL_MAC_PARAM_KEY,
                                hmac_key_path,
                                std::strlen(hmac_key_path)
                            ),
                            OSSL_PARAM_END,
                        };

                        const std::string data = "resiliency HMAC test data";
                        if (EVP_MAC_init(mctx.get(), nullptr, 0, mac_params) == 1 &&
                            EVP_MAC_update(
                                mctx.get(),
                                reinterpret_cast<const unsigned char *>(data.data()),
                                data.size()
                            ) == 1)
                        {
                            size_t mac_len = 0;
                            if (EVP_MAC_final(mctx.get(), nullptr, &mac_len, 0) == 1 && mac_len > 0)
                            {
                                std::vector<unsigned char> mac_out(mac_len);
                                ok = EVP_MAC_final(
                                         mctx.get(),
                                         mac_out.data(),
                                         &mac_len,
                                         mac_out.size()
                                     ) == 1;
                            }
                        }
                    }
                }
            }
            ::unlink(hmac_key_path);
        }
        ::unlink(ecdh_file.c_str());

        EXPECT_TRUE(ok) << "HMAC " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, NUM_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

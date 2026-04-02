// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file ec_resiliency_tests.cpp
///
/// EC resiliency stress tests: ECDSA sign/verify, EC keygen, multi-thread
/// ECDSA, ECDH key exchange, and ECDH+HKDF+HMAC chain — all under concurrent
/// partition resets.

#include <cstdlib>
#include <openssl/kdf.h>
#include <unistd.h>

#include "resiliency_helpers.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ec_resiliency : public resiliency_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// ECDSA sign/verify round-trips survive concurrent partition resets.
TEST_F(ec_resiliency, ecdsa_sign_verify_survives_resets)
{
    // Generate a session key before resets start.
    auto pkey = generate_ec_session_key(libctx(), "P-384");
    ASSERT_NE(pkey, nullptr) << "EC P-384 keygen failed";

    ResetHandle rh(api());

    // Background thread fires partition resets on a fixed interval.
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

    // Sign + verify in a loop; resiliency layer must recover transparently.
    uint32_t ok_count = 0;
    for (uint32_t i = 0; i < STRESS_OPS; ++i)
    {
        bool ok = ec_sign_verify_roundtrip(libctx(), pkey.get());
        EXPECT_TRUE(ok) << "ECDSA op " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, STRESS_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// EC keygen across all curves survives concurrent partition resets.
TEST_F(ec_resiliency, ec_keygen_survives_resets)
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

    // Cycle through all curves; each keygen requires an active session.
    const char *curves[] = { "P-256", "P-384", "P-521" };
    constexpr uint32_t NUM_OPS = STRESS_OPS / 2;
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < NUM_OPS; ++i)
    {
        auto pkey = generate_ec_session_key(libctx(), curves[i % 3]);
        EXPECT_NE(pkey, nullptr) << "keygen " << i << " failed";
        if (pkey)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, NUM_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// Multiple worker threads doing ECDSA survive concurrent partition resets.
TEST_F(ec_resiliency, multi_thread_ecdsa_survives_resets)
{
    // Shared key across all worker threads.
    auto pkey = generate_ec_session_key(libctx(), "P-384");
    ASSERT_NE(pkey, nullptr);

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

    // Launch multiple workers doing sign/verify concurrently.
    std::atomic<uint32_t> ok{ 0 };
    std::atomic<uint32_t> fail{ 0 };

    std::vector<std::thread> threads;
    for (uint32_t w = 0; w < NUM_WORKERS; ++w)
    {
        threads.emplace_back([&] {
            for (uint32_t i = 0; i < MULTI_OPS_PER_WORKER; ++i)
            {
                if (ec_sign_verify_roundtrip(libctx(), pkey.get()))
                    ok.fetch_add(1);
                else
                    fail.fetch_add(1);
                std::this_thread::sleep_for(WORKER_SLEEP);
            }
        });
    }
    for (auto &t : threads)
        t.join();

    stop.store(true);
    reset_thread.join();

    const uint32_t total = NUM_WORKERS * MULTI_OPS_PER_WORKER;
    EXPECT_EQ(ok.load(), total) << fail.load() << " failures";
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// ECDH key exchange derivation survives concurrent partition resets.
TEST_F(ec_resiliency, ecdh_derive_survives_resets)
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

    // Each iteration: generate keypair + derive shared secret.
    constexpr uint32_t NUM_OPS = STRESS_OPS / 2;
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < NUM_OPS; ++i)
    {
        // HSM key for our side, default-provider key for peer.
        auto our_key = generate_ec_session_key(libctx(), "P-256", "keyAgreement");
        auto peer_key = generate_ec_default_key(libctx(), "P-256");
        if (!our_key || !peer_key)
        {
            EXPECT_TRUE(false) << "keygen " << i << " failed";
            std::this_thread::sleep_for(WORKER_SLEEP);
            continue;
        }

        EvpPkeyCtxPtr derive_ctx(
            EVP_PKEY_CTX_new_from_pkey(libctx(), our_key.get(), ProviderCtx::propquery())
        );
        bool ok = derive_ctx && EVP_PKEY_derive_init(derive_ctx.get()) == 1 &&
                  EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_key.get()) == 1;

        if (ok)
        {
            size_t out_len = 0;
            ok = EVP_PKEY_derive(derive_ctx.get(), nullptr, &out_len) == 1 && out_len > 0;
            if (ok)
            {
                std::vector<unsigned char> buf(out_len);
                ok = EVP_PKEY_derive(derive_ctx.get(), buf.data(), &out_len) == 1;
            }
        }

        EXPECT_TRUE(ok) << "ECDH derive " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, NUM_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// Full ECDH + HKDF + HMAC chain survives concurrent partition resets.
TEST_F(ec_resiliency, ecdh_hkdf_hmac_roundtrip_survives_resets)
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

        // Step 1: ECDH → masked shared secret file.
        std::string ecdh_file = derive_masked_key_file(libctx(), "P-256");
        if (ecdh_file.empty())
        {
            EXPECT_FALSE(ecdh_file.empty()) << "ECDH " << i << " failed";
            std::this_thread::sleep_for(WORKER_SLEEP);
            continue;
        }

        // Step 2: HKDF → derive HMAC-SHA256 key from shared secret.
        char hmac_key_path[] = "/tmp/azihsm_resil_hmac_XXXXXX";
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
                    // Step 3: Compute HMAC-SHA256 over test data.
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

                        const std::string data = "resiliency chain test data";
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

        EXPECT_TRUE(ok) << "chain " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, NUM_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file lifecycle_resiliency_tests.cpp
///
/// Cross-cutting resiliency stress tests: session + key recovery after resets,
/// and mixed-operation workloads that exercise all recovery paths together.

#include "resiliency_helpers.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class lifecycle_resiliency : public resiliency_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Fresh keygen + sign/verify each iteration — proves both session and key
/// recovery work together after resets.
TEST_F(lifecycle_resiliency, session_and_key_recovery)
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

    const char *curves[] = { "P-256", "P-384", "P-521" };
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < STRESS_OPS; ++i)
    {
        // Generate a fresh key (requires an active session).
        auto pkey = generate_ec_session_key(libctx(), curves[i % 3]);
        if (pkey == nullptr)
        {
            EXPECT_NE(pkey, nullptr) << "keygen " << i << " failed";
            continue;
        }

        // Use the key immediately (requires both session and key handle).
        bool ok = ec_sign_verify_roundtrip(libctx(), pkey.get());
        EXPECT_TRUE(ok) << "sign/verify with fresh key " << i << " failed";
        if (ok)
            ok_count++;

        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, STRESS_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// Interleaved EC sign, RSA sign, and EC keygen under resets — exercises
/// all recovery paths (session, EC key, RSA key) together.
TEST_F(lifecycle_resiliency, mixed_ops_survive_resets)
{
    // Pre-generate one EC and one RSA session key.
    auto ec_key = generate_ec_session_key(libctx(), "P-384");
    ASSERT_NE(ec_key, nullptr);

    auto rsa_key = generate_rsa_session_key(libctx());
    ASSERT_NE(rsa_key, nullptr);

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

    const char *curves[] = { "P-256", "P-384", "P-521" };
    uint32_t ok_count = 0;

    for (uint32_t i = 0; i < STRESS_OPS; ++i)
    {
        bool ok = false;
        switch (i % 3)
        {
        case 0:
            // EC sign/verify with pre-generated key.
            ok = ec_sign_verify_roundtrip(libctx(), ec_key.get());
            break;
        case 1:
            // RSA sign/verify with pre-generated key.
            ok = rsa_sign_verify_roundtrip(libctx(), rsa_key.get());
            break;
        case 2: {
            // Fresh EC keygen (tests session recovery path).
            auto fresh = generate_ec_session_key(libctx(), curves[i % 3]);
            ok = (fresh != nullptr);
            break;
        }
        }
        EXPECT_TRUE(ok) << "mixed op " << i << " (type " << (i % 3) << ") failed";
        if (ok)
            ok_count++;

        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, STRESS_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

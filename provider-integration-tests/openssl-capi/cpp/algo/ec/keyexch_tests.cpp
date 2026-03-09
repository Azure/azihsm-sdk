// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file keyexch_tests.cpp
///
/// ECDH key exchange tests that use **session-based** EC keys via the OpenSSL
/// EVP API.  The ECDH derive operation returns a masked key blob — not a raw
/// shared secret — so these tests verify that derivation succeeds and produces
/// non-empty output, matching the approach taken by the CLI integration tests
/// (ecdh_key_exchange.sh).

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "utils/keygen_helpers.hpp"
#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ec_keyexch : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Derive a shared secret into a caller-provided buffer.
/// Verifies that the derivation succeeds and produces a non-empty masked blob.
TEST_F(ec_keyexch, derive_to_buffer)
{
    auto our_key = generate_ec_session_key(prov_.libctx(), "P-256", "keyAgreement");
    auto peer_key = generate_ec_default_key(prov_.libctx(), "P-256");
    ASSERT_NE(our_key, nullptr) << "Failed to generate our EC session key";
    ASSERT_NE(peer_key, nullptr) << "Failed to generate peer EC key";

    // Init derive context with our key
    EvpPkeyCtxPtr derive_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), our_key.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(derive_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_derive_init(derive_ctx.get()), 1) << "derive_init failed";

    // Set peer
    ASSERT_EQ(EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_key.get()), 1)
        << "derive_set_peer failed";

    // Size query
    size_t out_len = 0;
    ASSERT_EQ(EVP_PKEY_derive(derive_ctx.get(), nullptr, &out_len), 1)
        << "derive size query failed";
    ASSERT_GT(out_len, 0u);

    // Actual derivation
    std::vector<unsigned char> shared_secret(out_len);
    ASSERT_EQ(EVP_PKEY_derive(derive_ctx.get(), shared_secret.data(), &out_len), 1)
        << "EVP_PKEY_derive failed";

    EXPECT_GT(out_len, 0u) << "Derived masked blob should be non-empty";
}

/// Derive a shared secret into a file via the output_file context parameter.
/// Verifies that the file is created and contains data.
TEST_F(ec_keyexch, derive_to_file)
{
    auto our_key = generate_ec_session_key(prov_.libctx(), "P-256", "keyAgreement");
    auto peer_key = generate_ec_default_key(prov_.libctx(), "P-256");
    ASSERT_NE(our_key, nullptr);
    ASSERT_NE(peer_key, nullptr);

    // Create a unique temp file path.  mkstemp creates the file — we close and
    // unlink it so the provider creates it fresh during derive.
    char tmp_tpl[] = "/tmp/azihsm_test_ecdh_XXXXXX";
    int fd = mkstemp(tmp_tpl);
    ASSERT_GE(fd, 0) << "mkstemp failed";
    ::close(fd);
    ::unlink(tmp_tpl);

    TempFileGuard guard(tmp_tpl);

    // Init derive context
    EvpPkeyCtxPtr derive_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), our_key.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(derive_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_derive_init(derive_ctx.get()), 1);

    // Set peer
    ASSERT_EQ(EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_key.get()), 1);

    // Set output_file parameter
    OSSL_PARAM ctx_params[] = {
        OSSL_PARAM_utf8_string("output_file", guard.path, 0),
        OSSL_PARAM_END,
    };
    ASSERT_EQ(EVP_PKEY_CTX_set_params(derive_ctx.get(), ctx_params), 1)
        << "Failed to set output_file parameter";

    // Size query — returns 1 in file output mode (caller must provide a buffer
    // to trigger the derive, but no bytes are returned).
    size_t out_len = 0;
    ASSERT_EQ(EVP_PKEY_derive(derive_ctx.get(), nullptr, &out_len), 1);

    // Derive — triggers file write
    std::vector<unsigned char> dummy(out_len > 0 ? out_len : 1);
    ASSERT_EQ(EVP_PKEY_derive(derive_ctx.get(), dummy.data(), &out_len), 1)
        << "EVP_PKEY_derive to file failed";

    // Verify the file was created and is non-empty
    struct stat st = {};
    ASSERT_EQ(::stat(guard.path, &st), 0) << "Output file was not created at " << guard.path;
    EXPECT_GT(st.st_size, 0) << "Output file should contain a masked key blob";
}

/// ECDH derivation with mismatched curves must fail.
/// The failure can occur either at set_peer (OpenSSL parameter check) or at
/// derive time (provider-side validation), depending on OpenSSL version.
TEST_F(ec_keyexch, derive_fails_with_mismatched_curves)
{
    auto our_key = generate_ec_session_key(prov_.libctx(), "P-256", "keyAgreement");
    auto peer_key = generate_ec_default_key(prov_.libctx(), "P-384");
    ASSERT_NE(our_key, nullptr);
    ASSERT_NE(peer_key, nullptr);

    EvpPkeyCtxPtr derive_ctx(
        EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), our_key.get(), ProviderCtx::propquery())
    );
    ASSERT_NE(derive_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_derive_init(derive_ctx.get()), 1);

    int rc_peer = EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_key.get());
    if (rc_peer != 1)
    {
        // set_peer itself rejected the mismatched curves — test passes
        return;
    }

    // set_peer succeeded; the derive call must fail instead
    size_t out_len = 0;
    int rc_derive = EVP_PKEY_derive(derive_ctx.get(), nullptr, &out_len);
    if (rc_derive == 1 && out_len > 0)
    {
        std::vector<unsigned char> buf(out_len);
        rc_derive = EVP_PKEY_derive(derive_ctx.get(), buf.data(), &out_len);
    }
    EXPECT_NE(rc_derive, 1) << "derive should fail with mismatched curves";
}

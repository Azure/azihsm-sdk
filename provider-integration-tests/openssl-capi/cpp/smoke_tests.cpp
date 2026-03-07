// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <openssl/provider.h>

#include "utils/provider_ctx.hpp"

/// Verify that the azihsm provider can be loaded into an OpenSSL library
/// context.  This is the most basic sanity check — if the provider .so is
/// missing, has unresolved symbols, or fails its init callback the test will
/// fail here rather than in a more complex crypto test.
TEST(SmokeTest, provider_loads_successfully)
{
    ProviderCtx ctx;

    ASSERT_NE(ctx.libctx(), nullptr);
    ASSERT_NE(ctx.azihsm(), nullptr);
}

/// Confirm that the loaded provider reports the expected name.
TEST(SmokeTest, provider_name_is_correct)
{
    ProviderCtx ctx;

    const char *name = OSSL_PROVIDER_get0_name(ctx.azihsm());
    ASSERT_NE(name, nullptr);
    EXPECT_STREQ(name, "azihsm_provider");
}

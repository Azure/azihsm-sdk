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
    ASSERT_TRUE(OSSL_PROVIDER_available(ctx.libctx(), "azihsm"));
}

/// Confirm that the loaded provider reports the expected name.
TEST(SmokeTest, provider_name_is_correct)
{
    ProviderCtx ctx;

    // Iterate over loaded providers to find the azihsm provider handle.
    OSSL_PROVIDER *azihsm = nullptr;
    OSSL_PROVIDER_do_all(
        ctx.libctx(),
        [](OSSL_PROVIDER *prov, void *arg) -> int
        {
            const char *name = OSSL_PROVIDER_get0_name(prov);
            if (name != nullptr && std::string(name) == "azihsm")
            {
                *static_cast<OSSL_PROVIDER **>(arg) = prov;
            }
            return 1; // continue iteration
        },
        &azihsm
    );

    ASSERT_NE(azihsm, nullptr);
    const char *name = OSSL_PROVIDER_get0_name(azihsm);
    ASSERT_NE(name, nullptr);
    EXPECT_STREQ(name, "azihsm");
}

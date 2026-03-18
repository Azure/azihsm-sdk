// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <openssl/crypto.h>

int main(int argc, char **argv)
{
    // Suppress default-context config auto-loading so OPENSSL_CONF does not
    // cause the azihsm provider to load into the default library context.
    // Each test loads the config explicitly into a dedicated context via
    // OSSL_LIB_CTX_load_config().
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include "utils/module.hpp"

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    // Loads and initializes the module once per process (not in list mode).
    ::testing::AddGlobalTestEnvironment(new ModuleEnvironment);
    return RUN_ALL_TESTS();
}

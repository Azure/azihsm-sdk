# Copyright (C) Microsoft Corporation. All rights reserved.

cmake_minimum_required(VERSION 3.14)
project(azihsm_api_cpp_tests VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

SET(TEST_FEATURES "" CACHE STRING "Test features to enable")


include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(
    ScopeGuard
    GIT_REPOSITORY https://github.com/Neargye/scope_guard.git
    GIT_TAG v0.9.1
)
FetchContent_MakeAvailable(ScopeGuard)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6 # Optionally specify a commit hash, version tag or branch here
)
FetchContent_MakeAvailable(Corrosion)

enable_testing()

corrosion_import_crate(
    MANIFEST_PATH ../../native/Cargo.toml
    CRATE_TYPES cdylib
    CRATES azihsm_api_native
    FEATURES ${TEST_FEATURES}
    )

corrosion_experimental_cbindgen(
    TARGET azihsm_api_native 
    HEADER_NAME "azihsm_api.h"
    )

set(SOURCE 
    handle/part_list_handle.cpp
    partition_tests.cpp 
    session_tests.cpp 
    algo/aes/cbc_enc_dec_tests.cpp
    algo/aes/xts_enc_dec_tests.cpp
    algo/aes/keygen_tests.cpp
    algo/ecc/keygen_tests.cpp
    algo/ecc/sign_verify_tests.cpp
    algo/ecc/keyreport_tests.cpp
    algo/rsa/keygen_tests.cpp
    algo/rsa/keyreport_tests.cpp
    algo/rsa/enc_dec_tests.cpp
    algo/rsa/sign_verify_tests.cpp
    algo/sha/digest_tests.cpp
    algo/hmac/sign_verify_tests.cpp
)
add_executable(azihsm_api_cpp_tests ${SOURCE})
target_include_directories(azihsm_api_cpp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(
    azihsm_api_cpp_tests
    PUBLIC
        azihsm_api_native
        GTest::gtest_main
        scope_guard::scope_guard 
)

include(GoogleTest)
gtest_discover_tests(azihsm_api_cpp_tests)
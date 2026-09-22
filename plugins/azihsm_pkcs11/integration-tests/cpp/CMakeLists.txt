# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Functional tests for the AZIHSM PKCS#11 module, driven through the real
# Cryptoki ABI: the test binary dlopens the built module (path from the
# AZIHSM_PKCS11_MODULE environment variable, defaulting to the cargo build
# output) and talks to the device behind it, so it needs the mock- or
# hardware-backed build:
#
#   cargo build -p azihsm_pkcs11 --features mock
#   cmake -S plugins/azihsm_pkcs11/integration-tests/cpp -B target/pkcs11-cpp-tests
#   cmake --build target/pkcs11-cpp-tests
#   ctest --test-dir target/pkcs11-cpp-tests --output-on-failure --no-tests=error
#
# Same shape as plugins/ossl_prov/integration-tests/openssl-capi/cpp.

cmake_minimum_required(VERSION 3.14)
project(azihsm_pkcs11_cpp_tests VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# The module's own tree (vendored PKCS#11 headers + the platform-macro header
# that fixes the Cryptoki ABI, and the template header for its constants).
get_filename_component(AZIHSM_PKCS11_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(AZIHSM_REPO_ROOT "${AZIHSM_PKCS11_ROOT}/../.." ABSOLUTE)

set(SOURCE
    main.cpp
    smoke_tests.cpp
    aes/keygen_tests.cpp
    aes/cbc_tests.cpp
    session/op_lifecycle_tests.cpp
)
add_executable(azihsm_pkcs11_cpp_tests ${SOURCE})
target_include_directories(
    azihsm_pkcs11_cpp_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AZIHSM_PKCS11_ROOT}/include/pkcs11-v3.1
        ${AZIHSM_PKCS11_ROOT}/src
)
target_compile_options(azihsm_pkcs11_cpp_tests PRIVATE -Wall -Wextra -Werror)
# Where the cargo build puts the module; AZIHSM_PKCS11_MODULE overrides at run time.
target_compile_definitions(
    azihsm_pkcs11_cpp_tests
    PRIVATE AZIHSM_PKCS11_DEFAULT_MODULE="${AZIHSM_REPO_ROOT}/target/debug/azihsm_pkcs11.so"
)

find_package(Threads REQUIRED)
target_link_libraries(
    azihsm_pkcs11_cpp_tests
    PRIVATE
        GTest::gtest
        Threads::Threads
        ${CMAKE_DL_LIBS}
)

include(GoogleTest)
gtest_discover_tests(azihsm_pkcs11_cpp_tests)

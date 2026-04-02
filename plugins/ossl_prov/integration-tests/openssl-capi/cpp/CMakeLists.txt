# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.14)
project(azihsm_ossl_cpp_tests VERSION 0.1.0)

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

# OPENSSL_ROOT_DIR is passed from build.rs via cmake::Config::define().
# The FindOpenSSL module uses this hint to locate the correct installation
# before searching system paths.
if (NOT DEFINED OPENSSL_ROOT_DIR)
    message(FATAL_ERROR "OPENSSL_ROOT_DIR must be set (passed from build.rs via OPENSSL_DIR env var)")
endif()
find_package(OpenSSL 3 REQUIRED)

# Verify that the found OpenSSL actually comes from the requested prefix,
# not from a system installation.
get_filename_component(_ossl_resolved "${OPENSSL_INCLUDE_DIR}" REALPATH)
get_filename_component(_root_resolved "${OPENSSL_ROOT_DIR}" REALPATH)
string(FIND "${_ossl_resolved}" "${_root_resolved}" _pos)
if (_pos LESS 0)
    message(FATAL_ERROR
        "OpenSSL was found at ${OPENSSL_INCLUDE_DIR} which is outside "
        "OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}.  Set OPENSSL_DIR to the "
        "correct OpenSSL 3.0.3 installation prefix.")
endif()

message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto:  ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

enable_testing()

set(SOURCE
    main.cpp
    smoke_tests.cpp
    algo/digest/digest_tests.cpp
    algo/ec/sign_verify_tests.cpp
    algo/ec/keyexch_tests.cpp
    algo/ec/ecdh_hkdf_hmac_tests.cpp
    algo/kdf/hkdf_tests.cpp
    algo/mac/hmac_tests.cpp
    algo/rsa/sign_verify_tests.cpp
    algo/rsa/enc_dec_tests.cpp
    resiliency/ec_resiliency_tests.cpp
    resiliency/rsa_resiliency_tests.cpp
    resiliency/symmetric_resiliency_tests.cpp
    resiliency/lifecycle_resiliency_tests.cpp
)
add_executable(azihsm_ossl_cpp_tests ${SOURCE})
target_include_directories(azihsm_ossl_cpp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(
    azihsm_ossl_cpp_tests
    PUBLIC
        GTest::gtest
        OpenSSL::Crypto
)

# libcrypto depends on pthread and dl
find_package(Threads REQUIRED)
target_link_libraries(azihsm_ossl_cpp_tests PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

include(GoogleTest)
gtest_discover_tests(azihsm_ossl_cpp_tests)

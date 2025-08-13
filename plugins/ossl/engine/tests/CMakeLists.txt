# Copyright (c) Microsoft Corporation. All rights reserved.
#
# Integration tests for AZIHSM Engine

cmake_minimum_required(VERSION 3.16.3)

set(AZIHSM_ENGINE_TEST_PROJECT AZIHSMEngineTestProject)
set(AZIHSM_ENGINE_TESTS AZIHSMEngineTests)
set(AZIHSM_ENGINE_LIB libazihsmcpp)

project(AZIHSMEngineTestProject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(lib)
add_subdirectory(tests)

include_directories(${CMAKE_SOURCE_DIR}/lib/include)

message(STATUS "OpenSSL Version Found ${OPENSSL_VERSION}")
message(STATUS "OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")

if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(STATUS "OpenSSL 1.1.x found")
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE OPENSSL_1_1)
else()
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE OPENSSL_3)
endif()


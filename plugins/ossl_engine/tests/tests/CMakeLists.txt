# Copyright (c) Microsoft Corporation. All rights reserved.
#
# Integration tests for AZIHSM Engine

cmake_minimum_required(VERSION 3.16.3)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DEBUG_SO_PATH_DIR "${CMAKE_SOURCE_DIR}/../target/debug/")
    set(AZIHSM_LIB_DIR "${DEBUG_SO_PATH_DIR}")
else()
    set(RELEASE_SO_PATH_DIR "${CMAKE_SOURCE_DIR}/../target/release/")
    set(AZIHSM_LIB_DIR "${RELEASE_SO_PATH_DIR}")
endif()

Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.4.0 # or a later release
)

FetchContent_MakeAvailable(Catch2)

add_executable(${AZIHSM_ENGINE_TESTS}
    Engine.cpp
    Hash.cpp
    KeyConsts.cpp
)

add_subdirectory(cipher)
add_subdirectory(ctrl)
add_subdirectory(ec)
add_subdirectory(pkey)
add_subdirectory(rsa)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${AZIHSM_ENGINE_TESTS} PRIVATE ${AZIHSM_ENGINE_LIB})

message(STATUS "AZIHSM_LIB_DIR: ${AZIHSM_LIB_DIR}")

if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(STATUS "OpenSSL 1.1.x found")
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE OPENSSL_1_1)
else()
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE OPENSSL_3)
endif()

target_link_libraries(${AZIHSM_ENGINE_TESTS} PRIVATE Catch2::Catch2WithMain)
target_link_libraries(${AZIHSM_ENGINE_TESTS} PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

option(AZIHSM_GCM "Enable GCM cipher tests using AZIHSM" OFF)
option(AZIHSM_XTS "Enable XTS cipher tests using AZIHSM" OFF)
option(AZIHSM_NAMED_KEYS "Enable tests using named keys with AZIHSM" OFF)

if(AZIHSM_GCM)
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE AZIHSM_GCM)
endif()
if(AZIHSM_XTS)
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE AZIHSM_XTS)
endif()
if(AZIHSM_NAMED_KEYS)
    target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE AZIHSM_NAMED_KEYS)
endif()

message(STATUS "AZIHSM_GCM: ${AZIHSM_GCM}")
message(STATUS "AZIHSM_XTS: ${AZIHSM_XTS}")
message(STATUS "AZIHSM_NAMED_KEYS: ${AZIHSM_NAMED_KEYS}")

target_compile_definitions(${AZIHSM_ENGINE_TESTS} PRIVATE AZIHSM_LIB_DIR="${AZIHSM_LIB_DIR}")

# Code coverage target
add_custom_target(coverage
    COMMAND ${CMAKE_COMMAND} -E env RUSTFLAGS=\"-C instrument-coverage\" cargo build --features=mock
    COMMAND rm -rf *.profraw *.profdata *.lcov html-out
    COMMAND "${AZIHSM_ENGINE_TESTS}" -a
    COMMAND rust-profdata merge -sparse *.profraw -o coverage.profdata
    COMMAND rust-cov export -Xdemangler=rustfilt --object "${CMAKE_SOURCE_DIR}/../target/debug/libazihsmengine.so" --sources "${CMAKE_SOURCE_DIR}/../lib/src" -instr-profile=coverage.profdata -format=lcov > coverage.lcov
    COMMAND genhtml -o html-out coverage.lcov
    DEPENDS ${AZIHSM_ENGINE_TESTS}
)

# Catch2 framework configs
#enable testing
enable_testing()
#discover tests
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(CTest)
include(Catch)
catch_discover_tests(${AZIHSM_ENGINE_TESTS})

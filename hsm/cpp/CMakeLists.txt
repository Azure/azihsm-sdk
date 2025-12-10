# Copyright (C) Microsoft Corporation. All rights reserved.

cmake_minimum_required(VERSION 3.14)

project(azihsm_cpp_tests VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

set(DEFAULT_BUILD_TYPE "Debug")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

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

enable_testing()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
    set(TARGET_DIR "debug")
else ()
    set(CARGO_CMD cargo build --release)
    set(TARGET_DIR "release")
endif ()

if (AZIHSM_VIRT)
    set(CARGO_MOCK_FEATURES "virt")
else ()
    set(CARGO_MOCK_FEATURES "")
endif ()

set(AZIHSM_API_HEADER_NAME "azihsm.h")
if(WIN32)
    set(AZIHSM_API_LIB_NAME "azihsm.dll")
    set(AZIHSM_API_LINK_LIB_NAME "azihsm.dll.lib")
else()
    set(AZIHSM_API_LIB_NAME "libazihsm.so")
    set(AZIHSM_API_LINK_LIB_NAME "libazihsm.so")
endif()
set(AZIHSM_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target")
set(AZIHSM_API_LIB "${AZIHSM_TARGET_DIR}/${TARGET_DIR}/${AZIHSM_API_LIB_NAME}")
set(AZIHSM_API_LINK_LIB "${AZIHSM_TARGET_DIR}/${TARGET_DIR}/${AZIHSM_API_LINK_LIB_NAME}")
set(AZIHSM_API_HEADER "${AZIHSM_TARGET_DIR}/${TARGET_DIR}/${AZIHSM_API_HEADER_NAME}")

add_custom_target(azihsm_api ALL
    COMMENT "Compiling azihsm_api module"
    COMMAND ${CARGO_CMD} --target-dir ${AZIHSM_TARGET_DIR} --features ${CARGO_MOCK_FEATURES},${CARGO_FEATURES} --package azihsm
    COMMAND ${CMAKE_COMMAND} -E copy ${AZIHSM_API_LIB} ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${AZIHSM_API_LINK_LIB} ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${AZIHSM_API_HEADER} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
    BYPRODUCTS
        ${CMAKE_CURRENT_BINARY_DIR}/${AZIHSM_API_LINK_LIB_NAME}
        ${CMAKE_CURRENT_BINARY_DIR}/${AZIHSM_API_HEADER_NAME}
    )
add_dependencies(azihsm_api GTest::gtest_main)
add_dependencies(azihsm_api scope_guard::scope_guard)

set(SOURCE helpers.cpp part_tests.cpp session_tests.cpp key_mgmt_tests.cpp enc_dec_tests.cpp aes_tests.cpp ec_tests.cpp sha_tests.cpp rsa_tests.cpp hmac_tests.cpp rsa_key_prop_tests.cpp)
add_executable(azihsm_api_tests ${SOURCE})
target_include_directories(
    azihsm_api_tests 
    PRIVATE 
        ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(
    azihsm_api_tests
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/${AZIHSM_API_LINK_LIB_NAME}
        GTest::gtest_main
        scope_guard::scope_guard 
)
add_dependencies(azihsm_api_tests azihsm_api)

include(GoogleTest)
gtest_discover_tests(azihsm_api_tests)

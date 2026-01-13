# Copyright (C) Microsoft Corporation. All rights reserved.
cmake_minimum_required(VERSION 3.13.0)

project(azihsm_ossl_provider
    VERSION 0.0.1
    DESCRIPTION "Azure Integrated HSM provider for OpenSSL")

# Generate compile_commands.json for LSP
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

# Azure HSM SDK configuration
set(AZIHSM_SDK_PATH "../../" CACHE PATH "Path to azihsm SDK")
set(AZIHSM_BUILD_TYPE "release" CACHE STRING "Build type of azihsm SDK (debug/release)")

find_package(OpenSSL 3 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${AZIHSM_SDK_PATH}/target/${AZIHSM_BUILD_TYPE})

set(DEFAULT_BUILD_TYPE "Release")

if (CMAKE_BUILD_TYPE MATCHES Release|RelWithDebInfo)
    message("Release mode")
else()
    message("Debug mode")
    add_compile_options(-DDBG=1)
endif()

# In Sanitize version, enable sanitizers
if (CMAKE_BUILD_TYPE MATCHES Sanitize)
    add_compile_options(-fsanitize=address)
    add_compile_options(-fsanitize=leak)
    add_compile_options(-fsanitize=undefined)
    add_compile_options(-fno-sanitize-recover=all)
    add_link_options(-fsanitize=address)
    add_link_options(-fsanitize=leak)
    add_link_options(-fsanitize=undefined)
    add_link_options(-fno-sanitize-recover=all)
endif()

# Enhanced compiler warning flags for code quality
# C-specific warnings (strict prototypes not supported in C++)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -Wall \
    -Wextra \
    -Wno-unknown-pragmas \
    -Wstrict-prototypes \
    -Wwrite-strings \
    -Wpointer-arith \
    -Wconversion \
    -Wshadow \
    -Wformat=2 \
    -Wformat-security \
    -Wtrampolines \
    -Wlogical-op \
    -Wnested-externs \
    -Winit-self \
    -Wundef")

# C++ warnings (compatible subset of C warnings)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -std=c++1y \
    -Wall \
    -Wextra \
    -Wconversion \
    -Wshadow \
    -Wformat=2 \
    -Wundef")

# Optional: Treat warnings as errors (disabled by default for development)
option(ENABLE_WERROR "Treat compiler warnings as errors" OFF)
if(ENABLE_WERROR)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
    message(STATUS "Warning mode: Treating compiler warnings as errors")
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/azihsm_ossl_base.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/azihsm_ossl_base.h
)

set(AZIHSM_OSSL_SOURCES
    ./src/azihsm_ossl_hsm.c
    ./src/azihsm_ossl_base.c
    ./src/azihsm_ossl_digest.c
    ./src/azihsm_ossl_cipher.c
    ./src/azihsm_ossl_mac.c
    ./src/azihsm_ossl_kdf.c
    ./src/azihsm_ossl_keymgmt_rsa.c
    ./src/azihsm_ossl_keymgmt_ec.c
    ./src/azihsm_ossl_keyexch.c
    ./src/azihsm_ossl_signature.c
    ./src/azihsm_ossl_asym_cipher.c
    ./src/azihsm_ossl_pkey_param.c
    ./src/azihsm_ossl_encoder_rsa.c
    ./src/azihsm_ossl_encoder_ec.c
)

add_library(azihsm_ossl_provider SHARED ${AZIHSM_OSSL_SOURCES})

set_target_properties(azihsm_ossl_provider PROPERTIES PUBLIC_HEADER ./inc/azihsm_ossl_base.h)
target_include_directories(azihsm_ossl_provider PUBLIC ./inc)
target_include_directories(azihsm_ossl_provider PRIVATE ./src)

# Remove default "lib" prefix from azihsm.so as OpenSSL provider is not a generic Linux .so
set_target_properties(azihsm_ossl_provider PROPERTIES PREFIX "")
set_target_properties(azihsm_ossl_provider PROPERTIES OUTPUT_NAME "azihsm")

target_link_libraries(azihsm_ossl_provider PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(azihsm_ossl_provider PUBLIC ${AZIHSM_SDK_PATH}/target/${AZIHSM_BUILD_TYPE}/libazihsm.so)

if (NOT DEFINED OPENSSL_PROVIDERS)
   set(OPENSSL_PROVIDERS "${CMAKE_INSTALL_LIBDIR}/ossl-modules" CACHE PATH "Path to OpenSSL providers")
endif()

# Install the engine to the OpenSSL modules directory
# NB: this won't work if the distro has a custom modules directory that doesn't match
# the OpenSSL default.
install(
    TARGETS azihsm_ossl_provider
    LIBRARY DESTINATION "${OPENSSL_PROVIDERS}"
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)


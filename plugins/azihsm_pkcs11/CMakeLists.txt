# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.13.0)

project(azihsm_pkcs11
    VERSION 0.0.1
    DESCRIPTION "AZIHSM PKCS#11 module")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(AZIHSM_CARGO_FEATURES "" CACHE STRING "Cargo Features to enable")

include(GNUInstallDirs)
include(FetchContent)

# libcrypto is needed only for the caller POTA endorsement in the C_Login
# ceremony (azihsm_pkcs11_hsm.c) — exactly as the OpenSSL provider uses it.
find_package(OpenSSL 3 REQUIRED)

# --- Import the AZIHSM native C API (Rust cdylib) via Corrosion, then generate
#     the azihsm.h header via cbindgen. Same pattern as plugins/ossl_prov. ------
FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(
    MANIFEST_PATH ../../api/native/Cargo.toml
    CRATE_TYPES cdylib
    CRATES azihsm_api_native
    FEATURES ${AZIHSM_CARGO_FEATURES}
    )

corrosion_experimental_cbindgen(
    TARGET azihsm_api_native
    HEADER_NAME "azihsm.h"
    )

# --- Warning flags (subset of the ossl_prov set; PKCS#11 headers use some
#     constructs that trip -Wstrict-prototypes on older headers). ------------
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -Wall \
    -Wextra \
    -Wno-unknown-pragmas \
    -Wwrite-strings \
    -Wpointer-arith \
    -Wshadow \
    -Wformat=2 \
    -Wformat-security \
    -Winit-self \
    -Wundef")

option(ENABLE_WERROR "Treat compiler warnings as errors" OFF)
if(ENABLE_WERROR)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
endif()

set(AZIHSM_PKCS11_SOURCES
    ./src/azihsm_pkcs11_module.c
    ./src/azihsm_pkcs11_dispatch.c
    ./src/azihsm_pkcs11_slot.c
    ./src/azihsm_pkcs11_session.c
    ./src/azihsm_pkcs11_objstore_mem.c
    ./src/azihsm_pkcs11_objstore_file.c
    ./src/azihsm_pkcs11_config.c
    ./src/azihsm_pkcs11_status.c
    ./src/azihsm_pkcs11_hsm.c
    ./src/azihsm_pkcs11_stubs.c
)

add_library(azihsm_pkcs11 SHARED ${AZIHSM_PKCS11_SOURCES})

# The module talks to the AZIHSM SDK through azihsm.h; enable the backend seam.
target_compile_definitions(azihsm_pkcs11 PRIVATE AZIHSM_WITH_HSM=1)

# Vendored OASIS PKCS#11 v3.1 headers + our sources.
target_include_directories(azihsm_pkcs11 PRIVATE ./include/pkcs11-v3.1 ./src)
target_include_directories(azihsm_pkcs11 PRIVATE ${OPENSSL_INCLUDE_DIR})

# Standard PKCS#11 modules are unversioned, un-prefixed .so files.
set_target_properties(azihsm_pkcs11 PROPERTIES PREFIX "")
set_target_properties(azihsm_pkcs11 PROPERTIES OUTPUT_NAME "azihsm_pkcs11")

target_link_libraries(azihsm_pkcs11 PUBLIC azihsm_api_native)
target_link_libraries(azihsm_pkcs11 PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

# Copy the module to the Cargo target directory (AZIHSM_TARGET_DIR from build.rs).
if (DEFINED AZIHSM_TARGET_DIR)
    add_custom_command(
        TARGET azihsm_pkcs11
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            "$<TARGET_FILE:azihsm_pkcs11>"
            "${AZIHSM_TARGET_DIR}/azihsm_pkcs11.so"
        COMMENT "Copying azihsm_pkcs11.so to ${AZIHSM_TARGET_DIR}/"
        VERBATIM
    )
endif()

install(
    TARGETS azihsm_pkcs11
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkcs11
)

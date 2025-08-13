# 
# Copyright (c) Microsoft Corporation. All rights reserved.
#
#
# Integration tests for AZIHSM Engine

cmake_minimum_required(VERSION 3.16.3)

add_library(${AZIHSM_ENGINE_LIB} STATIC
    Engine.cpp
    Hash.cpp
)

add_subdirectory(cipher)
add_subdirectory(ec)
add_subdirectory(pkey)
add_subdirectory(rsa)

target_include_directories(${AZIHSM_ENGINE_LIB} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${AZIHSM_ENGINE_LIB} PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

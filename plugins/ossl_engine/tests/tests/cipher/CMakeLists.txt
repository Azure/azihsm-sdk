# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    Ciphers.cpp
    AesCbc.cpp
    AesGcm.cpp
    AesXts.cpp
    AesUnwrap.cpp)

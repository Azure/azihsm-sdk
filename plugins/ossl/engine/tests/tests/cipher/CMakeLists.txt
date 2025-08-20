# Copyright (C) Microsoft Corporation. All rights reserved.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    Ciphers.cpp
    AesCbc.cpp
    AesGcm.cpp
    AesXts.cpp
    AesUnwrap.cpp)

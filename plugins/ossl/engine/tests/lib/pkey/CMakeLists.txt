# Copyright (c) Microsoft Corporation. All rights reserved.

target_sources(
    ${AZIHSM_ENGINE_LIB}
    PUBLIC
    PKeys.cpp
    PKeyRsa.cpp
    PKeyHkdf.cpp
    PKeyEc.cpp
    PKeyDigestSignVerify.cpp)
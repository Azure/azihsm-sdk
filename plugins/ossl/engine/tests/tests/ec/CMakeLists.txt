# Copyright (C) Microsoft Corporation. All rights reserved.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    Ec.cpp
    Ecdsa.cpp 
    Ecdh.cpp 
    EcUnwrap.cpp 
    EcCommon.cpp)

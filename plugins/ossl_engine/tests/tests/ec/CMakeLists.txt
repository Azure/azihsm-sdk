# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    Ec.cpp
    Ecdsa.cpp 
    Ecdh.cpp 
    EcUnwrap.cpp 
    EcCommon.cpp)

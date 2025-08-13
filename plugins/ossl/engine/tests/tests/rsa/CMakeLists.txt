# Copyright (c) Microsoft Corporation. All rights reserved.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    Rsa.cpp
    RsaEncDec.cpp
    RsaSignVerify.cpp
    RsaUnwrap.cpp
    RsaCommon.cpp)

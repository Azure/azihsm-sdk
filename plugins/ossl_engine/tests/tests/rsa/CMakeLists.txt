# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    Rsa.cpp
    RsaEncDec.cpp
    RsaSignVerify.cpp
    RsaUnwrap.cpp
    RsaCommon.cpp)

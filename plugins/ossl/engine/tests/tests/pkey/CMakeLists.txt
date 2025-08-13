# Copyright (c) Microsoft Corporation. All rights reserved.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    NamedKeyEc.cpp
    NamedKeyRsa.cpp
    PKeys.cpp
    PKeyRsa.cpp
    PKeyHkdf.cpp
    PKeyEc.cpp
    PKeyEcdh.cpp
    PKeyEcdsa.cpp
    PKeyEcUnwrap.cpp
    PKeyRsaUnwrap.cpp
    PKeyRsaEncDec.cpp
    PKeyRsaSignVerify.cpp
    PKeyDigestSignVerifyEc.cpp
    PKeyDigestSignVerifyRsa.cpp)

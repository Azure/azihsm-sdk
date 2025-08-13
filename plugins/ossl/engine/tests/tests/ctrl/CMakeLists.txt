# Copyright (C) Microsoft Corporation. All rights reserved.

target_sources(
    ${AZIHSM_ENGINE_TESTS}
    PRIVATE
    KeyAttest.cpp
    EcKeyAttest.cpp
    PKeyEcAttest.cpp
    PKeyRsaAttest.cpp
    RsaAttest.cpp
    CtrlInfo.cpp
    GetUnwrapKey.cpp
    GetCollateral.cpp)

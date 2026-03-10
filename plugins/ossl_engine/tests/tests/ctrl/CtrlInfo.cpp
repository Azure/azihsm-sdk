// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "../../../api-interface/azihsm_engine.h"

TEST_CASE("AZIHSM engine ctrl info tests", "[AziHsmEngineCtrlInfo]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Verify engine CTRL works")
    {
        const AziHsmEngineInfo *info = azihsm_get_engine_info(e);
        REQUIRE(info != nullptr);
    }
}
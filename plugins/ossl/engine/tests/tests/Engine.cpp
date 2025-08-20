// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmEc.hpp"
#include "AziHsmPKeys.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <filesystem>
#include <string>
#include <memory>
#include <catch2/catch_test_macros.hpp>

namespace fs = std::filesystem;

// Actual library path and Engine ID
#ifndef AZIHSM_LIB_DIR
#define ENGINEDIR "../target/debug/"
#else
#define ENGINEDIR AZIHSM_LIB_DIR
#endif

#ifdef OPENSSL_3
#define DEFAULT_ENGINESDIR "/usr/lib/x86_64-linux-gnu/engines-3/"
#else
#define DEFAULT_ENGINESDIR "/usr/lib/x86_64-linux-gnu/engines-1.1/"
#endif

const char *ENGINE_ID = "azihsmengine";
const char *ENGINE_SO_DIR = ENGINEDIR;
const char *ENGINE_SO_NAME = "libazihsmengine.so";

static std::string findEngineLib(const std::string &engine_dir, const std::string &filename)
{
    const fs::path engines_dir = engine_dir;
    const fs::path default_engines_dir = DEFAULT_ENGINESDIR;

    std::vector<fs::path>
        directories = {engines_dir, default_engines_dir};
    for (const auto &directory : directories)
    {
        fs::path full_path = directory / filename;
        if (fs::exists(full_path))
        {
            return fs::absolute(full_path).string();
        }
    }

    throw std::runtime_error("Could not find engine path");
}

AziHsmEngine get_test_engine(const char *so_dir, const char *so_name, const char *engine_id)
{
    return AziHsmEngine(findEngineLib(so_dir, so_name), engine_id);
}

TEST_CASE("AZIHSM Engine Loading and Unloading", "[AziHsmEngineLoadUnload]")
{
    SECTION("Valid Engine ID and library")
    {
        AziHsmEngine azihsm_engine = get_test_engine();
        REQUIRE(azihsm_engine.getEngine() != nullptr);
    }

    SECTION("Check engine version and OpenSSL version match")
    {
        AziHsmEngine azihsm_engine = get_test_engine();
        const AziHsmEngineInfo *engine_info = azihsm_get_engine_info(azihsm_engine.getEngine());
        REQUIRE(engine_info != nullptr);

        REQUIRE(engine_info->ossl_version.version == OPENSSL_VERSION_NUMBER);
        REQUIRE(engine_info->ossl_version.version == OpenSSL_version_num());
    }

    SECTION("Get engine name by ID")
    {
        AziHsmEngine azihsm_engine = get_test_engine();
        REQUIRE(ENGINE_add(azihsm_engine.getEngine()) == 1);
        ENGINE *engine = ENGINE_by_id("azihsmengine");
        REQUIRE(engine != nullptr);
        ENGINE_free(engine);
        ENGINE_remove(azihsm_engine.getEngine());
    }

    SECTION("Invalid Engine ID")
    {
        REQUIRE_THROWS(get_test_engine(ENGINE_SO_DIR, ENGINE_SO_NAME, "test"));
    }

    SECTION("Lib with No HSM devices")
    {
        const char *no_dev_so_name = "libazihsm-nodev-engine.so";
        const char *no_dev_so_dir = "../../";
        REQUIRE_THROWS(get_test_engine(no_dev_so_dir, no_dev_so_name, ENGINE_ID));
    }
}

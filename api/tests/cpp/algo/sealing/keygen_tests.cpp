// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstdint>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/part_list_handle.hpp"
#include "utils/utils.hpp"

/// Test fixture for security-domain sealing key generation
/// (`AZIHSM_ALGO_ID_SD_SEALING_KEY_GEN`).
///
/// Sealing key generation is only valid on a V2 (security-domain)
/// session, which requires the two-phase TBOR HPKE handshake implemented
/// only by the emu (in-process firmware) backend. A *complete* end-to-end
/// generation additionally needs a fully provisioned partition (the FW
/// handler requires the `Initialized` lifecycle state and a
/// Crypto-Officer session), which no test harness sets up. These tests
/// therefore exercise the FFI boundary and host-side property validation
/// that run *before* the device produces a key, mirroring the
/// `partition_ex` host-guard tests.
class azihsm_sealing_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Open and factory-reset a partition into a clean state. Records a
    // gtest failure and returns 0 on error; the returned handle must be
    // closed by the caller.
    static azihsm_handle open_reset_partition(std::vector<azihsm_char> &path)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle, test_api_rev());
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "azihsm_part_open failed: " << err;
            return 0;
        }

        err = azihsm_part_reset(part_handle);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "azihsm_part_reset failed: " << err;
            azihsm_part_close(part_handle);
            return 0;
        }

        return part_handle;
    }

    // Open a Crypto-Officer security-domain session on an already-open
    // partition handle. Records a gtest failure and returns 0 on error;
    // the returned handle must be closed by the caller.
    static azihsm_handle open_sd_session(azihsm_handle part_handle)
    {
        azihsm_handle sess_handle = 0;
        azihsm_session_psk psk{ 0, nullptr };
        auto err = azihsm_sess_ex_open(
            part_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );
        if (err != AZIHSM_STATUS_SUCCESS || sess_handle == 0)
        {
            ADD_FAILURE() << "azihsm_sess_ex_open failed: " << err;
            return 0;
        }
        return sess_handle;
    }
};

namespace
{
// Builder for a security-domain sealing-key property list. Owns the
// scalar backing storage so the `azihsm_key_prop` `val` pointers stay
// valid for the lifetime of the builder. Well-formed defaults describe a
// `Sealing`-kind P-384 secret key permitted for derivation only, matching
// the wire contract enforced by `HsmSealingKey::validate_props`.
struct SealingProps
{
    azihsm_key_kind kind = AZIHSM_KEY_KIND_SEALING;
    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    uint32_t bits = 384;
    bool include_derive = true;
    uint8_t derive_val = 1;
    std::vector<azihsm_key_prop> storage;

    azihsm_key_prop_list list()
    {
        storage.clear();
        storage.push_back({ AZIHSM_KEY_PROP_ID_KIND, &kind, sizeof(kind) });
        storage.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        storage.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
        if (include_derive)
        {
            storage.push_back({ AZIHSM_KEY_PROP_ID_DERIVE, &derive_val, sizeof(derive_val) });
        }
        return { storage.data(), static_cast<uint32_t>(storage.size()) };
    }
};

azihsm_algo sealing_algo()
{
    azihsm_algo algo{};
    algo.id = AZIHSM_ALGO_ID_SD_SEALING_KEY_GEN;
    algo.params = nullptr;
    algo.len = 0;
    return algo;
}
} // namespace

// ── FFI boundary (backend-agnostic) ─────────────────────────────────────────
// These fail at the FFI boundary before the algorithm is dispatched or a
// session is resolved, so they run on every backend and need no session.

// A NULL output handle pointer is rejected before anything else.
TEST_F(azihsm_sealing_keygen, key_gen_null_key_handle)
{
    SealingProps props;
    auto algo = sealing_algo();
    auto prop_list = props.list();

    auto err = azihsm_key_gen(0, &algo, &prop_list, nullptr);

    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
}

// A NULL algorithm pointer is rejected.
TEST_F(azihsm_sealing_keygen, key_gen_null_algo)
{
    SealingProps props;
    auto prop_list = props.list();
    azihsm_handle key_handle = 0;

    auto err = azihsm_key_gen(0, nullptr, &prop_list, &key_handle);

    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    ASSERT_EQ(key_handle, 0u);
}

// A NULL property-list pointer is rejected.
TEST_F(azihsm_sealing_keygen, key_gen_null_prop_list)
{
    auto algo = sealing_algo();
    azihsm_handle key_handle = 0;

    auto err = azihsm_key_gen(0, &algo, nullptr, &key_handle);

    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    ASSERT_EQ(key_handle, 0u);
}

// ── Host-side dispatch + property validation (emu only) ──────────────────────
// The checks below run inside the sealing key-gen dispatch, which needs a
// live security-domain (V2) session — implemented only by the emu backend.
// They complete *before* the device produces a key, so they are
// deterministic on an unprovisioned partition.
#ifdef AZIHSM_FEATURE_EMU

// Sealing key generation takes no algorithm-specific parameters; a
// non-NULL `params` (with non-zero `len`) is rejected up front.
TEST_F(azihsm_sealing_keygen, key_gen_rejects_algo_params_present)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

        SealingProps props;
        auto prop_list = props.list();

        uint8_t param_byte = 0;
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SD_SEALING_KEY_GEN;
        algo.params = &param_byte;
        algo.len = 1;

        azihsm_handle key_handle = 0;
        auto err = azihsm_key_gen(sess_handle, &algo, &prop_list, &key_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(key_handle, 0u);
    });
}

// A non-`Sealing` key kind is rejected by the sealing property guard.
TEST_F(azihsm_sealing_keygen, key_gen_rejects_wrong_kind)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

        SealingProps props;
        props.kind = AZIHSM_KEY_KIND_AES;
        auto algo = sealing_algo();
        auto prop_list = props.list();

        azihsm_handle key_handle = 0;
        auto err = azihsm_key_gen(sess_handle, &algo, &prop_list, &key_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(key_handle, 0u);
    });
}

// A `Sealing` key that is not P-384 sized is rejected: `SdSealingKeyGen`
// always produces a 384-bit scalar, so the props must match.
TEST_F(azihsm_sealing_keygen, key_gen_rejects_wrong_bits)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

        SealingProps props;
        props.bits = 256;
        auto algo = sealing_algo();
        auto prop_list = props.list();

        azihsm_handle key_handle = 0;
        auto err = azihsm_key_gen(sess_handle, &algo, &prop_list, &key_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(key_handle, 0u);
    });
}

// A `Sealing` key without derive usage is rejected: derivation is the
// only permitted usage for a sealing key.
TEST_F(azihsm_sealing_keygen, key_gen_rejects_missing_derive)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

        SealingProps props;
        props.include_derive = false;
        auto algo = sealing_algo();
        auto prop_list = props.list();

        azihsm_handle key_handle = 0;
        auto err = azihsm_key_gen(sess_handle, &algo, &prop_list, &key_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(key_handle, 0u);
    });
}

// Well-formed sealing props pass every host-side guard, so the request is
// constructed and shipped to the device. The call is therefore never
// rejected with the host-guard statuses (`INVALID_ARGUMENT` /
// `INVALID_KEY_PROPS`); it may still fail on-device because a freshly
// reset partition is not provisioned (the FW `SdSealingKeyGen` handler
// requires the `Initialized` lifecycle state). This exercises the FFI
// property conversion and request-construction path the negative tests
// skip.
TEST_F(azihsm_sealing_keygen, key_gen_valid_props_pass_host_guards)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

        SealingProps props;
        auto algo = sealing_algo();
        auto prop_list = props.list();

        azihsm_handle key_handle = 0;
        auto err = azihsm_key_gen(sess_handle, &algo, &prop_list, &key_handle);

        EXPECT_NE(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        EXPECT_NE(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

        // If the device unexpectedly produced a key, don't leak it.
        if (err == AZIHSM_STATUS_SUCCESS && key_handle != 0)
        {
            azihsm_key_delete(key_handle);
        }
    });
}
#endif // AZIHSM_FEATURE_EMU

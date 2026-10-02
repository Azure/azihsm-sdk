// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstddef>
#include <gtest/gtest.h>
#include <scope_guard.hpp>

#include "handle/part_list_handle.hpp"
#include "utils/utils.hpp"

static_assert(offsetof(azihsm_sess_ex_part_init_params, part_policy) == 0);
static_assert(offsetof(azihsm_sess_ex_part_final_params, part_policy) == 0);
static_assert(offsetof(azihsm_sd_create_remote_backup_params, part_policy) == 0);
static_assert(offsetof(azihsm_sd_reseal_remote_backup_params, part_policy) == 0);
static_assert(offsetof(azihsm_sd_restore_remote_backup_params, part_policy) == 0);
static_assert(offsetof(azihsm_sd_create_peer_backup_params, part_policy) == 0);
static_assert(offsetof(azihsm_sd_restore_peer_backup_params, part_policy) == 0);

class azihsm_sess_ex : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Open and factory-reset a partition into a clean state.
    //
    // Unlike `azihsm_sess_open` (MBOR), `azihsm_sess_ex_open` runs the
    // two-phase TBOR HPKE handshake against the partition's *default*
    // PSK and identity key, so it does NOT require MBOR credential
    // establishment (`azihsm_part_init`). A freshly reset partition is
    // all it needs — matching the Rust `new_partition()` helper. The
    // returned handle must be closed by the caller.
    //
    // On any failure a gtest failure is recorded and 0 is returned so the
    // caller can early-return instead of operating on an invalid handle;
    // if reset fails the opened handle is closed before returning.
    static azihsm_handle open_reset_partition(std::vector<azihsm_char> &path)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle, sd_test_api_rev());
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

    // Open a security-domain session on an already-open partition handle.
    //
    // Records a gtest failure and returns 0 on error so the caller can
    // early-return. The returned handle must be closed by the caller.
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

// Happy-path session open requires the two-phase TBOR HPKE handshake, which is
// implemented by a real backend (emu or hardware), not mock; the mock backend
// returns `UnsupportedEncoding` for TBOR ops. Exclude these tests from the mock
// lane (see `AZIHSM_FEATURE_MOCK` in CMakeLists).
#if !defined(AZIHSM_FEATURE_MOCK)
TEST_F(azihsm_sess_ex, open_and_close)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = 0;
        azihsm_session_psk psk{ 0, nullptr };
        auto err = azihsm_sess_ex_open(
            part_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sess_handle, 0);

        auto sess_guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });
    });
}
#endif // !defined(AZIHSM_FEATURE_MOCK)

TEST_F(azihsm_sess_ex, open_null_sess_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_session_psk psk{ 0, nullptr };
        auto err =
            azihsm_sess_ex_open(part_handle, &psk, AZIHSM_SESSION_EX_TYPE_AUTHENTICATED, nullptr);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sess_ex, open_invalid_partition_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle bad_handle = 0xDEADBEEF;

        azihsm_handle sess_handle = 0;

        azihsm_session_psk psk{ 0, nullptr };
        auto err = azihsm_sess_ex_open(
            bad_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// A NULL `psk` credential pointer is rejected before any device round-trip.
TEST_F(azihsm_sess_ex, open_null_psk)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_ex_open(
            part_handle,
            nullptr,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// An unknown `psk_id` (neither CO = 0 nor CU = 1) is rejected.
TEST_F(azihsm_sess_ex, open_invalid_psk_id)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = 0;
        azihsm_session_psk psk{ 2, nullptr }; // 2 is neither CO nor CU
        auto err = azihsm_sess_ex_open(
            part_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// A caller-supplied PSK buffer of the wrong length (not `PSK_LEN`) is rejected.
TEST_F(azihsm_sess_ex, open_wrong_length_psk)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = 0;
        // 16 bytes: a valid buffer but the wrong length (PSK is 32 bytes).
        std::vector<uint8_t> short_psk(16, 0);
        azihsm_buffer psk_buf{ short_psk.data(), static_cast<uint32_t>(short_psk.size()) };
        azihsm_session_psk psk{ 0, &psk_buf };
        auto err = azihsm_sess_ex_open(
            part_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// `azihsm_sess_ex_psk_change` resolves the session handle before touching
// the PSK buffer, so an invalid handle is rejected on every backend.
TEST_F(azihsm_sess_ex, psk_change_invalid_session_handle)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    // A well-formed 32-byte (`PSK_LEN`) PSK, so the handle is what's rejected.
    std::vector<uint8_t> new_psk(32, 0x5A);
    azihsm_buffer new_psk_buf{ new_psk.data(), static_cast<uint32_t>(new_psk.size()) };

    auto err = azihsm_sess_ex_psk_change(bad_handle, &new_psk_buf);

    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// The `azihsm_sess_ex_part_init` tests below need a live security-domain
// session, which requires the two-phase TBOR HPKE handshake implemented only by
// the emu (in-process firmware) backend. They exercise the ABI-boundary
// validation and buffer-probe contract that runs *before* the partition is
// provisioned, so they do not require valid provisioning inputs.
#if !defined(AZIHSM_FEATURE_MOCK)
namespace
{
// Well-formed (non-empty, non-null) provisioning inputs. The byte contents and
// exact lengths are irrelevant for the pre-provisioning validation paths these
// tests cover, since the FFI rejects them before reaching `part_init_ex`.
struct PartInitInputs
{
    std::vector<uint8_t> mach_seed = std::vector<uint8_t>(32, 0);
    std::vector<uint8_t> part_policy = std::vector<uint8_t>(32, 0);
    std::vector<uint8_t> pota = std::vector<uint8_t>(48, 0);
    std::vector<uint8_t> sata = std::vector<uint8_t>(48, 0);
    azihsm_buffer mach_seed_buf{};
    azihsm_buffer part_policy_buf{};
    azihsm_buffer pota_buf{};
    azihsm_buffer sata_buf{};
    azihsm_sess_ex_part_init_params params{};

    PartInitInputs()
    {
        mach_seed_buf = { mach_seed.data(), static_cast<uint32_t>(mach_seed.size()) };
        part_policy_buf = { part_policy.data(), static_cast<uint32_t>(part_policy.size()) };
        pota_buf = { pota.data(), static_cast<uint32_t>(pota.size()) };
        sata_buf = { sata.data(), static_cast<uint32_t>(sata.size()) };
        params.mach_seed = &mach_seed_buf;
        params.part_policy = &part_policy_buf;
        params.pota_thumbprint = &pota_buf;
        params.sata_thumbprint = &sata_buf;
        params.sapota_thumbprint = nullptr;
    }
};
} // namespace

// A NULL `params` pointer is rejected before any output buffer is touched.
TEST_F(azihsm_sess_ex, part_init_null_params)
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

        uint8_t csr_byte = 0;
        uint8_t report_byte = 0;
        azihsm_buffer pta_csr{ &csr_byte, 1 };
        azihsm_buffer pta_report{ &report_byte, 1 };

        auto err = azihsm_sess_ex_part_init(sess_handle, nullptr, &pta_csr, &pta_report);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Passing the same buffer for both outputs is rejected as INVALID_ARGUMENT
// (aliased mutable outputs are not permitted).
TEST_F(azihsm_sess_ex, part_init_same_output_buffer)
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

        PartInitInputs in;
        uint8_t byte = 0;
        azihsm_buffer shared{ &byte, 1 };

        auto err = azihsm_sess_ex_part_init(sess_handle, &in.params, &shared, &shared);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Undersized output buffers are rejected with BUFFER_TOO_SMALL before the
// partition is provisioned, and *both* `len` fields are updated to the required
// capacity so a single probe call reports both sizes.
TEST_F(azihsm_sess_ex, part_init_buffer_too_small)
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

        PartInitInputs in;
        uint8_t csr_byte = 0;
        uint8_t report_byte = 0;
        azihsm_buffer pta_csr{ &csr_byte, 1 };
        azihsm_buffer pta_report{ &report_byte, 1 };

        auto err = azihsm_sess_ex_part_init(sess_handle, &in.params, &pta_csr, &pta_report);

        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(pta_csr.len, 1u);
        EXPECT_GT(pta_report.len, 1u);
    });
}

// A NULL `ptr` with `len == 0` is a valid size probe: it returns
// BUFFER_TOO_SMALL with both `len` fields set to the required capacity.
TEST_F(azihsm_sess_ex, part_init_null_output_probe)
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

        PartInitInputs in;
        azihsm_buffer pta_csr{ nullptr, 0 };
        azihsm_buffer pta_report{ nullptr, 0 };

        auto err = azihsm_sess_ex_part_init(sess_handle, &in.params, &pta_csr, &pta_report);

        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(pta_csr.len, 0u);
        EXPECT_GT(pta_report.len, 0u);
    });
}

// A wrong-length `part_policy` buffer is rejected with INVALID_ARGUMENT at
// the native boundary, before the partition is provisioned. The output
// buffers are sized to clear the buffer-capacity probe so the failure is
// attributable to the policy-length guard (the typed Rust API accepts only
// a `&PartPolicy`, so this length check now lives at the FFI boundary where
// the opaque image is parsed back into a `PartPolicy`).
TEST_F(azihsm_sess_ex, part_init_rejects_bad_part_policy_len)
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

        // `PartInitInputs` carries a deliberately wrong-length (32-byte)
        // policy image; `PART_POLICY_LEN` is 484.
        PartInitInputs in;
        std::vector<uint8_t> csr(512, 0);
        std::vector<uint8_t> report(1024, 0);
        azihsm_buffer pta_csr{ csr.data(), static_cast<uint32_t>(csr.size()) };
        azihsm_buffer pta_report{ report.data(), static_cast<uint32_t>(report.size()) };

        auto err = azihsm_sess_ex_part_init(sess_handle, &in.params, &pta_csr, &pta_report);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// A NULL `new_psk` buffer is rejected once the session is resolved.
TEST_F(azihsm_sess_ex, psk_change_null_new_psk)
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

        auto err = azihsm_sess_ex_psk_change(sess_handle, nullptr);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// A `new_psk` buffer of the wrong length (not `PSK_LEN` = 32 bytes) is rejected.
TEST_F(azihsm_sess_ex, psk_change_wrong_length_new_psk)
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

        // 16 bytes: a valid buffer but the wrong length (PSK is 32 bytes).
        std::vector<uint8_t> short_psk(16, 0x5A);
        azihsm_buffer short_psk_buf{ short_psk.data(), static_cast<uint32_t>(short_psk.size()) };

        auto err = azihsm_sess_ex_psk_change(sess_handle, &short_psk_buf);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// PSK-rotation round trip: after rotating the CO PSK from the default, the
// partition accepts the new secret on `azihsm_sess_ex_open` and rejects the
// default — the C-ABI mirror of the Rust `change_psk_rotates_co_psk` test.
TEST_F(azihsm_sess_ex, psk_change_rotates_co_psk)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        // A non-default replacement CO PSK, exactly `PSK_LEN` (32 bytes).
        std::vector<uint8_t> new_psk(32, 0x5A);
        azihsm_buffer new_psk_buf{ new_psk.data(), static_cast<uint32_t>(new_psk.size()) };

        // Open with the default CO PSK, rotate it, then close the session.
        {
            azihsm_handle sess_handle = open_sd_session(part_handle);
            if (sess_handle == 0)
            {
                return;
            }
            auto sess_guard =
                scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

            ASSERT_EQ(azihsm_sess_ex_psk_change(sess_handle, &new_psk_buf), AZIHSM_STATUS_SUCCESS);
        }

        // Reopening with the rotated secret must now succeed.
        {
            azihsm_handle sess_handle = 0;
            azihsm_session_psk psk{ 0, &new_psk_buf };
            auto err = azihsm_sess_ex_open(
                part_handle,
                &psk,
                AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
                &sess_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(sess_handle, 0);
            azihsm_sess_close(sess_handle);
        }

        // Reopening with the (now stale) default CO PSK must be rejected.
        {
            azihsm_handle sess_handle = 0;
            azihsm_session_psk psk{ 0, nullptr };
            auto err = azihsm_sess_ex_open(
                part_handle,
                &psk,
                AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
                &sess_handle
            );
            ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            // Defensive: if the stale default PSK unexpectedly opened a
            // session, don't leak the handle.
            if (sess_handle != 0)
            {
                azihsm_sess_close(sess_handle);
            }
        }
    });
}

// A `part_final` size probe with a too-small `local_mk_backup` reports
// BUFFER_TOO_SMALL even when the `part_policy` buffer has the wrong length,
// because the output-buffer capacity check now precedes the policy-length
// parse (matching `part_init`). A single non-empty cert clears the cert-chain
// length guard; the chain contents are only validated later, inside
// `part_final_ex`, which the probe never reaches.
TEST_F(azihsm_sess_ex, part_final_size_probe_precedes_policy_parse)
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

        // Deliberately wrong-length (32-byte) policy image; `PART_POLICY_LEN`
        // is 484.
        std::vector<uint8_t> policy(32, 0);
        std::vector<uint8_t> cert(1, 0);
        azihsm_buffer policy_buf{ policy.data(), static_cast<uint32_t>(policy.size()) };
        azihsm_buffer cert_buf{ cert.data(), static_cast<uint32_t>(cert.size()) };

        azihsm_sess_ex_part_final_params params{};
        params.part_policy = &policy_buf;
        params.pta_cert_chain = &cert_buf;
        params.pta_cert_chain_len = 1;
        params.prev_local_mk_backup = nullptr;

        // Zero-capacity output buffer: a pure size probe.
        azihsm_buffer local_mk_backup{ nullptr, 0 };
        auto err = azihsm_sess_ex_part_final(sess_handle, &params, &local_mk_backup);

        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(local_mk_backup.len, 0u);
    });
}

TEST_F(azihsm_sess_ex, part_final_rejects_bad_part_policy_len)
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

        std::vector<uint8_t> policy(32, 0);
        std::vector<uint8_t> cert(1, 0);
        azihsm_buffer policy_buf{ policy.data(), static_cast<uint32_t>(policy.size()) };
        azihsm_buffer cert_buf{ cert.data(), static_cast<uint32_t>(cert.size()) };

        azihsm_sess_ex_part_final_params params{};
        params.part_policy = &policy_buf;
        params.pta_cert_chain = &cert_buf;
        params.pta_cert_chain_len = 1;
        params.prev_local_mk_backup = nullptr;

        azihsm_buffer local_mk_backup{ nullptr, 0 };
        ASSERT_EQ(
            azihsm_sess_ex_part_final(sess_handle, &params, &local_mk_backup),
            AZIHSM_STATUS_BUFFER_TOO_SMALL
        );
        ASSERT_GT(local_mk_backup.len, 0u);

        std::vector<uint8_t> backup(local_mk_backup.len, 0);
        local_mk_backup.ptr = backup.data();
        ASSERT_EQ(
            azihsm_sess_ex_part_final(sess_handle, &params, &local_mk_backup),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}
#endif // !defined(AZIHSM_FEATURE_MOCK)

// The typed partition-policy builder FFI is pure host-side serialization and
// needs no device, so these run in every lane (including the mock lane).

// NULL builder handles are rejected by every entry point.
TEST(azihsm_part_policy_builder, null_handle_rejected)
{
    EXPECT_EQ(
        azihsm_part_policy_builder_set_version(nullptr, 1, 0),
        AZIHSM_STATUS_INVALID_ARGUMENT
    );
    EXPECT_EQ(azihsm_part_policy_builder_set_flags(nullptr, 0), AZIHSM_STATUS_INVALID_ARGUMENT);

    azihsm_buffer out{ nullptr, 0 };
    EXPECT_EQ(azihsm_part_policy_build(nullptr, &out), AZIHSM_STATUS_INVALID_ARGUMENT);

    // A NULL out-handle pointer is rejected by the constructor.
    EXPECT_EQ(azihsm_part_policy_builder_new(nullptr), AZIHSM_STATUS_INVALID_ARGUMENT);

    // Freeing NULL is a documented no-op (must not crash).
    azihsm_part_policy_builder_free(nullptr);
}

TEST(azihsm_part_policy_builder, misaligned_handle_rejected)
{
    azihsm_part_policy_builder *builder = nullptr;
    ASSERT_EQ(azihsm_part_policy_builder_new(&builder), AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(builder, nullptr);
    auto guard =
        scope_guard::make_scope_exit([&builder] { azihsm_part_policy_builder_free(builder); });
    auto *misaligned =
        reinterpret_cast<azihsm_part_policy_builder *>(reinterpret_cast<uint8_t *>(builder) + 1);

    EXPECT_EQ(azihsm_part_policy_builder_set_flags(misaligned, 0), AZIHSM_STATUS_INVALID_ARGUMENT);
    azihsm_buffer out{ nullptr, 0 };
    EXPECT_EQ(azihsm_part_policy_build(misaligned, &out), AZIHSM_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(out.len, 0u);
}

// The two-call size-probe contract: a zero-capacity buffer reports the
// required length, and a correctly-sized buffer then serializes the image.
TEST(azihsm_part_policy_builder, build_round_trips_via_size_probe)
{
    azihsm_part_policy_builder *b = nullptr;
    ASSERT_EQ(azihsm_part_policy_builder_new(&b), AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(b, nullptr);
    auto guard = scope_guard::make_scope_exit([&b] { azihsm_part_policy_builder_free(b); });

    // `PolicyKeyKind::Ecc384` (kind 0) is `X || Y`, exactly
    // `POLICY_MAX_KEY_LEN` (96) bytes; the firmware rejects any other
    // length, so the builder requires it too.
    std::vector<uint8_t> pota(96, 0x11);
    azihsm_buffer pota_buf{ pota.data(), static_cast<uint32_t>(pota.size()) };
    ASSERT_EQ(azihsm_part_policy_builder_set_version(b, 1, 0), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(azihsm_part_policy_builder_set_pota_key(b, 0, &pota_buf), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(azihsm_part_policy_builder_set_sata_key(b, 0, &pota_buf), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(azihsm_part_policy_builder_set_flags(b, 0), AZIHSM_STATUS_SUCCESS);

    // Probe: zero-capacity buffer yields the required length.
    azihsm_buffer probe{ nullptr, 0 };
    ASSERT_EQ(azihsm_part_policy_build(b, &probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(probe.len, 0u);

    // Serialize into a correctly-sized buffer.
    std::vector<uint8_t> image(probe.len, 0);
    azihsm_buffer out{ image.data(), probe.len };
    ASSERT_EQ(azihsm_part_policy_build(b, &out), AZIHSM_STATUS_SUCCESS);
    EXPECT_EQ(out.len, probe.len);

    // The version bytes land at the front of the canonical image.
    EXPECT_EQ(image[0], 1u);
    EXPECT_EQ(image[1], 0u);
}

TEST(azihsm_part_policy_builder, invalid_versions_and_reserved_flags_rejected_at_build)
{
    azihsm_part_policy_builder *builder = nullptr;
    ASSERT_EQ(azihsm_part_policy_builder_new(&builder), AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(builder, nullptr);
    auto guard =
        scope_guard::make_scope_exit([&builder] { azihsm_part_policy_builder_free(builder); });
    std::vector<uint8_t> key(96, 0x11);
    azihsm_buffer key_buf{ key.data(), static_cast<uint32_t>(key.size()) };
    ASSERT_EQ(azihsm_part_policy_builder_set_pota_key(builder, 0, &key_buf), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(azihsm_part_policy_builder_set_sata_key(builder, 0, &key_buf), AZIHSM_STATUS_SUCCESS);

    for (uint16_t major = 0; major <= 255; ++major)
    {
        ASSERT_EQ(
            azihsm_part_policy_builder_set_version(builder, static_cast<uint8_t>(major), 255),
            AZIHSM_STATUS_SUCCESS
        );
        azihsm_buffer out{ nullptr, 0 };
        EXPECT_EQ(
            azihsm_part_policy_build(builder, &out),
            major == 1 ? AZIHSM_STATUS_BUFFER_TOO_SMALL : AZIHSM_STATUS_INVALID_ARGUMENT
        ) << "major="
          << major;
        if (major != 1)
        {
            EXPECT_EQ(out.len, 0u);
        }
    }

    ASSERT_EQ(azihsm_part_policy_builder_set_version(builder, 1, 0), AZIHSM_STATUS_SUCCESS);
    for (uint16_t flags = 0; flags <= 255; ++flags)
    {
        ASSERT_EQ(
            azihsm_part_policy_builder_set_flags(builder, static_cast<uint8_t>(flags)),
            AZIHSM_STATUS_SUCCESS
        );
        azihsm_buffer out{ nullptr, 0 };
        EXPECT_EQ(
            azihsm_part_policy_build(builder, &out),
            flags <= 7 ? AZIHSM_STATUS_BUFFER_TOO_SMALL : AZIHSM_STATUS_INVALID_ARGUMENT
        ) << "flags="
          << flags;
        if (flags > 7)
        {
            EXPECT_EQ(out.len, 0u);
        }
    }
}

// Oversized key material is rejected at build time rather than truncated
// (truncation would yield a *different* key while reporting success).
TEST(azihsm_part_policy_builder, oversized_key_rejected_at_build)
{
    azihsm_part_policy_builder *b = nullptr;
    ASSERT_EQ(azihsm_part_policy_builder_new(&b), AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(b, nullptr);
    auto guard = scope_guard::make_scope_exit([&b] { azihsm_part_policy_builder_free(b); });

    std::vector<uint8_t> valid_key(96, 0x11);
    azihsm_buffer valid_key_buf{ valid_key.data(), static_cast<uint32_t>(valid_key.size()) };
    ASSERT_EQ(azihsm_part_policy_builder_set_pota_key(b, 0, &valid_key_buf), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(azihsm_part_policy_builder_set_sata_key(b, 0, &valid_key_buf), AZIHSM_STATUS_SUCCESS);
    azihsm_buffer probe{ nullptr, 0 };
    ASSERT_EQ(azihsm_part_policy_build(b, &probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);

    // `POLICY_MAX_KEY_LEN` is 96; one byte over must not fit.
    std::vector<uint8_t> too_long(97, 0x22);
    azihsm_buffer key_buf{ too_long.data(), static_cast<uint32_t>(too_long.size()) };
    // The setter defers validation; it still reports success.
    ASSERT_EQ(azihsm_part_policy_builder_set_pota_key(b, 0, &key_buf), AZIHSM_STATUS_SUCCESS);

    std::vector<uint8_t> image(512, 0);
    azihsm_buffer out{ image.data(), static_cast<uint32_t>(image.size()) };
    EXPECT_EQ(azihsm_part_policy_build(b, &out), AZIHSM_STATUS_INVALID_ARGUMENT);
}

// A known key kind must carry its exact firmware-required length. An
// `Ecc384` (kind 0) key is `X || Y` = 96 bytes; a shorter key merely
// "fits" the 96-byte slot but is rejected at build time, since firmware
// rejects every non-96-byte Ecc384 key.
TEST(azihsm_part_policy_builder, wrong_length_ecc384_rejected_at_build)
{
    azihsm_part_policy_builder *b = nullptr;
    ASSERT_EQ(azihsm_part_policy_builder_new(&b), AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(b, nullptr);
    auto guard = scope_guard::make_scope_exit([&b] { azihsm_part_policy_builder_free(b); });

    std::vector<uint8_t> valid_key(96, 0x11);
    azihsm_buffer valid_key_buf{ valid_key.data(), static_cast<uint32_t>(valid_key.size()) };
    ASSERT_EQ(azihsm_part_policy_builder_set_pota_key(b, 0, &valid_key_buf), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(azihsm_part_policy_builder_set_sata_key(b, 0, &valid_key_buf), AZIHSM_STATUS_SUCCESS);
    azihsm_buffer probe{ nullptr, 0 };
    ASSERT_EQ(azihsm_part_policy_build(b, &probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);

    // 48 bytes fits the slot but is not a well-formed Ecc384 key.
    std::vector<uint8_t> too_short(48, 0x33);
    azihsm_buffer key_buf{ too_short.data(), static_cast<uint32_t>(too_short.size()) };
    ASSERT_EQ(azihsm_part_policy_builder_set_pota_key(b, 0, &key_buf), AZIHSM_STATUS_SUCCESS);

    std::vector<uint8_t> image(512, 0);
    azihsm_buffer out{ image.data(), static_cast<uint32_t>(image.size()) };
    EXPECT_EQ(azihsm_part_policy_build(b, &out), AZIHSM_STATUS_INVALID_ARGUMENT);
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>

#include "handle/part_list_handle.hpp"
#include "utils/utils.hpp"

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
    // all it needs — matching the Rust emu `fresh_emu_partition()`
    // helper. The returned handle must be closed by the caller.
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

    // Open a security-domain session on an already-open partition handle.
    //
    // Records a gtest failure and returns 0 on error so the caller can
    // early-return. The returned handle must be closed by the caller.
    static azihsm_handle open_sd_session(azihsm_handle part_handle)
    {
        azihsm_handle sess_handle = 0;
        auto err =
            azihsm_sess_ex_open(part_handle, AZIHSM_SESSION_EX_TYPE_AUTHENTICATED, &sess_handle);
        if (err != AZIHSM_STATUS_SUCCESS || sess_handle == 0)
        {
            ADD_FAILURE() << "azihsm_sess_ex_open failed: " << err;
            return 0;
        }
        return sess_handle;
    }
};

// Happy-path session open requires the two-phase TBOR HPKE handshake, which is
// only implemented by the emu (in-process firmware) backend; the mock backend
// returns `UnsupportedEncoding` for TBOR ops. Gate this test on the emu backend
// so it is excluded from the mock lane (see `AZIHSM_FEATURE_EMU` in CMakeLists).
#ifdef AZIHSM_FEATURE_EMU
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
        auto err =
            azihsm_sess_ex_open(part_handle, AZIHSM_SESSION_EX_TYPE_AUTHENTICATED, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sess_handle, 0);

        auto sess_guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });
    });
}
#endif // AZIHSM_FEATURE_EMU

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

        auto err = azihsm_sess_ex_open(part_handle, AZIHSM_SESSION_EX_TYPE_AUTHENTICATED, nullptr);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sess_ex, open_invalid_partition_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle bad_handle = 0xDEADBEEF;

        azihsm_handle sess_handle = 0;

        auto err =
            azihsm_sess_ex_open(bad_handle, AZIHSM_SESSION_EX_TYPE_AUTHENTICATED, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// The `azihsm_sess_ex_part_init` tests below need a live security-domain
// session, which requires the two-phase TBOR HPKE handshake implemented only by
// the emu (in-process firmware) backend. They exercise the ABI-boundary
// validation and buffer-probe contract that runs *before* the partition is
// provisioned, so they do not require valid provisioning inputs.
#ifdef AZIHSM_FEATURE_EMU
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
#endif // AZIHSM_FEATURE_EMU

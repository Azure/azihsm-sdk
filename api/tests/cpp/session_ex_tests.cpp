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
    static azihsm_handle open_reset_partition(std::vector<azihsm_char> &path)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle, test_api_rev());
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = azihsm_part_reset(part_handle);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

        return part_handle;
    }
};

#if 0
TEST_F(azihsm_sess_ex, open_and_close)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        auto part_guard = scope_guard::make_scope_exit([&part_handle] {
            azihsm_part_close(part_handle);
        });

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
#endif

TEST_F(azihsm_sess_ex, open_null_sess_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
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

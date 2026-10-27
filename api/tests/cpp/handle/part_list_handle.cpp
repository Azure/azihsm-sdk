// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "part_list_handle.hpp"
#include "../utils/utils.hpp"
#include "part_handle.hpp"
#include "session_handle.hpp"

#include <scope_guard.hpp>

#if SESSION_EX_TESTS
#include "../utils/sd_provision.hpp"
#endif

void PartitionListHandle::for_each_session(const std::function<void(azihsm_handle)> &func) const
{
#if SESSION_EX_TESTS
    for_each_part([&](std::vector<azihsm_char> &path) {
        azihsm_str path_str{ path.data(), static_cast<uint32_t>(path.size()) };
        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle, session_ex_test_api_rev());
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to open session_ex test partition. Error: " + std::to_string(err)
            );
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        err = azihsm_part_reset(part_handle);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to reset session_ex test partition. Error: " + std::to_string(err)
            );
        }

        azihsm_handle session_handle = provision_sd_co_session(part_handle);
        if (session_handle == 0)
        {
            throw std::runtime_error("Failed to provision session_ex test partition");
        }
        auto session_guard =
            scope_guard::make_scope_exit([&session_handle] { azihsm_sess_close(session_handle); });

        func(session_handle);
    });
#else
    for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());
        func(session.get());
    });
#endif
}
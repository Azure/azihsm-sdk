// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "part_list_handle.hpp"
#include "../utils/utils.hpp"
#include "part_handle.hpp"
#include "session_handle.hpp"

#include <scope_guard.hpp>

namespace
{
constexpr size_t TEST_CO_PSK_LEN = 32;
constexpr uint8_t TEST_CO_PSK_FILL = 0xA5;
} // namespace
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

#if defined(AZIHSM_FEATURE_EMU)
        err = azihsm_part_reset(part_handle);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to reset session_ex test partition. Error: " + std::to_string(err)
            );
        }
#endif

        std::vector<uint8_t> rotated_psk(TEST_CO_PSK_LEN, TEST_CO_PSK_FILL);
        azihsm_buffer rotated_psk_buf{ rotated_psk.data(),
                                       static_cast<uint32_t>(rotated_psk.size()) };
#if defined(AZIHSM_FEATURE_EMU)
        azihsm_session_psk psk{ 0, nullptr };
#else
        azihsm_session_psk psk{ 0, &rotated_psk_buf };
#endif
        azihsm_handle session_handle = 0;
        err = azihsm_sess_ex_open(
            part_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &session_handle
        );
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to call azihsm_sess_ex_open for a test. Error: " + std::to_string(err)
            );
        }
        auto session_guard =
            scope_guard::make_scope_exit([&session_handle] { azihsm_sess_close(session_handle); });

#if defined(AZIHSM_FEATURE_EMU)
        err = azihsm_sess_ex_psk_change(session_handle, &rotated_psk_buf);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to rotate session_ex test CO PSK. Error: " + std::to_string(err)
            );
        }
#endif

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
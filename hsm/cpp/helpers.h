// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <stdint.h>
#include <vector>

// Platform-specific character type alias
#if defined(_WIN32)
using AzihsmCharType = AzihsmWideChar;
#else
using AzihsmCharType = AzihsmChar;
#endif

extern uint8_t TEST_CRED_ID[16];

extern uint8_t TEST_CRED_PIN[16];

std::vector<AzihsmCharType> get_partition_path(azihsm_handle handle, uint32_t part_index);
std::pair<azihsm_handle, std::vector<AzihsmCharType>> open_partition(uint32_t part_index = 0);
std::vector<AzihsmCharType> create_azihsm_str(const char *str);
std::pair<azihsm_handle, azihsm_handle> open_session();

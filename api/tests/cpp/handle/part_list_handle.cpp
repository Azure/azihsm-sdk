// Copyright (C) Microsoft Corporation. All rights reserved.

#include "part_list_handle.hpp"
#include "part_handle.hpp"
#include "session_handle.hpp"

void PartitionListHandle::for_each_session(const std::function<void(azihsm_handle)> &func) const
{
    for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());
        func(session.get());
    });
}
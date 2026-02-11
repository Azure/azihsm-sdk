// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <optional>
#include <string>
#include <vector>
#include <azihsm_api.h>

// Helpers for multi-process tests, which simulate scenarios where
// (masked) key data needs to be transferred between different server instances.
// Testing of this kind is implemented as a pair of tests: the parent test and
// the child test. The parent test behaves as the first server instance,
// creating keys and beginning operations. It then runs the child test with
// relevant parameters in a separate process by using these helpers. The child
// test behaves as the second server instance, using the parameters from the parent,
// including the masked key data, to set up its HSM and continue performing
// operations to check the validity and usability of the masked key data.

struct cross_process_test_params
{
    // Common parameters for all tests
    std::string test_name;
    std::vector<uint8_t> path_bytes;
    std::vector<uint8_t> bmk;
    std::vector<uint8_t> obk;
    std::vector<uint8_t> seed;
    std::vector<uint8_t> message;
    std::vector<uint8_t> signature_or_ciphertext;
    std::vector<uint8_t> masked_key;
    
    // Algorithm-specific parameters
    std::optional<std::vector<uint8_t>> iv;  // For symmetric encryption (AES-CBC, etc.)

    cross_process_test_params(
        const std::string &test_name,
        const std::vector<uint8_t> &path_bytes,
        const std::vector<uint8_t> &bmk,
        const std::vector<uint8_t> &obk,
        const std::vector<uint8_t> &seed,
        const std::vector<uint8_t> &message,
        const std::vector<uint8_t> &signature_or_ciphertext,
        const std::vector<uint8_t> &masked_key,
        const std::optional<std::vector<uint8_t>> &iv = std::nullopt
    ) : test_name(test_name),
        path_bytes(path_bytes),
        bmk(bmk),
        obk(obk),
        seed(seed),
        message(message),
        signature_or_ciphertext(signature_or_ciphertext),
        masked_key(masked_key),
        iv(iv)
    {}

    cross_process_test_params() = default;
};

// Invoke the specified test in a child process, passing necessary
// parameters via a temporary file.
//
// Returns the exit code of the child process (0 for success, non-zero for failure).
int run_child_test(const cross_process_test_params & params);

// Called by the child process to collect test parameters set by the parent process.
cross_process_test_params get_cross_process_test_params();

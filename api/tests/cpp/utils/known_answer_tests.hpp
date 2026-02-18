// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <vector>
#include "utils/auto_key.hpp"

// Holds hard-coded data for a known-answer test (KAT).
struct CbcKnownAnswerTestCase
{
	uint32_t bits;
	const uint8_t *key;
	size_t key_len;
	const uint8_t *iv;
	size_t iv_len;
	const uint8_t *plaintext;
	size_t plaintext_len;
	const uint8_t *ciphertext;
	size_t ciphertext_len;
	const char *test_name;
};

// Shared NIST-style AES-CBC (no padding) known-answer test cases used across test suites.
const std::vector<CbcKnownAnswerTestCase> &cbc_known_answer_test_cases();

// Shared AES-CBC-PAD boundary test cases.
//
// These are intentionally separate from no-padding CBC KAT cases because they validate
// PKCS#7 boundary semantics in AES_CBC_PAD specifically:
// - 15-byte plaintext -> pad length 1
// - 16-byte plaintext -> full padding block (pad length 16)
//
// Broader plaintext-length behavior is covered by non-KAT padding sweeps in algorithm tests.
const std::vector<CbcKnownAnswerTestCase> &cbc_pad_boundary_known_answer_test_cases();

// Imports fixed local AES key bytes as an HSM key for deterministic validation.
//
// This is test harness setup: KATs require an exact key value, while normal keygen in tests
// produces random keys. The helper uses the supported RSA-AES wrap/unwrap ingest path.
auto_key import_local_aes_key_for_kat(
	azihsm_handle session,
	const uint8_t *local_key_data,
	size_t local_key_len,
	uint32_t aes_key_bits
);

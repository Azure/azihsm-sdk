// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <vector>
#include "utils/auto_key.hpp"

// Holds hard-coded data for a known-answer test (KAT).
struct CbcKnownAnswerVector
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

// Shared NIST-style AES-CBC known-answer vectors used across test suites.
const std::vector<CbcKnownAnswerVector> &cbc_known_answer_vectors();

// Shared AES-CBC-PAD boundary vectors (15-byte and 16-byte plaintext cases).
const std::vector<CbcKnownAnswerVector> &cbc_pad_boundary_known_answer_vectors();

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

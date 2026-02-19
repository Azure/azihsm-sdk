// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/known_answer_tests.hpp"
#include <functional>

class azihsm_aes_cbc : public ::testing::Test
{
  protected:
    enum class CryptOperation
    {
            Encrypt,
            Decrypt,
    };

    static constexpr size_t AES_BLOCK_SIZE = 16;

    PartitionListHandle part_list_ = PartitionListHandle{};

    static void init_cbc_algo(
        azihsm_algo &algo,
        azihsm_algo_aes_cbc_params &params,
        azihsm_algo_id algo_id,
        uint8_t iv_fill
    )
    {
        uint8_t iv[AES_BLOCK_SIZE] = { 0 };
        iv[0] = iv_fill;
        std::memcpy(params.iv, iv, sizeof(iv));

        algo.id = algo_id;
        algo.params = &params;
        algo.len = sizeof(params);
    }

    static azihsm_status crypt_call(
        CryptOperation operation,
        azihsm_algo *algo,
        azihsm_handle key_handle,
        azihsm_buffer *input,
        azihsm_buffer *output
    )
    {
        if (operation == CryptOperation::Encrypt)
        {
            return azihsm_crypt_encrypt(algo, key_handle, input, output);
        }

        return azihsm_crypt_decrypt(algo, key_handle, input, output);
    }

    static azihsm_status crypt_init_call(
        CryptOperation operation,
        azihsm_algo *algo,
        azihsm_handle key_handle,
        azihsm_handle *ctx
    )
    {
        if (operation == CryptOperation::Encrypt)
        {
            return azihsm_crypt_encrypt_init(algo, key_handle, ctx);
        }

        return azihsm_crypt_decrypt_init(algo, key_handle, ctx);
    }

    static azihsm_status crypt_update_call(
        CryptOperation operation,
        azihsm_handle ctx,
        azihsm_buffer *input,
        azihsm_buffer *output
    )
    {
        if (operation == CryptOperation::Encrypt)
        {
            return azihsm_crypt_encrypt_update(ctx, input, output);
        }

        return azihsm_crypt_decrypt_update(ctx, input, output);
    }

    static azihsm_status crypt_finish_call(
        CryptOperation operation,
        azihsm_handle ctx,
        azihsm_buffer *output
    )
    {
        if (operation == CryptOperation::Encrypt)
        {
            return azihsm_crypt_encrypt_finish(ctx, output);
        }

        return azihsm_crypt_decrypt_finish(ctx, output);
    }

    // Runs single-shot operation and returns the finish status.
    // If output sizing reports BUFFER_TOO_SMALL, retries once with a sized buffer.
    static azihsm_status single_shot_status_with_sizing(
        CryptOperation operation,
        azihsm_algo *algo,
        azihsm_handle key_handle,
        azihsm_buffer *input
    )
    {
        azihsm_buffer output{ nullptr, 0 };
        auto err = crypt_call(operation, algo, key_handle, input, &output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> candidate(output.len);
            output.ptr = candidate.data();
            err = crypt_call(operation, algo, key_handle, input, &output);
        }

        return err;
    }

    // Runs streaming update and returns finish status.
    // If output sizing reports BUFFER_TOO_SMALL, retries once with a sized buffer.
    static azihsm_status streaming_update_status_with_sizing(
        CryptOperation operation,
        azihsm_handle ctx,
        azihsm_buffer *input
    )
    {
        azihsm_buffer output{ nullptr, 0 };
        auto err = crypt_update_call(operation, ctx, input, &output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> out_buf(output.len);
            output.ptr = out_buf.data();
            err = crypt_update_call(operation, ctx, input, &output);
        }

        return err;
    }

    // Runs streaming finish and returns finish status.
    // If output sizing reports BUFFER_TOO_SMALL, retries once with a sized buffer.
    static azihsm_status streaming_finish_status_with_sizing(
        CryptOperation operation,
        azihsm_handle ctx
    )
    {
        azihsm_buffer output{ nullptr, 0 };
        auto err = crypt_finish_call(operation, ctx, &output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> out_buf(output.len);
            output.ptr = out_buf.data();
            err = crypt_finish_call(operation, ctx, &output);
        }

        return err;
    }

    // Returns AES-CBC-PAD ciphertext length for a plaintext length.
    static size_t padded_ciphertext_len(size_t plaintext_len)
    {
        return ((plaintext_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    }

    // Builds deterministic incrementing bytes: 0x00, 0x01, 0x02, ...
    static std::vector<uint8_t> make_incrementing_bytes(size_t len)
    {
        std::vector<uint8_t> bytes(len);
        for (size_t i = 0; i < len; ++i)
        {
            bytes[i] = static_cast<uint8_t>(i & 0xFF);
        }

        return bytes;
    }

    // Executes single-shot encrypt/decrypt with two-call output sizing flow.
    static std::vector<uint8_t> single_shot_crypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        CryptOperation operation
    )
    {
        azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
        azihsm_buffer output{ nullptr, 0 };
        azihsm_status err;

        // Query required buffer size
        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        }
        else
        {
            err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        }
        EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(output.len, 0);

        // Allocate buffer and perform operation
        std::vector<uint8_t> result(output.len);
        output.ptr = result.data();

        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        }
        else
        {
            err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        }
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Resize to actual bytes written
        result.resize(output.len);
        return result;
    }

    // Executes streaming encrypt/decrypt with chunked update and finish sizing flow.
    static std::vector<uint8_t> streaming_crypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        size_t chunk_size,
        CryptOperation operation
    )
    {
        auto_ctx ctx;
        azihsm_status err;

        // Initialize context
        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt_init(algo, key_handle, ctx.get_ptr());
        }
        else
        {
            err = azihsm_crypt_decrypt_init(algo, key_handle, ctx.get_ptr());
        }
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_NE(ctx.get(), 0);

        std::vector<uint8_t> output;
        size_t offset = 0;

        // Process in chunks
        while (offset < input_len)
        {
            size_t current_chunk = std::min(chunk_size, input_len - offset);
            azihsm_buffer input{ const_cast<uint8_t *>(input_data + offset),
                                 static_cast<uint32_t>(current_chunk) };
            azihsm_buffer out_buf{ nullptr, 0 };

            if (operation == CryptOperation::Encrypt)
            {
                err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);
            }
            else
            {
                err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);
            }

            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                // Buffer too small, allocate and retry with same input
                EXPECT_GT(out_buf.len, 0);
                size_t current_pos = output.size();
                output.resize(current_pos + out_buf.len);
                out_buf.ptr = output.data() + current_pos;

                if (operation == CryptOperation::Encrypt)
                {
                    err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);
                }
                else
                {
                    err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);
                }
                EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
                // Adjust output size to actual bytes written
                output.resize(current_pos + out_buf.len);
            }
            else if (err == AZIHSM_STATUS_SUCCESS)
            {
                // Success - data may or may not have been produced
                // out_buf.len tells us how much data, but we didn't provide a buffer
                // so we don't copy anything
            }
            else
            {
                ADD_FAILURE() << "Unexpected error: " << err;
                break;
            }

            // Move to next chunk regardless of whether output was produced
            offset += current_chunk;
        }

        // Finish
        azihsm_buffer finish_out{ nullptr, 0 };
        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt_finish(ctx, &finish_out);
        }
        else
        {
            err = azihsm_crypt_decrypt_finish(ctx, &finish_out);
        }

        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            EXPECT_GT(finish_out.len, 0);
            size_t current_pos = output.size();
            output.resize(current_pos + finish_out.len);
            finish_out.ptr = output.data() + current_pos;

            if (operation == CryptOperation::Encrypt)
            {
                err = azihsm_crypt_encrypt_finish(ctx, &finish_out);
            }
            else
            {
                err = azihsm_crypt_decrypt_finish(ctx, &finish_out);
            }
            EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
            // Adjust output size to actual bytes written
            output.resize(current_pos + finish_out.len);
        }
        else
        {
            EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        }

        return output;
    }

    // Verifies single-shot encrypt/decrypt roundtrip and expected ciphertext length.
    void test_single_shot_roundtrip(
        azihsm_handle key_handle,
        azihsm_algo_id algo_id,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t expected_ciphertext_len
    )
    {
        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, algo_id, 0xCC);

        // Encrypt
        auto ciphertext = single_shot_crypt(
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len,
            CryptOperation::Encrypt
        );
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset IV for decryption
        init_cbc_algo(crypt_algo, cbc_params, algo_id, 0xCC);

        // Decrypt
        auto decrypted = single_shot_crypt(
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }

    // Verifies streaming encrypt/decrypt roundtrip and expected ciphertext length.
    void test_streaming_roundtrip(
        azihsm_handle key_handle,
        azihsm_algo_id algo_id,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t chunk_size,
        size_t expected_ciphertext_len
    )
    {
        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, algo_id, 0xAA);

        // Encrypt
        auto ciphertext = streaming_crypt(
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len,
            chunk_size,
            CryptOperation::Encrypt
        );
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset IV for decryption
        init_cbc_algo(crypt_algo, cbc_params, algo_id, 0xAA);

        // Decrypt
        auto decrypted = streaming_crypt(
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            chunk_size,
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }

    // Runs CBC KAT test cases in either single-shot or streaming mode.
    // Known Answer Test (KAT) cases have fixed plaintext, key, IV, and expected ciphertext values.
    // - chunk_sizes == nullptr: run single-shot encrypt/decrypt checks.
    // - chunk_sizes != nullptr: run streaming checks for each provided chunk size.
    void run_cbc_kat_cases(
        azihsm_algo_id algo_id,
        const std::vector<CbcKnownAnswerTestCase> &test_cases,
        const std::vector<size_t> *chunk_sizes
    )
    {
        part_list_.for_each_session([&](azihsm_handle session) {
            for (const auto &test_case : test_cases)
            {
                auto key =
                    import_local_aes_key_for_kat(
                        session,
                        test_case.key,
                        test_case.key_len,
                        test_case.bits
                    );
                ASSERT_NE(key.get(), 0);

                azihsm_algo_aes_cbc_params cbc_params{};
                std::memcpy(cbc_params.iv, test_case.iv, test_case.iv_len);

                azihsm_algo crypt_algo{};
                crypt_algo.id = algo_id;
                crypt_algo.params = &cbc_params;
                crypt_algo.len = sizeof(cbc_params);

                if (chunk_sizes == nullptr)
                {
                    // Single-shot path: validate exact ciphertext bytes and roundtrip plaintext.
                    SCOPED_TRACE(test_case.test_name);

                    auto ciphertext = single_shot_crypt(
                        key.get(),
                        &crypt_algo,
                        test_case.plaintext,
                        test_case.plaintext_len,
                        CryptOperation::Encrypt
                    );
                    ASSERT_EQ(ciphertext.size(), test_case.ciphertext_len);
                    ASSERT_EQ(
                        std::memcmp(
                            ciphertext.data(),
                            test_case.ciphertext,
                            test_case.ciphertext_len
                        ),
                        0
                    );

                    std::memcpy(cbc_params.iv, test_case.iv, test_case.iv_len);
                    auto plaintext = single_shot_crypt(
                        key.get(),
                        &crypt_algo,
                        test_case.ciphertext,
                        test_case.ciphertext_len,
                        CryptOperation::Decrypt
                    );
                    ASSERT_EQ(plaintext.size(), test_case.plaintext_len);
                    ASSERT_EQ(
                        std::memcmp(
                            plaintext.data(),
                            test_case.plaintext,
                            test_case.plaintext_len
                        ),
                        0
                    );
                    continue;
                }

                // Streaming path: repeat KAT per chunk size to exercise chunk boundary handling.
                for (auto chunk_size : *chunk_sizes)
                {
                    SCOPED_TRACE(
                        std::string(test_case.test_name) +
                        " chunk_size=" +
                        std::to_string(chunk_size)
                    );

                    // We need to reset IV because CBC updates IV in-place,
                    // but each run must start from the test case's original IV.
                    std::memcpy(cbc_params.iv, test_case.iv, test_case.iv_len);
                    auto ciphertext = streaming_crypt(
                        key.get(),
                        &crypt_algo,
                        test_case.plaintext,
                        test_case.plaintext_len,
                        chunk_size,
                        CryptOperation::Encrypt
                    );
                    ASSERT_EQ(ciphertext.size(), test_case.ciphertext_len);
                    ASSERT_EQ(
                        std::memcmp(
                            ciphertext.data(),
                            test_case.ciphertext,
                            test_case.ciphertext_len
                        ),
                        0
                    );

                    std::memcpy(cbc_params.iv, test_case.iv, test_case.iv_len);
                    auto plaintext = streaming_crypt(
                        key.get(),
                        &crypt_algo,
                        test_case.ciphertext,
                        test_case.ciphertext_len,
                        chunk_size,
                        CryptOperation::Decrypt
                    );
                    ASSERT_EQ(plaintext.size(), test_case.plaintext_len);
                    ASSERT_EQ(
                        std::memcmp(
                            plaintext.data(),
                            test_case.plaintext,
                            test_case.plaintext_len
                        ),
                        0
                    );
                }
            }
        });
    }
};

// Test data structures
struct AesKeyTestParams
{
    uint32_t bits;
    const char *test_name;
};

struct DataSizeTestParams
{
    size_t data_size;
    size_t expected_output_size_no_pad;
    size_t expected_output_size_with_pad;
    const char *test_name;
};

struct StreamingRoundtripCase
{
    size_t plaintext_len;
    size_t chunk_size;
    size_t expected_ciphertext_len;
    uint8_t plaintext_fill;
    const char *test_name;
};

static const std::vector<AesKeyTestParams> &aes_key_sizes()
{
    static const std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };
    return key_sizes;
}

// Returns plaintext lengths used by streaming padding size sweep tests.
static const std::vector<size_t> &padding_sweep_plaintext_sizes()
{
    static const std::vector<size_t> sizes = [] {
        std::vector<size_t> values;
        for (size_t value = 0; value <= 32; ++value)
        {
            values.push_back(value);
        }
        values.push_back(63);
        values.push_back(64);
        values.push_back(65);
        values.push_back(127);
        values.push_back(128);
        values.push_back(129);
        return values;
    }();

    return sizes;
}

// Returns chunk sizes used by streaming padding size sweep tests.
static const std::vector<size_t> &padding_sweep_chunk_sizes()
{
    static const std::vector<size_t> sizes = {
        1, 2, 3, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 256
    };

    return sizes;
}

// Runs single-shot roundtrip checks across all AES key sizes and input cases.
static void run_single_shot_key_size(
    PartitionListHandle &part_list,
    azihsm_algo_id algo_id,
    const std::vector<DataSizeTestParams> &data_sizes,
    uint8_t plaintext_fill,
    const std::function<void(azihsm_handle, azihsm_algo_id, const uint8_t *, size_t, size_t)> &
        roundtrip_runner
)
{
    for (const auto &key_param : aes_key_sizes())
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " " + data_param.test_name);

            part_list.for_each_session([&](azihsm_handle session) {
                auto key = generate_aes_key(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, plaintext_fill);
                size_t expected_ciphertext_len = (algo_id == AZIHSM_ALGO_ID_AES_CBC_PAD)
                    ? data_param.expected_output_size_with_pad
                    : data_param.expected_output_size_no_pad;

                roundtrip_runner(
                    key.get(),
                    algo_id,
                    plaintext.data(),
                    plaintext.size(),
                    expected_ciphertext_len
                );
            });
        }
    }
}

// Runs streaming roundtrip checks across all AES key sizes and input cases.
static void run_streaming_case_list(
    PartitionListHandle &part_list,
    azihsm_algo_id algo_id,
    const std::function<
        void(azihsm_handle, azihsm_algo_id, const uint8_t *, size_t, size_t, size_t)> &
        roundtrip_runner,
    const std::vector<StreamingRoundtripCase> &test_cases
)
{
    // Applies every streaming test case to each supported AES key size (128/192/256).
    for (const auto &key_param : aes_key_sizes())
    {
        for (const auto &test_case : test_cases)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " " + test_case.test_name);

            part_list.for_each_session([&](azihsm_handle session) {
                auto key = generate_aes_key(session, key_param.bits);

                std::vector<uint8_t> plaintext(test_case.plaintext_len, test_case.plaintext_fill);

                roundtrip_runner(
                    key.get(),
                    algo_id,
                    plaintext.data(),
                    plaintext.size(),
                    test_case.chunk_size,
                    test_case.expected_ciphertext_len
                );
            });
        }
    }
}

// ==================== Correctness and Known-Answer Coverage ====================

TEST_F(azihsm_aes_cbc, single_shot_no_padding_all_key_sizes)
{
    std::vector<DataSizeTestParams> data_sizes = {
        { 16, 16, 32, "1_block" },  // Exactly 1 block
        { 32, 32, 48, "2_blocks" }, // Exactly 2 blocks
        { 48, 48, 64, "3_blocks" }, // Exactly 3 blocks
        { 64, 64, 80, "4_blocks" }, // Exactly 4 blocks
    };

    run_single_shot_key_size(
        part_list_,
        AZIHSM_ALGO_ID_AES_CBC,
        data_sizes,
        0xAB,
        [&](azihsm_handle key, azihsm_algo_id algo, const uint8_t *input, size_t len, size_t expected) {
            test_single_shot_roundtrip(key, algo, input, len, expected);
        }
    );
}

TEST_F(azihsm_aes_cbc, single_shot_with_padding_all_key_sizes)
{
    std::vector<DataSizeTestParams> data_sizes = {
        { 1, 16, 16, "1_byte" },    // Much smaller than block
        { 13, 16, 16, "13_bytes" }, // Just under 1 block
        { 15, 16, 16, "15_bytes" }, // 1 byte short of block
        { 16, 16, 32, "16_bytes" }, // Exactly 1 block (needs full padding block)
        { 17, 32, 32, "17_bytes" }, // 1 byte over 1 block
        { 27, 32, 32, "27_bytes" }, // Between 1 and 2 blocks
        { 32, 32, 48, "32_bytes" }, // Exactly 2 blocks
        { 63, 64, 64, "63_bytes" }, // 1 byte short of 4 blocks
    };

    run_single_shot_key_size(
        part_list_,
        AZIHSM_ALGO_ID_AES_CBC_PAD,
        data_sizes,
        0xCD,
        [&](azihsm_handle key, azihsm_algo_id algo, const uint8_t *input, size_t len, size_t expected) {
            test_single_shot_roundtrip(key, algo, input, len, expected);
        }
    );
}

TEST_F(azihsm_aes_cbc, streaming_no_padding_cases)
{
    std::vector<StreamingRoundtripCase> test_cases = {
        { 32, 16, 32, 0xEF, "exact_blocks" },
        { 64, 16, 64, 0xEF, "multiple_blocks" },
        { 64, 32, 64, 0xEF, "larger_chunks" },
        { 48, 10, 48, 0xEF, "non_aligned_chunks" },
    };

    run_streaming_case_list(
        part_list_,
        AZIHSM_ALGO_ID_AES_CBC,
        [&](azihsm_handle key,
            azihsm_algo_id algo,
            const uint8_t *input,
            size_t len,
            size_t chunk_size,
            size_t expected_ciphertext_len) {
            test_streaming_roundtrip(key, algo, input, len, chunk_size, expected_ciphertext_len);
        },
        test_cases
    );
}

TEST_F(azihsm_aes_cbc, streaming_with_padding_cases)
{
    std::vector<StreamingRoundtripCase> test_cases = {
        { 13, 5, 16, 0x12, "small_data_small_chunks" },
        { 27, 10, 32, 0x12, "non_aligned_data_and_chunks" },
        { 31, 16, 32, 0x12, "almost_two_blocks" },
        { 50, 15, 64, 0x12, "odd_chunk_size" },
        { 100, 33, 112, 0x12, "larger_data_odd_chunks" },
    };

    run_streaming_case_list(
        part_list_,
        AZIHSM_ALGO_ID_AES_CBC_PAD,
        [&](azihsm_handle key,
            azihsm_algo_id algo,
            const uint8_t *input,
            size_t len,
            size_t chunk_size,
            size_t expected_ciphertext_len) {
            test_streaming_roundtrip(key, algo, input, len, chunk_size, expected_ciphertext_len);
        },
        test_cases
    );
}

// AES-CBC KAT (single-shot): verifies exact expected ciphertext and decrypt roundtrip
// against fixed test cases across key sizes.
TEST_F(azihsm_aes_cbc, single_shot_known_answer_cases)
{
    run_cbc_kat_cases(AZIHSM_ALGO_ID_AES_CBC, cbc_known_answer_test_cases(), nullptr);
}

// AES-CBC KAT (streaming): verifies fixed test cases across varied chunk sizes,
// ensuring chunk boundaries do not change ciphertext or decrypt behavior.
TEST_F(azihsm_aes_cbc, streaming_known_answer_cases)
{
    std::vector<size_t> chunk_sizes = { 1, 16, 17, 64 };
    run_cbc_kat_cases(AZIHSM_ALGO_ID_AES_CBC, cbc_known_answer_test_cases(), &chunk_sizes);
}

// CBC-PAD KAT (single-shot): verifies exact expected ciphertext and decrypt roundtrip
// for boundary-length plaintext test cases (e.g., 15-byte and 16-byte cases).
TEST_F(azihsm_aes_cbc, single_shot_padding_known_answer_cases)
{
    run_cbc_kat_cases(
        AZIHSM_ALGO_ID_AES_CBC_PAD,
        cbc_pad_boundary_known_answer_test_cases(),
        nullptr
    );
}

// CBC-PAD KAT (streaming): verifies the same boundary test cases across varied chunk sizes,
// ensuring chunking does not alter expected ciphertext or decrypt behavior.
TEST_F(azihsm_aes_cbc, streaming_padding_known_answer_cases)
{
    std::vector<size_t> chunk_sizes = { 1, 15, 16, 17 };
    run_cbc_kat_cases(
        AZIHSM_ALGO_ID_AES_CBC_PAD,
        cbc_pad_boundary_known_answer_test_cases(),
        &chunk_sizes
    );
}

TEST_F(azihsm_aes_cbc, empty_data_with_padding)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0xFF);

        // Encrypt empty data - should produce one block of padding
        uint8_t empty[1] = { 0 };
        azihsm_buffer input{ empty, 0 };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, 16u); // One block of padding

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Decrypt should return empty data
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0xFF);
        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> plaintext(plain_buf.len);
        plain_buf.ptr = plaintext.data();
        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(plain_buf.len, 0u);
    });
}

TEST_F(azihsm_aes_cbc, streaming_consistency_with_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0xFF);

        std::vector<uint8_t> plaintext(100, 0x55);

        // Single-shot encrypt
        auto single_shot_ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );

        // Reset IV for streaming
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0xFF);

        // Streaming encrypt
        auto streaming_ciphertext = streaming_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            17,
            CryptOperation::Encrypt
        );

        // Results should be identical
        ASSERT_EQ(single_shot_ciphertext.size(), streaming_ciphertext.size());
        ASSERT_EQ(
            std::memcmp(
                single_shot_ciphertext.data(),
                streaming_ciphertext.data(),
                single_shot_ciphertext.size()
            ),
            0
        );
    });
}

TEST_F(azihsm_aes_cbc, large_data_streaming)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x11);

        // Test with larger data (4KB)
        std::vector<uint8_t> plaintext = make_incrementing_bytes(4096);

        // Encrypt
        auto ciphertext = streaming_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            256,
            CryptOperation::Encrypt
        );

        // Reset IV for decryption
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x11);

        // Decrypt
        auto decrypted = streaming_crypt(
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            256,
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// Verifies single-shot CBC-PAD preserves content for larger payloads.
TEST_F(azihsm_aes_cbc, large_data_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x21);

        std::vector<uint8_t> plaintext = make_incrementing_bytes(4096);

        auto ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );
        ASSERT_EQ(ciphertext.size(), padded_ciphertext_len(plaintext.size()));

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x21);
        auto decrypted = single_shot_crypt(
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

TEST_F(azihsm_aes_cbc, different_ivs_produce_different_ciphertexts)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        uint8_t plaintext[16] = { 0x42 };

        // Encrypt with IV1
        uint8_t iv1[16] = { 0xAA };
        azihsm_algo_aes_cbc_params cbc_params1{};
        std::memcpy(cbc_params1.iv, iv1, sizeof(iv1));

        azihsm_algo crypt_algo1{};
        crypt_algo1.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo1.params = &cbc_params1;
        crypt_algo1.len = sizeof(cbc_params1);

        auto ciphertext1 = single_shot_crypt(
            key.get(),
            &crypt_algo1,
            plaintext,
            sizeof(plaintext),
            CryptOperation::Encrypt
        );

        // Encrypt with IV2
        uint8_t iv2[16] = { 0xBB };
        azihsm_algo_aes_cbc_params cbc_params2{};
        std::memcpy(cbc_params2.iv, iv2, sizeof(iv2));

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo2.params = &cbc_params2;
        crypt_algo2.len = sizeof(cbc_params2);

        auto ciphertext2 = single_shot_crypt(
            key.get(),
            &crypt_algo2,
            plaintext,
            sizeof(plaintext),
            CryptOperation::Encrypt
        );

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_padding_size_sweep)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        for (size_t plaintext_len = 0; plaintext_len <= 64; ++plaintext_len)
        {
            std::vector<uint8_t> plaintext(plaintext_len, 0x5A);

            azihsm_algo_aes_cbc_params cbc_params{};
            azihsm_algo crypt_algo{};
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x89);

            auto ciphertext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                plaintext.data(),
                plaintext.size(),
                CryptOperation::Encrypt
            );
            ASSERT_EQ(ciphertext.size(), padded_ciphertext_len(plaintext_len));

            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x89);
            auto decrypted = single_shot_crypt(
                key.get(),
                &crypt_algo,
                ciphertext.data(),
                ciphertext.size(),
                CryptOperation::Decrypt
            );
            ASSERT_EQ(decrypted.size(), plaintext.size());
            ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
        }
    });
}

TEST_F(azihsm_aes_cbc, streaming_padding_size_and_chunk_sweep)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        for (auto plaintext_len : padding_sweep_plaintext_sizes())
        {
            std::vector<uint8_t> plaintext = make_incrementing_bytes(plaintext_len);

            for (auto chunk_size : padding_sweep_chunk_sizes())
            {
                SCOPED_TRACE(
                    "plaintext_len=" + std::to_string(plaintext_len) +
                    " chunk_size=" + std::to_string(chunk_size)
                );

                test_streaming_roundtrip(
                    key.get(),
                    AZIHSM_ALGO_ID_AES_CBC_PAD,
                    plaintext.data(),
                    plaintext.size(),
                    chunk_size,
                    padded_ciphertext_len(plaintext_len)
                );
            }
        }
    });
}

// ==================== Argument Validation and API Behavior ====================

TEST_F(azihsm_aes_cbc, single_shot_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x12);

        uint8_t plaintext[AES_BLOCK_SIZE] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Encrypt, nullptr, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x23);

        uint8_t plaintext[AES_BLOCK_SIZE] = { 0xAB };
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer output{ nullptr, 0 };

        auto err =
            crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &bad_input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer bad_output{ nullptr, 1 };
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x34);

        uint8_t plaintext[AES_BLOCK_SIZE] = { 0xCC };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        crypt_algo.len = sizeof(cbc_params) - 1;
        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(cbc_params) + 1;
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_null_iv_is_rejected)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());
        auto key = generate_aes_key(session.get(), 128);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo.params = nullptr; // No IV provided
        crypt_algo.len = 0;

        uint8_t plaintext[16] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_invalid_key_handle_is_rejected)
{
    azihsm_algo_aes_cbc_params cbc_params{};
    azihsm_algo crypt_algo{};
    init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0xDD);

    uint8_t plaintext[16] = { 0xEE };
    azihsm_buffer input{ plaintext, sizeof(plaintext) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = azihsm_crypt_encrypt(&crypt_algo, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Validates streaming init rejects null mandatory pointers.
TEST_F(azihsm_aes_cbc, streaming_init_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x35);

        azihsm_handle ctx = 0;

        auto err = crypt_init_call(CryptOperation::Encrypt, nullptr, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_init_call(CryptOperation::Decrypt, nullptr, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates streaming init rejects malformed algorithm parameter layouts.
TEST_F(azihsm_aes_cbc, streaming_init_invalid_algo_params_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x36);

        azihsm_handle ctx = 0;

        crypt_algo.params = nullptr;
        crypt_algo.len = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x36);
        crypt_algo.params = nullptr;
        crypt_algo.len = 0;
        err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates streaming init rejects incorrect CBC parameter size values.
TEST_F(azihsm_aes_cbc, streaming_init_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x37);

        azihsm_handle ctx = 0;

        crypt_algo.len = sizeof(cbc_params) - 1;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(cbc_params) + 1;
        err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates streaming init rejects invalid key handles.
TEST_F(azihsm_aes_cbc, streaming_init_invalid_key_handle_is_rejected)
{
    azihsm_algo_aes_cbc_params cbc_params{};
    azihsm_algo crypt_algo{};
    init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x38);

    azihsm_handle ctx = 0;
    auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, 0xDEADBEEF, &ctx);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, 0xDEADBEEF, &ctx);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Validates streaming update/finish reject null buffers.
TEST_F(azihsm_aes_cbc, streaming_update_finish_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x39);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x44 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Encrypt, ctx, nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_finish_call(CryptOperation::Encrypt, ctx, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates update/finish reject malformed buffer shapes (null pointer with non-zero len).
TEST_F(azihsm_aes_cbc, streaming_update_finish_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x3A);

        azihsm_handle enc_ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &enc_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_handle dec_ctx = 0;
        err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &dec_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0x01;
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer bad_output{ nullptr, 1 };
        azihsm_buffer good_output{ &byte, 1 };
        azihsm_buffer good_input{ &byte, 1 };

        err = crypt_update_call(CryptOperation::Encrypt, enc_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Encrypt, enc_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Decrypt, dec_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Decrypt, dec_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_finish_call(CryptOperation::Encrypt, enc_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_finish_call(CryptOperation::Decrypt, dec_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates single-shot output-buffer sizing behavior for no-padding mode (query/exact/too-small).
TEST_F(azihsm_aes_cbc, single_shot_output_buffer_sizing_no_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x45);

        std::vector<uint8_t> plaintext(2 * AES_BLOCK_SIZE, 0x99);
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, plaintext.size());

        std::vector<uint8_t> exact_output(output.len);
        output.ptr = exact_output.data();
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, plaintext.size());

        std::vector<uint8_t> small_output(plaintext.size() - 1);
        azihsm_buffer too_small{ small_output.data(), static_cast<uint32_t>(small_output.size()) };
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &too_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(too_small.len, plaintext.size());
    });
}

// Validates single-shot output-buffer sizing behavior for padding mode across boundary lengths.
TEST_F(azihsm_aes_cbc, single_shot_output_buffer_sizing_with_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x46);

        std::vector<size_t> plaintext_lens = { 0, 15, 16, 17 };
        for (auto plaintext_len : plaintext_lens)
        {
            SCOPED_TRACE("plaintext_len=" + std::to_string(plaintext_len));

            std::vector<uint8_t> plaintext(plaintext_len, 0xA3);
            uint8_t dummy = 0;
            azihsm_buffer input{
                plaintext_len == 0 ? &dummy : plaintext.data(),
                static_cast<uint32_t>(plaintext_len)
            };
            azihsm_buffer output{ nullptr, 0 };

            auto expected_len = padded_ciphertext_len(plaintext_len);

            auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(output.len, expected_len);

            std::vector<uint8_t> exact_output(output.len);
            output.ptr = exact_output.data();
            err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(output.len, expected_len);

            std::vector<uint8_t> small_output(expected_len - 1);
            azihsm_buffer too_small{ small_output.data(), static_cast<uint32_t>(small_output.size()) };
            err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &too_small);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(too_small.len, expected_len);
        }
    });
}

// Validates update() output-buffer sizing behavior for no-padding mode (query/too-small/exact-size).
TEST_F(azihsm_aes_cbc, streaming_update_output_buffer_sizing_no_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x7B);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> block_a = make_incrementing_bytes(AES_BLOCK_SIZE);
        std::vector<uint8_t> block_b(AES_BLOCK_SIZE, 0xA7);
        azihsm_buffer input_a{ block_a.data(), static_cast<uint32_t>(block_a.size()) };
        azihsm_buffer input_b{ block_b.data(), static_cast<uint32_t>(block_b.size()) };
        azihsm_buffer output{ nullptr, 0 };

        // The output length is 0 because no-padding CBC keeps one trailing
        // full block until more input or finish() so update() can stay
        // consistent at block boundaries.
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input_a, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, 0u);

        // Feeding a different second block should not change the required output size for the first block.
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input_b, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> too_small(AES_BLOCK_SIZE - 1);
        azihsm_buffer short_output{ too_small.data(), static_cast<uint32_t>(too_small.size()) };
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input_b, &short_output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(short_output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> exact(AES_BLOCK_SIZE);
        azihsm_buffer exact_output{ exact.data(), static_cast<uint32_t>(exact.size()) };
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input_b, &exact_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(exact_output.len, AES_BLOCK_SIZE);

        azihsm_buffer finish_output{ nullptr, 0 };
        // The final deferred block is emitted at finish().
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(finish_output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> finish_exact(AES_BLOCK_SIZE);
        finish_output.ptr = finish_exact.data();
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(finish_output.len, AES_BLOCK_SIZE);

        // Streamed output should match single-shot ciphertext for A + B.
        std::vector<uint8_t> plaintext;
        plaintext.reserve(2 * AES_BLOCK_SIZE);
        plaintext.insert(plaintext.end(), block_a.begin(), block_a.end());
        plaintext.insert(plaintext.end(), block_b.begin(), block_b.end());

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x7B);
        auto single_shot_ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );
        ASSERT_EQ(single_shot_ciphertext.size(), 2 * AES_BLOCK_SIZE);

        ASSERT_EQ(
            std::memcmp(exact.data(), single_shot_ciphertext.data(), AES_BLOCK_SIZE),
            0
        );
        ASSERT_EQ(
            std::memcmp(
                finish_exact.data(),
                single_shot_ciphertext.data() + AES_BLOCK_SIZE,
                AES_BLOCK_SIZE
            ),
            0
        );
    });
}

// Validates finish() output-buffer sizing behavior for padding mode (query/too-small/exact-size).
TEST_F(azihsm_aes_cbc, streaming_finish_output_buffer_sizing_with_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x7C);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer finish_out{ nullptr, 0 };
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &finish_out);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(finish_out.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> too_small(AES_BLOCK_SIZE - 1);
        azihsm_buffer short_out{ too_small.data(), static_cast<uint32_t>(too_small.size()) };
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &short_out);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(short_out.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> exact(AES_BLOCK_SIZE);
        azihsm_buffer exact_out{ exact.data(), static_cast<uint32_t>(exact.size()) };
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &exact_out);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(exact_out.len, AES_BLOCK_SIZE);
    });
}

// ==================== Malformed Input and Padding Rejection ====================

TEST_F(azihsm_aes_cbc, encrypt_non_block_aligned_plaintext_no_padding_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0xBB);

        // Try to encrypt non-block-aligned data without padding
        uint8_t plaintext[13] = { 0xCC }; // Not a multiple of 16
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Ensures CBC decrypt rejects ciphertext lengths that are not multiples of the block size.
TEST_F(azihsm_aes_cbc, decrypt_non_block_aligned_ciphertext_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        std::vector<uint8_t> bad_ciphertext(17, 0xA5);
        azihsm_buffer input{ bad_ciphertext.data(), static_cast<uint32_t>(bad_ciphertext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x56);
        auto err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x56);
        err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Ensures CBC-PAD decrypt rejects tampered ciphertext with invalid PKCS#7 padding.
TEST_F(azihsm_aes_cbc, decrypt_invalid_padding_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x67);

        std::vector<uint8_t> plaintext(31, 0x44);
        auto ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );

        ciphertext.back() ^= 0xFF;

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x67);
        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err =
            single_shot_status_with_sizing(CryptOperation::Decrypt, &crypt_algo, key.get(), &input);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Sweeps PKCS#7 malformed cases (zero pad byte and inconsistent pad bytes) across pad lengths.
TEST_F(azihsm_aes_cbc, decrypt_invalid_padding_variants_fail)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        for (size_t pad_len = 1; pad_len <= AES_BLOCK_SIZE; ++pad_len)
        {
            // Build plaintext so PKCS#7 pad length in the finish block is exactly `pad_len`.
            const size_t plaintext_len = (2 * AES_BLOCK_SIZE) - pad_len;
            std::vector<uint8_t> plaintext(plaintext_len, 0x2A);

            azihsm_algo_aes_cbc_params cbc_params{};
            azihsm_algo crypt_algo{};
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x68);

            auto ciphertext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                plaintext.data(),
                plaintext.size(),
                CryptOperation::Encrypt
            );

            SCOPED_TRACE("pad_len=" + std::to_string(pad_len));

            auto assert_decrypt_fails = [&](std::vector<uint8_t> mutated) {
                // Reinitialize algo/IV so each mutation is evaluated from the same decrypt state.
                init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x68);
                azihsm_buffer input{ mutated.data(), static_cast<uint32_t>(mutated.size()) };
                auto err = single_shot_status_with_sizing(
                    CryptOperation::Decrypt,
                    &crypt_algo,
                    key.get(),
                    &input
                );

                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            };

            // We intentionally mutate the second to last (C[n-1]) block with deterministic flips here.
            // This change was made because direct last (C[n]) block tampering can produce
            // flaky test failures, where padding occasionally still appears valid.

            // Case 1: force pad length byte to 0 (always invalid in PKCS#7).
            auto zero_pad = ciphertext;
            zero_pad[zero_pad.size() - AES_BLOCK_SIZE - 1] ^= static_cast<uint8_t>(pad_len);
            assert_decrypt_fails(std::move(zero_pad));

            if (pad_len > 1)
            {
                // Case 2: break pad-byte consistency while keeping final pad length byte intact.
                auto inconsistent_pad = ciphertext;
                inconsistent_pad[inconsistent_pad.size() - AES_BLOCK_SIZE - 2] ^= 0x01;
                assert_decrypt_fails(std::move(inconsistent_pad));
            }
        }
    });
}

// Validates chunked CBC-PAD decrypt still rejects tampered padding regardless of chunk boundaries.
TEST_F(azihsm_aes_cbc, streaming_decrypt_invalid_padding_fails_across_chunk_sizes)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x69);

        std::vector<uint8_t> plaintext(31, 0x5B);
        auto ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );

        // Corrupt terminal padding byte so rejection can happen during update or finish.
        ciphertext.back() ^= 0xFF;

        std::vector<size_t> chunk_sizes = { 1, 7, 16, 31 };
        for (auto chunk_size : chunk_sizes)
        {
            SCOPED_TRACE("chunk_size=" + std::to_string(chunk_size));
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x69);

            azihsm_handle ctx = 0;
            auto err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &ctx);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            bool saw_failure = false;
            size_t offset = 0;
            while (offset < ciphertext.size())
            {
                // Feed mutated ciphertext in variable chunk boundaries to exercise stream parser paths.
                size_t current_chunk = std::min(chunk_size, ciphertext.size() - offset);
                azihsm_buffer input{
                    ciphertext.data() + offset,
                    static_cast<uint32_t>(current_chunk),
                };

                err =
                    streaming_update_status_with_sizing(CryptOperation::Decrypt, ctx, &input);

                if (err != AZIHSM_STATUS_SUCCESS)
                {
                    saw_failure = true;
                    break;
                }

                offset += current_chunk;
            }

            if (!saw_failure)
            {
                // If update accepted all chunks, finish must still reject invalid PKCS#7 state.
                err = streaming_finish_status_with_sizing(CryptOperation::Decrypt, ctx);

                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            }
        }
    });
}

// Verifies streaming no-padding rejects partial finish blocks for both encrypt and decrypt flows.
TEST_F(azihsm_aes_cbc, streaming_no_padding_partial_block_input_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        auto run_expect_failure = [&](CryptOperation operation, std::vector<uint8_t> input_bytes) {
            azihsm_algo_aes_cbc_params cbc_params{};
            azihsm_algo crypt_algo{};
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x22);

            azihsm_handle ctx = 0;
            auto err = crypt_init_call(operation, &crypt_algo, key.get(), &ctx);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_buffer input{ input_bytes.data(), static_cast<uint32_t>(input_bytes.size()) };

            bool saw_failure = false;
            err = streaming_update_status_with_sizing(operation, ctx, &input);

            if (err != AZIHSM_STATUS_SUCCESS)
            {
                saw_failure = true;
            }

            if (!saw_failure)
            {
                err = streaming_finish_status_with_sizing(operation, ctx);
                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            }
        };

        std::vector<uint8_t> bad_plaintext(17, 0xA1);
        run_expect_failure(CryptOperation::Encrypt, std::move(bad_plaintext));

        std::vector<uint8_t> bad_ciphertext(17, 0xA2);
        run_expect_failure(CryptOperation::Decrypt, std::move(bad_ciphertext));
    });
}

// ==================== Streaming Lifecycle and Context Rules ====================

// Verifies zero-length update is a no-op for CBC-PAD and output is emitted only at finish.
TEST_F(azihsm_aes_cbc, streaming_zero_length_update_with_padding_noop_until_finish)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x6A);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t dummy = 0x00;
        azihsm_buffer empty_input{ &dummy, 0 };
        azihsm_buffer update_out{ nullptr, 0 };
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &empty_input, &update_out);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(update_out.len, 0u);

        azihsm_buffer finish_out{ nullptr, 0 };
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &finish_out);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(finish_out.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> finish_buf(finish_out.len);
        finish_out.ptr = finish_buf.data();
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &finish_out);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(finish_out.len, AES_BLOCK_SIZE);
    });
}

// Ensures streaming APIs consistently reject obviously invalid context handles.
TEST_F(azihsm_aes_cbc, streaming_invalid_context_handles_are_rejected)
{
    uint8_t data[AES_BLOCK_SIZE] = { 0x11 };
    azihsm_buffer input{ data, sizeof(data) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = crypt_update_call(CryptOperation::Encrypt, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_update_call(CryptOperation::Decrypt, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_finish_call(CryptOperation::Encrypt, 0xDEADBEEF, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_finish_call(CryptOperation::Decrypt, 0xDEADBEEF, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Verifies context state is terminal after finish, so further update/finish calls fail.
TEST_F(azihsm_aes_cbc, streaming_use_after_finish_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x78);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = streaming_finish_status_with_sizing(CryptOperation::Encrypt, ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x33 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer after_finish_output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, &after_finish_output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &after_finish_output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Verifies an encrypt-initialized context cannot be used through decrypt update/finish APIs.
TEST_F(azihsm_aes_cbc, streaming_operation_mismatch_on_context_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x79);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x41 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Decrypt, ctx, &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = crypt_finish_call(CryptOperation::Decrypt, ctx, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = streaming_finish_status_with_sizing(CryptOperation::Encrypt, ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Checks PKCS#7 behavior in streaming mode: finish without update emits one full padding block.
TEST_F(azihsm_aes_cbc, streaming_encrypt_finish_without_update_with_padding_outputs_block)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x7A);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer output{ nullptr, 0 };
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> out_buf(output.len);
        output.ptr = out_buf.data();
        err = crypt_finish_call(CryptOperation::Encrypt, ctx, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);
    });
}

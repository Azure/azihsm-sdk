// Copyright (C) Microsoft Corporation. All rights reserved.

use super::cbc_tests_helper::CbcTestVectorFailure;
use super::cbc_tests_helper::assert_cbc_vector_success;
use super::cbc_tests_helper::test_single_shot_decrypt;
use super::cbc_tests_helper::test_single_shot_encrypt;
use super::cbc_tests_helper::test_streaming_decrypt;
use super::cbc_tests_helper::test_streaming_encrypt;
use super::*;
use crate::aes::tests::testvectors::AES_CBC_128_VAR_TXT_TEST_VECTORS;
use crate::aes::tests::testvectors::AES_CBC_192_VAR_TXT_TEST_VECTORS;
use crate::aes::tests::testvectors::AES_CBC_256_VAR_TXT_TEST_VECTORS;

const STREAMING_CHUNK_LENS: [usize; 6] = [1, 3, 7, 12, 2, 19];

fn check_var_txt_vector_one_shot(vector: &AesCbcTestVector) -> Result<(), CbcTestVectorFailure> {
    let (input, expected) = if vector.encrypt {
        (vector.plaintext, vector.ciphertext)
    } else {
        (vector.ciphertext, vector.plaintext)
    };

    let output = if vector.encrypt {
        test_single_shot_encrypt(vector.key, vector.iv, input)
    } else {
        test_single_shot_decrypt(vector.key, vector.iv, input)
    }
    .map_err(|e| CbcTestVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: vector.encrypt,
        source: e,
    })?;

    if output.as_slice() != expected {
        return Err(CbcTestVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: vector.encrypt,
            key: vector.key,
            iv: vector.iv,
            input,
            expected,
            actual: output,
        });
    }

    Ok(())
}

fn check_var_txt_vector_streaming(vector: &AesCbcTestVector) -> Result<(), CbcTestVectorFailure> {
    let (input, expected) = if vector.encrypt {
        (vector.plaintext, vector.ciphertext)
    } else {
        (vector.ciphertext, vector.plaintext)
    };

    let output = if vector.encrypt {
        test_streaming_encrypt(vector.key, vector.iv, input, &STREAMING_CHUNK_LENS)
    } else {
        test_streaming_decrypt(vector.key, vector.iv, input, &STREAMING_CHUNK_LENS)
    }
    .map_err(|e| CbcTestVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: vector.encrypt,
        source: e,
    })?;

    if output.as_slice() != expected {
        return Err(CbcTestVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: vector.encrypt,
            key: vector.key,
            iv: vector.iv,
            input,
            expected,
            actual: output,
        });
    }

    Ok(())
}

// Variable Text tests
#[test]
fn test_aes_128_nist_var_txt_vectors() {
    for vector in AES_CBC_128_VAR_TXT_TEST_VECTORS.iter() {
        assert_cbc_vector_success(
            "AES-128 CBC NIST VarTxt (one-shot)",
            "AES-128 CBC VarTxt (one-shot) mismatch!",
            check_var_txt_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_192_nist_var_txt_vectors() {
    for vector in AES_CBC_192_VAR_TXT_TEST_VECTORS.iter() {
        assert_cbc_vector_success(
            "AES-192 CBC NIST VarTxt (one-shot)",
            "AES-192 CBC VarTxt (one-shot) mismatch!",
            check_var_txt_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_256_nist_var_txt_vectors() {
    for vector in AES_CBC_256_VAR_TXT_TEST_VECTORS.iter() {
        assert_cbc_vector_success(
            "AES-256 CBC NIST VarTxt (one-shot)",
            "AES-256 CBC VarTxt (one-shot) mismatch!",
            check_var_txt_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_128_nist_var_txt_vectors_streaming() {
    for vector in AES_CBC_128_VAR_TXT_TEST_VECTORS.iter() {
        assert_cbc_vector_success(
            "AES-128 CBC NIST VarTxt (streaming)",
            "AES-128 CBC NIST VarTxt (streaming) mismatch!",
            check_var_txt_vector_streaming(vector),
        );
    }
}

#[test]
fn test_aes_192_nist_var_txt_vectors_streaming() {
    for vector in AES_CBC_192_VAR_TXT_TEST_VECTORS.iter() {
        assert_cbc_vector_success(
            "AES-192 CBC NIST VarTxt (streaming)",
            "AES-192 CBC NIST VarTxt (streaming) mismatch!",
            check_var_txt_vector_streaming(vector),
        );
    }
}

#[test]
fn test_aes_256_nist_var_txt_vectors_streaming() {
    for vector in AES_CBC_256_VAR_TXT_TEST_VECTORS.iter() {
        assert_cbc_vector_success(
            "AES-256 CBC NIST VarTxt (streaming)",
            "AES-256 CBC NIST VarTxt (streaming) mismatch!",
            check_var_txt_vector_streaming(vector),
        );
    }
}

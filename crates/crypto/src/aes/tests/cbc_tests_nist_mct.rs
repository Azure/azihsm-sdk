// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::aes::tests::testvectors::AES_CBC_128_MCT_TEST_VECTORS;
use crate::aes::tests::testvectors::AES_CBC_192_MCT_TEST_VECTORS;
use crate::aes::tests::testvectors::AES_CBC_256_MCT_TEST_VECTORS;

// Monte Carlo test sample vectors (MCT)
//
// Reference pseudocode (single-block CBC Monte Carlo):
// For j = 0..999
//   CT[j] = AES(Key[i], IV, PT[j])  (CBC: CT = AES_K(PT xor IV), IV <- CT)
//   PT[j+1] = (j == 0 ? IV[i] : CT[j-1])
// Output is CT[999].

#[derive(Debug)]
enum MctVectorFailure {
    Crypto {
        id: u32,
        encrypt: bool,
        source: CryptoError,
    },
    Mismatch {
        id: u32,
        encrypt: bool,
        key: &'static [u8],
        iv: &'static [u8],
        seed: &'static [u8],
        expected: &'static [u8],
        actual: Vec<u8>,
    },
}

fn check_nist_mct_vector_one_shot_encrypt(
    vector: &AesCbcTestVector,
) -> Result<(), MctVectorFailure> {
    let key = AesKey::from_bytes(vector.key).map_err(|e| MctVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: true,
        source: e,
    })?;

    let seed = vector.plaintext;
    let expected = vector.ciphertext;

    // CBC Encrypt Monte Carlo loop (single-block), per the below pseudocode:
    // For j = 0..999
    //   CT[j] = AES(Key[i], IV, PT[j])  (CBC: CT = AES_K(PT xor IV), IV <- CT)
    //   PT[j+1] = (j == 0 ? IV[i] : CT[j-1])
    // Output is CT[999].
    let initial_iv = vector.iv.to_vec();
    let mut chaining_iv = initial_iv.clone();

    let mut input_block = seed.to_vec();

    // Determine required output *capacity* once.
    // Some backends (e.g., OpenSSL EVP) require `input_len + block_size` capacity
    let iv_for_size = chaining_iv.clone();
    let required_len = {
        let mut algo = AesCbcAlgo::with_no_padding(&iv_for_size);
        Encrypter::encrypt(&mut algo, &key, &input_block, None)
    }
    .map_err(|e| MctVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: true,
        source: e,
    })?;

    let expected_out_len = vector.iv.len();
    let mut previous_output = vec![0u8; expected_out_len];
    let mut current_output = vec![0u8; expected_out_len];
    let mut scratch = vec![0u8; required_len];

    for j in 0..1000 {
        let mut algo = AesCbcAlgo::with_no_padding(&chaining_iv);
        let out_len =
            { Encrypter::encrypt(&mut algo, &key, &input_block, Some(scratch.as_mut_slice())) }
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: true,
                    source: e,
                })?;
        assert_eq!(out_len, expected_out_len);
        current_output.copy_from_slice(&scratch[..out_len]);

        // CBC-MCT chaining (single block), per the provided pseudocode:
        // Next input is IV[i] for j=0, else previous iteration's output.
        if j == 0 {
            input_block.copy_from_slice(&initial_iv);
        } else {
            input_block.copy_from_slice(&previous_output);
        }

        // Shift output history.
        previous_output.copy_from_slice(&current_output);

        chaining_iv.copy_from_slice(algo.iv());
    }

    if expected != current_output.as_slice() {
        return Err(MctVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: true,
            key: vector.key,
            iv: vector.iv,
            seed,
            expected,
            actual: current_output,
        });
    }

    Ok(())
}

fn check_nist_mct_vector_one_shot_decrypt(
    vector: &AesCbcTestVector,
) -> Result<(), MctVectorFailure> {
    let key = AesKey::from_bytes(vector.key).map_err(|e| MctVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: false,
        source: e,
    })?;

    let seed = vector.ciphertext;
    let expected = vector.plaintext;

    // CBC Encrypt Monte Carlo loop (single-block), per the below pseudocode:
    // For j = 0..999
    //   CT[j] = AES(Key[i], IV, PT[j])  (CBC: CT = AES_K(PT xor IV), IV <- CT)
    //   PT[j+1] = (j == 0 ? IV[i] : CT[j-1])
    // Output is CT[999].
    let initial_iv = vector.iv.to_vec();
    let mut chaining_iv = initial_iv.clone();

    let mut input_block = seed.to_vec();

    // Determine required output *capacity* once.
    // Some backends (e.g., OpenSSL EVP) require `input_len + block_size` capacity
    let iv_for_size = chaining_iv.clone();
    let required_len = {
        let mut algo = AesCbcAlgo::with_no_padding(&iv_for_size);
        Decrypter::decrypt(&mut algo, &key, &input_block, None)
    }
    .map_err(|e| MctVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: false,
        source: e,
    })?;

    let expected_out_len = vector.iv.len();
    let mut previous_output = vec![0u8; expected_out_len];
    let mut current_output = vec![0u8; expected_out_len];
    let mut scratch = vec![0u8; required_len];

    for j in 0..1000 {
        let mut algo = AesCbcAlgo::with_no_padding(&chaining_iv);
        let out_len =
            { Decrypter::decrypt(&mut algo, &key, &input_block, Some(scratch.as_mut_slice())) }
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: false,
                    source: e,
                })?;
        assert_eq!(out_len, expected_out_len);
        current_output.copy_from_slice(&scratch[..out_len]);

        // CBC-MCT chaining (single block), per the provided pseudocode:
        // Next input is IV[i] for j=0, else previous iteration's output.
        if j == 0 {
            input_block.copy_from_slice(&initial_iv);
        } else {
            input_block.copy_from_slice(&previous_output);
        }

        // Shift output history.
        previous_output.copy_from_slice(&current_output);

        chaining_iv.copy_from_slice(algo.iv());
    }

    if expected != current_output.as_slice() {
        return Err(MctVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: false,
            key: vector.key,
            iv: vector.iv,
            seed,
            expected,
            actual: current_output,
        });
    }

    Ok(())
}

fn check_nist_mct_vector_streaming_encrypt(
    vector: &AesCbcTestVector,
) -> Result<(), MctVectorFailure> {
    let seed = vector.plaintext;
    let expected = vector.ciphertext;

    let initial_iv = vector.iv.to_vec();
    let mut chaining_iv = initial_iv.clone();

    let mut input_block = seed.to_vec();

    let expected_out_len = vector.iv.len();
    let mut previous_output = vec![0u8; expected_out_len];
    let mut current_output = vec![0u8; expected_out_len];
    let mut scratch = vec![0u8; input_block.len() + 16];

    for j in 0..1000 {
        let key = AesKey::from_bytes(vector.key).map_err(|e| MctVectorFailure::Crypto {
            id: vector.test_count_id,
            encrypt: true,
            source: e,
        })?;
        let algo = AesCbcAlgo::with_no_padding(&chaining_iv);
        let mut context =
            Encrypter::encrypt_init(algo, key).map_err(|e| MctVectorFailure::Crypto {
                id: vector.test_count_id,
                encrypt: true,
                source: e,
            })?;

        let mut offset = 0usize;

        // Feed input through multiple updates (not block-aligned) to exercise
        // the streaming buffering/chaining behavior.
        let mut cursor = 0usize;
        for chunk_len in [1usize, 3, 2, 5] {
            if cursor >= input_block.len() {
                break;
            }
            let end = (cursor + chunk_len).min(input_block.len());
            offset += context
                .update(&input_block[cursor..end], Some(&mut scratch[offset..]))
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: true,
                    source: e,
                })?;
            cursor = end;
        }
        if cursor < input_block.len() {
            offset += context
                .update(&input_block[cursor..], Some(&mut scratch[offset..]))
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: true,
                    source: e,
                })?;
        }
        offset +=
            context
                .finish(Some(&mut scratch[offset..]))
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: true,
                    source: e,
                })?;
        assert_eq!(offset, expected_out_len);
        current_output.copy_from_slice(&scratch[..offset]);

        // CBC-MCT chaining (single block), per the provided pseudocode:
        // Next input is IV[i] for j=0, else previous iteration's output.
        if j == 0 {
            input_block.copy_from_slice(&initial_iv);
        } else {
            input_block.copy_from_slice(&previous_output);
        }

        // Shift output history.
        previous_output.copy_from_slice(&current_output);
        // chaining_iv is mutated by init/update/final via the API.

        let algo = context.into_algo();
        chaining_iv.copy_from_slice(algo.iv());
    }

    if expected != current_output.as_slice() {
        return Err(MctVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: true,
            key: vector.key,
            iv: vector.iv,
            seed,
            expected,
            actual: current_output,
        });
    }

    Ok(())
}

fn check_nist_mct_vector_streaming_decrypt(
    vector: &AesCbcTestVector,
) -> Result<(), MctVectorFailure> {
    let seed = vector.ciphertext;
    let expected = vector.plaintext;

    let initial_iv = vector.iv.to_vec();
    let mut chaining_iv = initial_iv.clone();

    let mut input_block = seed.to_vec();

    let expected_out_len = vector.iv.len();
    let mut previous_output = vec![0u8; expected_out_len];
    let mut current_output = vec![0u8; expected_out_len];
    let mut scratch = vec![0u8; input_block.len() + 16];

    for j in 0..1000 {
        let key = AesKey::from_bytes(vector.key).map_err(|e| MctVectorFailure::Crypto {
            id: vector.test_count_id,
            encrypt: true,
            source: e,
        })?;
        let algo = AesCbcAlgo::with_no_padding(&chaining_iv);
        let mut context =
            Decrypter::decrypt_init(algo, key).map_err(|e| MctVectorFailure::Crypto {
                id: vector.test_count_id,
                encrypt: false,
                source: e,
            })?;

        let mut offset = 0usize;

        // Feed input through multiple updates (not block-aligned) to exercise
        // the streaming buffering/chaining behavior.
        let mut cursor = 0usize;
        for chunk_len in [1usize, 3, 2, 5] {
            if cursor >= input_block.len() {
                break;
            }
            let end = (cursor + chunk_len).min(input_block.len());
            offset += context
                .update(&input_block[cursor..end], Some(&mut scratch[offset..]))
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: false,
                    source: e,
                })?;
            cursor = end;
        }
        if cursor < input_block.len() {
            offset += context
                .update(&input_block[cursor..], Some(&mut scratch[offset..]))
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: false,
                    source: e,
                })?;
        }
        offset +=
            context
                .finish(Some(&mut scratch[offset..]))
                .map_err(|e| MctVectorFailure::Crypto {
                    id: vector.test_count_id,
                    encrypt: false,
                    source: e,
                })?;
        assert_eq!(offset, expected_out_len);
        current_output.copy_from_slice(&scratch[..offset]);

        // CBC-MCT chaining (single block), per the provided pseudocode:
        // Next input is IV[i] for j=0, else previous iteration's output.
        if j == 0 {
            input_block.copy_from_slice(&initial_iv);
        } else {
            input_block.copy_from_slice(&previous_output);
        }

        // Shift output history.
        previous_output.copy_from_slice(&current_output);

        // chaining_iv is mutated by init/update/final via the API.
        let algo = context.into_algo();
        chaining_iv.copy_from_slice(algo.iv());
    }

    if expected != current_output.as_slice() {
        return Err(MctVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: false,
            key: vector.key,
            iv: vector.iv,
            seed,
            expected,
            actual: current_output,
        });
    }

    Ok(())
}

#[test]
fn test_aes_128_nist_mct_vectors() {
    for vector in AES_CBC_128_MCT_TEST_VECTORS.iter() {
        let result = if vector.encrypt {
            check_nist_mct_vector_one_shot_encrypt(vector)
        } else {
            check_nist_mct_vector_one_shot_decrypt(vector)
        };

        result.unwrap_or_else(|failure| match failure {
            MctVectorFailure::Crypto { id, encrypt, source } => {
                panic!(
                    "AES-128 CBC NIST MCT (one-shot) failed: id={} encrypt={} err={:?}",
                    id, encrypt, source
                );
            }
            MctVectorFailure::Mismatch {
                id,
                encrypt,
                key,
                iv,
                seed,
                expected,
                actual,
            } => {
                panic!(
                    "AES-128 CBC NIST MCT (one-shot) mismatch!\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nSeed: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
                    id, encrypt, key, iv, seed, expected, actual
                );
            }
        });
    }
}
#[test]
fn test_aes_128_nist_mct_vectors_streaming() {
    for vector in AES_CBC_128_MCT_TEST_VECTORS.iter() {
        let result = if vector.encrypt {
            check_nist_mct_vector_streaming_encrypt(vector)
        } else {
            check_nist_mct_vector_streaming_decrypt(vector)
        };

        result.unwrap_or_else(|failure| match failure {
            MctVectorFailure::Crypto { id, encrypt, source } => {
                panic!(
                    "AES-128 CBC NIST MCT (streaming) failed: id={} encrypt={} err={:?}",
                    id, encrypt, source
                );
            }
            MctVectorFailure::Mismatch {
                id,
                encrypt,
                key,
                iv,
                seed,
                expected,
                actual,
            } => {
                panic!(
                    "AES-128 CBC NIST MCT (streaming) mismatch!\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nSeed: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
                    id, encrypt, key, iv, seed, expected, actual
                );
            }
        });
    }
}
#[test]
fn test_aes_192_nist_mct_vectors() {
    for vector in AES_CBC_192_MCT_TEST_VECTORS.iter() {
        let result = if vector.encrypt {
            check_nist_mct_vector_one_shot_encrypt(vector)
        } else {
            check_nist_mct_vector_one_shot_decrypt(vector)
        };

        result.unwrap_or_else(|failure| match failure {
            MctVectorFailure::Crypto { id, encrypt, source } => {
                panic!(
                    "AES-192 CBC NIST MCT (one-shot) failed: id={} encrypt={} err={:?}",
                    id, encrypt, source
                );
            }
            MctVectorFailure::Mismatch {
                id,
                encrypt,
                key,
                iv,
                seed,
                expected,
                actual,
            } => {
                panic!(
                    "AES-192 CBC NIST MCT (one-shot) mismatch!\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nSeed: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
                    id, encrypt, key, iv, seed, expected, actual
                );
            }
        });
    }
}
#[test]
fn test_aes_192_nist_mct_vectors_streaming() {
    for vector in AES_CBC_192_MCT_TEST_VECTORS.iter() {
        let result = if vector.encrypt {
            check_nist_mct_vector_streaming_encrypt(vector)
        } else {
            check_nist_mct_vector_streaming_decrypt(vector)
        };

        result.unwrap_or_else(|failure| match failure {
            MctVectorFailure::Crypto { id, encrypt, source } => {
                panic!(
                    "AES-192 CBC NIST MCT (streaming) failed: id={} encrypt={} err={:?}",
                    id, encrypt, source
                );
            }
            MctVectorFailure::Mismatch {
                id,
                encrypt,
                key,
                iv,
                seed,
                expected,
                actual,
            } => {
                panic!(
                    "AES-192 CBC NIST MCT (streaming) mismatch!\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nSeed: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
                    id, encrypt, key, iv, seed, expected, actual
                );
            }
        });
    }
}
#[test]
fn test_aes_256_nist_mct_vectors() {
    for vector in AES_CBC_256_MCT_TEST_VECTORS.iter() {
        let result = if vector.encrypt {
            check_nist_mct_vector_one_shot_encrypt(vector)
        } else {
            check_nist_mct_vector_one_shot_decrypt(vector)
        };

        result.unwrap_or_else(|failure| match failure {
            MctVectorFailure::Crypto { id, encrypt, source } => {
                panic!(
                    "AES-256 CBC NIST MCT (one-shot) failed: id={} encrypt={} err={:?}",
                    id, encrypt, source
                );
            }
            MctVectorFailure::Mismatch {
                id,
                encrypt,
                key,
                iv,
                seed,
                expected,
                actual,
            } => {
                panic!(
                    "AES-256 CBC NIST MCT (one-shot) mismatch!\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nSeed: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
                    id, encrypt, key, iv, seed, expected, actual
                );
            }
        });
    }
}
#[test]
fn test_aes_256_nist_mct_vectors_streaming() {
    for vector in AES_CBC_256_MCT_TEST_VECTORS.iter() {
        let result = if vector.encrypt {
            check_nist_mct_vector_streaming_encrypt(vector)
        } else {
            check_nist_mct_vector_streaming_decrypt(vector)
        };

        result.unwrap_or_else(|failure| match failure {
            MctVectorFailure::Crypto { id, encrypt, source } => {
                panic!(
                    "AES-256 CBC NIST MCT (streaming) failed: id={} encrypt={} err={:?}",
                    id, encrypt, source
                );
            }
            MctVectorFailure::Mismatch {
                id,
                encrypt,
                key,
                iv,
                seed,
                expected,
                actual,
            } => {
                panic!(
                    "AES-256 CBC NIST MCT (streaming) mismatch!\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nSeed: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
                    id, encrypt, key, iv, seed, expected, actual
                );
            }
        });
    }
}

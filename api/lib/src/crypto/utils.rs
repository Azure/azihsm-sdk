// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use super::AzihsmError;

pub mod rsa_pkcs_pss_utils {
    use azihsm_crypto::*;

    use super::*;
    use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
    use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
    use crate::AZIHSM_RSA_VERIFY_INTERNAL_ERROR;

    /// Mask Generation Function 1 (MGF1) as defined in PKCS #1 v2.2
    pub fn mgf1(
        seed: &[u8],
        length: usize,
        hash_algo: &mut HashAlgo,
        mask: &mut [u8],
    ) -> Result<(), AzihsmError> {
        let h_len = hash_algo.size();

        if length > (1 << 32) * h_len {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        // Ensure output buffer is large enough
        if mask.len() < length {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Generate mask using MGF1 algorithm
        let mut counter: u32 = 0;
        let mut bytes_written = 0;

        while bytes_written < length {
            // Convert counter to 4-byte big-endian representation
            let c = counter.to_be_bytes();

            // Concatenate seed and counter: d = seed || C
            let mut d = Vec::with_capacity(seed.len() + 4);
            d.extend_from_slice(seed);
            d.extend_from_slice(&c);

            // Hash the concatenated data
            let mut hash_output = vec![0u8; h_len];
            Hasher::hash(hash_algo, &d, Some(&mut hash_output))
                .map_err(|_| AZIHSM_RSA_VERIFY_INTERNAL_ERROR)?;

            // Copy hash output to mask, taking care not to exceed length
            let bytes_to_copy = std::cmp::min(h_len, length - bytes_written);
            mask[bytes_written..bytes_written + bytes_to_copy]
                .copy_from_slice(&hash_output[..bytes_to_copy]);

            bytes_written += bytes_to_copy;
            counter += 1;
        }

        Ok(())
    }

    /// XOR two byte slices of equal length
    pub fn xor_slices(a: &mut [u8], b: &[u8]) {
        assert_eq!(a.len(), b.len(), "Slices must have equal length for XOR");
        for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
            *a_byte ^= *b_byte;
        }
    }

    /// Zero the leftmost n_bits in the first byte of the slice
    pub fn zero_leftmost_x_bits(data: &mut [u8], n_bits: usize) {
        if n_bits == 0 || data.is_empty() {
            return;
        }

        if n_bits >= 8 {
            // If we need to zero 8 or more bits, zero entire bytes
            let bytes_to_zero = n_bits / 8;
            let remaining_bits = n_bits % 8;

            // Zero complete bytes
            for i in 0..std::cmp::min(bytes_to_zero, data.len()) {
                data[i] = 0;
            }

            // Zero remaining bits in the next byte if any
            if remaining_bits > 0 && bytes_to_zero < data.len() {
                let mask = 0xFF >> remaining_bits;
                data[bytes_to_zero] &= mask;
            }
        } else {
            // Zero only the leftmost n_bits of the first byte
            let mask = 0xFF >> n_bits;
            data[0] &= mask;
        }
    }
}

/// PKCS#7 padding utilities - works with any block cipher
pub mod pkcs7 {
    use super::*;

    /// Apply PKCS#7 padding to input data
    ///
    /// # Arguments
    /// * `input` - The data to pad
    /// * `output` - Vector to store padded data
    /// * `block_size` - Block size in bytes (8 for DES/3DES, 16 for AES, etc.)
    ///
    pub fn apply(input: &[u8], output: &mut Vec<u8>, block_size: usize) {
        output.extend_from_slice(input);
        let padding_len = block_size - (input.len() % block_size);
        for _ in 0..padding_len {
            output.push(padding_len as u8);
        }
    }

    /// Remove PKCS#7 padding from decrypted data
    ///
    /// # Arguments  
    /// * `data` - Padded data to unpad (modified in place)
    /// * `block_size` - Block size in bytes
    /// * `error_code` - Error to return on invalid padding
    ///
    /// # Returns
    /// * `Ok(())` - Padding removed successfully
    /// * `Err(error_code)` - Invalid padding detected
    ///
    pub fn remove(
        data: &mut Vec<u8>,
        block_size: usize,
        error_code: AzihsmError,
    ) -> Result<(), AzihsmError> {
        if data.is_empty() {
            Err(error_code)?;
        }

        let padding_len = *data.last().unwrap() as usize;

        // Validate padding length
        if padding_len == 0 || padding_len > block_size || padding_len > data.len() {
            Err(error_code)?;
        }

        // Validate padding bytes
        let start_idx = data.len() - padding_len;
        for &byte in &data[start_idx..] {
            if byte != padding_len as u8 {
                Err(error_code)?;
            }
        }

        // Remove padding
        data.truncate(start_idx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AZIHSM_AES_DECRYPT_FAILED;

    #[test]
    fn test_pkcs7_padding_application() {
        let test_cases = vec![
            // (input, block_size, expected_output)
            (
                b"A".as_slice(),
                8,
                vec![0x41, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07],
            ),
            (
                b"HELLO".as_slice(),
                8,
                vec![0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x03, 0x03, 0x03],
            ),
            (
                b"1234567".as_slice(),
                8,
                vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x01],
            ),
            (
                b"12345678".as_slice(),
                8,
                vec![
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x08, 0x08, 0x08, 0x08, 0x08,
                    0x08, 0x08, 0x08,
                ],
            ),
            // AES block size (16 bytes)
            (
                b"A".as_slice(),
                16,
                vec![
                    0x41, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
                    0x0F, 0x0F, 0x0F,
                ],
            ),
            (
                b"HELLO WORLD12345".as_slice(),
                16,
                vec![
                    0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x20, 0x57, 0x4F, 0x52, 0x4C, 0x44, 0x31, 0x32,
                    0x33, 0x34, 0x35, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                    0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                ],
            ),
        ];

        for (i, (input, block_size, expected)) in test_cases.into_iter().enumerate() {
            let mut output = Vec::new();
            pkcs7::apply(input, &mut output, block_size);
            assert_eq!(
                output, expected,
                "Test case {}: Padding application failed",
                i
            );
        }
    }

    #[test]
    fn test_pkcs7_padding_removal() {
        let test_cases = vec![
            // (padded_input, block_size, expected_output)
            (
                vec![0x41, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07],
                8,
                vec![0x41],
            ),
            (
                vec![0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x03, 0x03, 0x03],
                8,
                vec![0x48, 0x45, 0x4C, 0x4C, 0x4F],
            ),
            (
                vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x01],
                8,
                vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
            ),
        ];

        for (i, (mut padded_input, block_size, expected)) in test_cases.into_iter().enumerate() {
            pkcs7::remove(&mut padded_input, block_size, AZIHSM_AES_DECRYPT_FAILED)
                .unwrap_or_else(|_| panic!("Test case {}: Failed to remove padding", i));
            assert_eq!(
                padded_input, expected,
                "Test case {}: Padding removal failed",
                i
            );
        }
    }

    #[test]
    fn test_pkcs7_padding_round_trip() {
        let inputs = vec![
            b"".as_slice(),
            b"A".as_slice(),
            b"HELLO".as_slice(),
            b"HELLO WORLD".as_slice(),
            b"1234567890123456".as_slice(), // Exactly one AES block
            b"12345678901234567890123456789012".as_slice(), // Two AES blocks
            b"The quick brown fox jumps over the lazy dog".as_slice(),
        ];

        let block_sizes = [8, 16]; // Test both DES and AES block sizes

        for (input_idx, input) in inputs.into_iter().enumerate() {
            for (block_idx, block_size) in block_sizes.iter().enumerate() {
                let mut padded = Vec::new();

                // Apply padding
                pkcs7::apply(input, &mut padded, *block_size);

                // Verify padded length is multiple of block size
                assert_eq!(
                    padded.len() % block_size,
                    0,
                    "Input {}, Block {}: Padded length not multiple of block size",
                    input_idx,
                    block_idx
                );

                // Remove padding
                pkcs7::remove(&mut padded, *block_size, AZIHSM_AES_DECRYPT_FAILED).unwrap_or_else(
                    |_| {
                        panic!(
                            "Input {}, Block {}: Failed to remove padding",
                            input_idx, block_idx
                        )
                    },
                );

                // Verify round-trip
                assert_eq!(
                    padded, input,
                    "Input {}, Block {}: Round-trip failed",
                    input_idx, block_idx
                );
            }
        }
    }

    #[test]
    fn test_pkcs7_padding_invalid_cases() {
        let invalid_cases = vec![
            // (invalid_padded_data, block_size, description)
            (vec![], 16, "Empty data"),
            (vec![0x00], 16, "Zero padding length"),
            (vec![0x11], 16, "Padding length > block size"),
            (vec![0x01, 0x02], 16, "Wrong padding byte"),
            (vec![0x01, 0x01, 0x01, 0x02], 16, "Mixed padding bytes"),
            (
                vec![0x05, 0x05, 0x05, 0x05],
                16,
                "Padding length > actual length",
            ),
        ];

        for (i, (mut invalid_data, block_size, description)) in
            invalid_cases.into_iter().enumerate()
        {
            let result = pkcs7::remove(&mut invalid_data, block_size, AZIHSM_AES_DECRYPT_FAILED);
            assert!(
                result.is_err(),
                "Test case {} ({}): Should reject invalid padding",
                i,
                description
            );
            assert_eq!(
                result.unwrap_err(),
                AZIHSM_AES_DECRYPT_FAILED,
                "Test case {} ({}): Wrong error code",
                i,
                description
            );
        }
    }
}

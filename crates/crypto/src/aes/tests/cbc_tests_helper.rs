// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[derive(Debug)]
pub(super) enum CbcTestVectorFailure {
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
        input: &'static [u8],
        expected: &'static [u8],
        actual: Vec<u8>,
    },
}

pub(super) fn assert_cbc_vector_success(
    failure_prefix: &str,
    mismatch_header: &str,
    result: Result<(), CbcTestVectorFailure>,
) {
    result.unwrap_or_else(|failure| match failure {
        CbcTestVectorFailure::Crypto { id, encrypt, source } => {
            panic!(
                "{} failed: id={} encrypt={} err={:?}",
                failure_prefix, id, encrypt, source
            );
        }
        CbcTestVectorFailure::Mismatch {
            id,
            encrypt,
            key,
            iv,
            input,
            expected,
            actual,
        } => {
            panic!(
                "{}\nTest Count ID: {}\nEncrypt: {}\nKey: {:02x?}\nIV: {:02x?}\nInput: {:02x?}\nExpected Output: {:02x?}\nActual Output: {:02x?}",
                mismatch_header, id, encrypt, key, iv, input, expected, actual
            );
        }
    });
}

pub(super) fn test_single_shot_encrypt(
    key_bytes: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = AesKey::from_bytes(key_bytes)?;
    let iv = iv.to_vec();

    let mut algo = AesCbcAlgo::with_no_padding(&iv);
    let len = Encrypter::encrypt(&mut algo, &key, input, None)?;
    let mut output = vec![0u8; len];
    let len = Encrypter::encrypt(&mut algo, &key, input, Some(&mut output))?;
    output.truncate(len);
    Ok(output)
}

pub(super) fn test_single_shot_decrypt(
    key_bytes: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = AesKey::from_bytes(key_bytes)?;
    let iv = iv.to_vec();

    let mut algo = AesCbcAlgo::with_no_padding(&iv);
    let len = Decrypter::decrypt(&mut algo, &key, input, None)?;
    let mut output = vec![0u8; len];
    let len = Decrypter::decrypt(&mut algo, &key, input, Some(&mut output))?;
    output.truncate(len);
    Ok(output)
}

pub(super) fn test_streaming_encrypt(
    key_bytes: &[u8],
    iv: &[u8],
    input: &[u8],
    chunk_lens: &[usize],
) -> Result<Vec<u8>, CryptoError> {
    let key = AesKey::from_bytes(key_bytes)?;
    let iv = iv.to_vec();

    let mut output = vec![0u8; input.len() + 16];
    let algo = AesCbcAlgo::with_no_padding(&iv);
    let mut context = Encrypter::encrypt_init(algo, key)?;

    let mut offset = 0usize;
    let mut cursor = 0usize;
    for &chunk_len in chunk_lens {
        if cursor >= input.len() {
            break;
        }
        let end = (cursor + chunk_len).min(input.len());
        offset += context.update(&input[cursor..end], Some(&mut output[offset..]))?;
        cursor = end;
    }
    if cursor < input.len() {
        offset += context.update(&input[cursor..], Some(&mut output[offset..]))?;
    }
    offset += context.finish(Some(&mut output[offset..]))?;
    output.truncate(offset);
    Ok(output)
}

pub(super) fn test_streaming_decrypt(
    key_bytes: &[u8],
    iv: &[u8],
    input: &[u8],
    chunk_lens: &[usize],
) -> Result<Vec<u8>, CryptoError> {
    let key = AesKey::from_bytes(key_bytes)?;
    let iv = iv.to_vec();

    let mut output = vec![0u8; input.len() + 16];
    let algo = AesCbcAlgo::with_no_padding(&iv);
    let mut context = Decrypter::decrypt_init(algo, key)?;

    let mut offset = 0usize;
    let mut cursor = 0usize;
    for &chunk_len in chunk_lens {
        if cursor >= input.len() {
            break;
        }
        let end = (cursor + chunk_len).min(input.len());
        offset += context.update(&input[cursor..end], Some(&mut output[offset..]))?;
        cursor = end;
    }
    if cursor < input.len() {
        offset += context.update(&input[cursor..], Some(&mut output[offset..]))?;
    }
    offset += context.finish(Some(&mut output[offset..]))?;
    output.truncate(offset);
    Ok(output)
}

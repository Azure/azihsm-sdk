// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use super::*;
use crate::hmac::*;
use crate::secretkey::*;

impl KbkdfKeyDeriveOps for SecretKey {
    /// Derives a key using KBKDF (SP800-108) with the specified base key, hash algorithm, label, and context.
    ///
    /// # Parameters
    /// - `base_key`: The input key material for HMAC.
    /// - `hash_algo`: The hash algorithm to use (SHA256, SHA384, SHA512).
    /// - `label`: Optional label for KBKDF.
    /// - `context`: Optional context for KBKDF.
    /// - `out_len`: Desired output key length in bytes.
    /// - `secret_key`: Output buffer to receive the derived key.
    ///
    /// # Returns
    /// - `Ok(&[u8])`: Slice of the valid derived key bytes.
    /// - `Err(CryptoError)`: If any error occurs during key derivation.
    #[allow(unsafe_code)]
    fn kbkdf_derive<'a>(
        &self,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        context: Option<&[u8]>,
        out_len: usize,
        secret_key: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        tracing::debug!("kbdkf_derive called: base_key_len={}, hash_algo={:?}, label_len={}, context_len={}, out_len={}", self.kdk.len(), hash_algo, label.map_or(0, |l| l.len()), context.map_or(0, |c| c.len()), out_len);
        // Validate output length
        if out_len == 0 {
            tracing::error!("Output length must be greater than zero");
            return Err(CryptoError::InvalidOutputLength);
        }
        if secret_key.len() < out_len {
            tracing::error!(
                "Output buffer too small: secret_key.len()={}, out_len={}",
                secret_key.len(),
                out_len
            );
            return Err(CryptoError::InvalidOutputLength);
        }

        // Prepare label and context buffers for KBKDF
        let l_label = label.unwrap_or(&[]);
        let l_context = context.unwrap_or(&[]);
        tracing::debug!(
            "Prepared label/context: label_len={}, context_len={}",
            l_label.len(),
            l_context.len()
        );

        // Manual KBKDF (SP800-108 CTR-HMAC) implementation using internal hmac module
        let hash_len = match hash_algo {
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
            HashAlgo::Sha512 => 64,
            _ => {
                tracing::error!("Unsupported hash algorithm: {:?}", hash_algo);
                return Err(CryptoError::UnsupportedHashAlgorithm);
            }
        };
        if out_len == 0 || secret_key.len() < out_len {
            tracing::error!("Invalid output length for KBKDF manual");
            return Err(CryptoError::InvalidOutputLength);
        }
        // Construct fixed input: [Counter 4 bytes][Label] || 0x00 || [Context]
        let mut fixed_input = Vec::new();
        fixed_input.extend_from_slice(l_label);
        if !l_context.is_empty() {
            fixed_input.push(0x00);
            fixed_input.extend_from_slice(l_context);
        }

        let mut result = Vec::with_capacity(out_len);
        let mut counter: u32 = 1;
        // Validate HMAC key length for selected hash algorithm
        let key_range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.kdk.len() < key_range.lower_bound {
            tracing::error!(
                "KBKDF: base key too short for {:?}: {} < {}",
                hash_algo,
                self.kdk.len(),
                key_range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.kdk.len() > key_range.upper_bound {
            tracing::error!(
                "KBKDF: base key too long for {:?}: {} > {}",
                hash_algo,
                self.kdk.len(),
                key_range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        let hmac_key = match HmacKey::from_slice(&self.kdk) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Failed to create HmacKey: {:?}", e);
                return Err(CryptoError::SecretCreationFailed);
            }
        };
        while result.len() < out_len {
            let mut hmac_input = Vec::new();
            hmac_input.extend_from_slice(&counter.to_be_bytes());
            hmac_input.extend_from_slice(&fixed_input);
            let mut digest = vec![0u8; hash_len];
            match hmac_key.hmac_crypt_sign(hash_algo, &hmac_input, &mut digest) {
                Ok(sig) => {
                    let take_len = std::cmp::min(sig.len(), out_len - result.len());
                    result.extend_from_slice(&sig[..take_len]);
                }
                Err(e) => {
                    tracing::error!("HMAC sign failed: {:?}", e);
                    return Err(CryptoError::KbkdfSignerUpdateError);
                }
            }
            counter += 1;
        }
        secret_key[..out_len].copy_from_slice(&result[..out_len]);
        Ok(&secret_key[..out_len])
    }
}

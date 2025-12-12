// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use azihsm_crypto::DigestContext;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashContext;
use azihsm_crypto::HashOp;

use crate::crypto::DigestOp;
use crate::crypto::StreamingDigestAlgo;
use crate::crypto::StreamingDigestOp;
use crate::types::AlgoId;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_ALGORITHM_NOT_SUPPORTED;
use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
use crate::AZIHSM_INTERNAL_ERROR;

pub struct ShaAlgo {
    pub algo: AlgoId,
}

impl DigestOp for ShaAlgo {
    fn digest(
        &mut self,
        _session: &Session,
        message: &[u8],
        digest: &mut [u8],
    ) -> Result<(), AzihsmError> {
        let sha_algo = match self.algo {
            AlgoId::Sha1 => HashAlgo::Sha1,
            AlgoId::Sha256 => HashAlgo::Sha256,
            AlgoId::Sha384 => HashAlgo::Sha384,
            AlgoId::Sha512 => HashAlgo::Sha512,
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        };
        // Call hash function, session is not used for now
        sha_algo
            .hash(message, digest)
            .map_err(|crypto_error| match crypto_error {
                azihsm_crypto::CryptoError::ShaError => AZIHSM_INTERNAL_ERROR,
                azihsm_crypto::CryptoError::ShaDigestSizeError => AZIHSM_ERROR_INSUFFICIENT_BUFFER,
                _ => AZIHSM_INTERNAL_ERROR,
            })
    }
    /// Get the required digest length for the algorithm
    fn digest_len(&self) -> Result<u32, AzihsmError> {
        let sha_algo = match self.algo {
            AlgoId::Sha1 => HashAlgo::Sha1,
            AlgoId::Sha256 => HashAlgo::Sha256,
            AlgoId::Sha384 => HashAlgo::Sha384,
            AlgoId::Sha512 => HashAlgo::Sha512,
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        };
        // Get digest length
        Ok(sha_algo.hash_length() as u32)
    }
}

/// Streaming SHA digest operation
pub struct ShaDigestStream {
    hasher: DigestContext,
    hash_algo: HashAlgo,
}

impl StreamingDigestOp for ShaDigestStream {
    fn digest_len(&self) -> usize {
        self.hash_algo.hash_length()
    }

    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError> {
        self.hasher.update(data).map_err(|_| AZIHSM_INTERNAL_ERROR)
    }

    fn finalize(self, digest: &mut [u8]) -> Result<usize, AzihsmError> {
        let digest_len = self.hash_algo.hash_length();

        if digest.len() < digest_len {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        self.hasher
            .finish(&mut digest[..digest_len])
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        Ok(digest_len)
    }
}

impl<'a> StreamingDigestAlgo<'a> for ShaAlgo {
    type DigestStream = ShaDigestStream;

    fn digest_init(&self, _session: &'a Session) -> Result<Self::DigestStream, AzihsmError> {
        let hash_algo = HashAlgo::try_from(self.algo)?;
        let hasher = hash_algo.init().map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        Ok(ShaDigestStream { hasher, hash_algo })
    }
}

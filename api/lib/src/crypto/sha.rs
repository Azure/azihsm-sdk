// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use azihsm_crypto::*;

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
        let mut sha_algo = match self.algo {
            AlgoId::Sha1 => HashAlgo::sha1(),
            AlgoId::Sha256 => HashAlgo::sha256(),
            AlgoId::Sha384 => HashAlgo::sha384(),
            AlgoId::Sha512 => HashAlgo::sha512(),
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        };

        Hasher::hash(&mut sha_algo, message, Some(digest)).map_err(|e| match e {
            CryptoError::HashBufferTooSmall => AZIHSM_ERROR_INSUFFICIENT_BUFFER,
            _ => AZIHSM_INTERNAL_ERROR,
        })?;
        Ok(())
    }
    /// Get the required digest length for the algorithm
    fn digest_len(&self) -> Result<u32, AzihsmError> {
        let sha_algo = match self.algo {
            AlgoId::Sha1 => HashAlgo::sha1(),
            AlgoId::Sha256 => HashAlgo::sha256(),
            AlgoId::Sha384 => HashAlgo::sha384(),
            AlgoId::Sha512 => HashAlgo::sha512(),
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        };
        // Get digest length
        Ok(sha_algo.size() as u32)
    }
}

/// Streaming SHA digest operation
pub struct ShaDigestStream {
    hasher: HashAlgoContext,
    size: usize,
}

impl StreamingDigestOp for ShaDigestStream {
    fn digest_len(&self) -> usize {
        self.size
    }

    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError> {
        self.hasher.update(data).map_err(|_| AZIHSM_INTERNAL_ERROR)
    }

    fn finalize(mut self, digest: &mut [u8]) -> Result<usize, AzihsmError> {
        let digest_len = self.digest_len();

        if digest.len() < digest_len {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        self.hasher
            .finish(Some(&mut digest[..digest_len]))
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        Ok(digest_len)
    }
}

impl<'a> StreamingDigestAlgo<'a> for ShaAlgo {
    type DigestStream = ShaDigestStream;
    fn digest_init(&self, _session: &'a Session) -> Result<Self::DigestStream, AzihsmError> {
        let hash_algo = HashAlgo::try_from(self.algo)?;
        let hash_size = hash_algo.size();
        let hasher = Hasher::hash_init(hash_algo).map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        Ok(ShaDigestStream {
            hasher,
            size: hash_size,
        })
    }
}

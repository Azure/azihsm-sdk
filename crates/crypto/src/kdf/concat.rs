// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Single-step "concatenation" KDFs on a shared secret — ANSI X9.63 and
//! NIST SP 800-56A r3 one-step (§5.8.2.1).
//!
//! Both derive keying material from a shared secret `Z` (typically an ECDH
//! output) plus an optional info octet string, by hashing
//! `Z`, a 4-byte big-endian block counter, and the info in a variant-fixed
//! order, concatenating the per-block digests, and truncating to the
//! requested length:
//!
//! ```text
//! X9.63       : K = Hash(Z || counter || Info) || …     (SEC 1 §3.6.1)
//! SP 800-56A  : K = Hash(counter || Z || Info) || …     (SP 800-56A §5.8.2.1)
//! ```
//!
//! The two differ only in the placement of the counter relative to `Z`.
//! Because they need nothing but a hash, this is a single **platform-
//! agnostic** implementation over the shared [`Hasher`] — it works
//! identically on the OpenSSL (Linux) and CNG (Windows) backends, unlike
//! HKDF which has per-backend implementations.

use super::*;

/// Which single-step concatenation KDF to run.  The variants differ only
/// in the byte order of the hash input (see the [module docs](self)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcatKdfMode {
    /// ANSI X9.63 / SEC 1 §3.6.1: `Hash(Z || counter || Info)`.
    X963,
    /// NIST SP 800-56A r3 §5.8.2.1 one-step: `Hash(counter || Z || Info)`.
    Sp800_56a,
}

/// Single-step concatenation KDF provider.
///
/// Configured with a hash algorithm, the [`ConcatKdfMode`] variant, and an
/// optional info octet string (`SharedInfo` for X9.63, `OtherInfo` for
/// SP 800-56A), then run via [`DeriveOp::derive`].
pub struct ConcatKdfAlgo {
    hash_algo: HashAlgo,
    mode: ConcatKdfMode,
    info: Option<Vec<u8>>,
}

impl ConcatKdfAlgo {
    /// Create a single-step KDF over `hash` in the given `mode`.
    ///
    /// `info` is the optional `SharedInfo` (X9.63) / `OtherInfo`
    /// (SP 800-56A) octet string; `None` (or an empty slice) omits it.
    pub fn new(hash: HashAlgo, mode: ConcatKdfMode, info: Option<Vec<u8>>) -> Self {
        Self {
            hash_algo: hash,
            mode,
            info,
        }
    }
}

impl DeriveOp for ConcatKdfAlgo {
    type Key = GenericSecretKey;
    type DerivedKey = GenericSecretKey;

    /// Derive `derive_len` bytes of keying material from shared secret
    /// `key` (`Z`).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::ConcatKdfInvalidSecretLength`] — `key` (`Z`) is empty.
    /// - [`CryptoError::ConcatKdfInvalidDerivedKeyLength`] — `derive_len`
    ///   is zero, or so large that the block counter would exceed the
    ///   `2^32 - 1` cap.
    /// - [`CryptoError::ConcatKdfDeriveError`] — the underlying hash failed.
    fn derive(&self, key: &Self::Key, derive_len: usize) -> Result<Self::DerivedKey, CryptoError> {
        if key.size() == 0 {
            return Err(CryptoError::ConcatKdfInvalidSecretLength);
        }
        if derive_len == 0 {
            return Err(CryptoError::ConcatKdfInvalidDerivedKeyLength);
        }

        let hash_size = self.hash_algo.size();
        // Number of hash blocks required.  Guard against the RFC/SEC cap:
        // the 4-byte counter must not overflow `u32`.
        let rounds = derive_len.div_ceil(hash_size);
        if u32::try_from(rounds).is_err() {
            return Err(CryptoError::ConcatKdfInvalidDerivedKeyLength);
        }

        let z = key.to_vec()?;
        let info = self.info.as_deref().unwrap_or(&[]);

        let mut derived = vec![0u8; derive_len];
        for round in 0..rounds {
            // Block counter is 1-indexed, 4 bytes big-endian.  `round <
            // rounds <= u32::MAX` (checked above), so `+ 1` cannot wrap.
            let counter = (round as u32 + 1).to_be_bytes();

            // Assemble the per-block hash input in the variant's field
            // order, then hash it in one shot.
            let mut input = Vec::with_capacity(z.len() + counter.len() + info.len());
            match self.mode {
                ConcatKdfMode::X963 => {
                    input.extend_from_slice(&z);
                    input.extend_from_slice(&counter);
                    input.extend_from_slice(info);
                }
                ConcatKdfMode::Sp800_56a => {
                    input.extend_from_slice(&counter);
                    input.extend_from_slice(&z);
                    input.extend_from_slice(info);
                }
            }

            let mut hasher = self.hash_algo.clone();
            let digest = Hasher::hash_vec(&mut hasher, &input)
                .map_err(|_| CryptoError::ConcatKdfDeriveError)?;

            let start = round * hash_size;
            let len = (derive_len - start).min(hash_size);
            derived[start..start + len].copy_from_slice(&digest[..len]);
        }

        GenericSecretKey::from_bytes(&derived)
    }
}

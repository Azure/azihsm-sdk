// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Random number generation support
#[cfg(target_os = "windows")]
mod rand_cng;

#[cfg(target_os = "linux")]
mod rand_ossl;

pub(crate) use crate::CryptoError;

/// RNG struct for random number generation
#[derive(Debug, Clone)]
pub struct Rng {}

/// Trait for RNG operations.
pub trait RngOp {
    /// Generates a random number.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to fill with random bytes.
    ///
    /// # Returns
    ///
    /// * `Result<(), CryptoError>` - Returns `Ok(())` on success,
    ///   or `Err(CryptoError)` if random number generation fails.
    fn rand_bytes(&self, buf: &mut [u8]) -> Result<(), CryptoError>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rand_bytes() {
        let rng = Rng {};
        let mut buf = [0u8; 1024];
        assert!(rng.rand_bytes(&mut buf).is_ok());
        println!("Random bytes: {:x?}", buf);
        // Check that the buffer is not all zeros (very unlikely)
        assert_ne!(buf, [0u8; 1024]);
    }
}

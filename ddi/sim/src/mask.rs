// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Masking Key for Live Migration.
use crate::errors::ManticoreError;
use crate::table::entry::Kind;

/// The maximum possible size of crypto key after serialization
/// Also adjust this to make sure KEY_BLOB_MAX_SIZE mod 4 == 0 for AES Encrypt/Decrypt
pub(crate) const KEY_BLOB_MAX_SIZE: usize = 2720;

/// Trait for Key Masking related operations.
/// Serialize keys and entries into opaque byte arrays.
pub(crate) trait KeySerialization<T> {
    /// Serializes the struct into a byte array.
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError>;

    /// Deserializes from a byte array.
    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<T, ManticoreError>;
}

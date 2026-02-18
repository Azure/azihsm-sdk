// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod hkdf_ossl;
    } else if #[cfg(target_os = "windows")] {
        mod hkdf_cng;
    } else {
        compile_error!("Unsupported target OS for HKDF implementation");

    }
}
mod kbkdf;

use super::*;

/// HKDF derivation mode selector.
///
/// Specifies which phase(s) of the HKDF algorithm to execute. This allows
/// flexible usage patterns including full HKDF, or individual Extract/Expand
/// operations for scenarios requiring multiple derived keys from the same input.
///
/// # RFC 5869 Specification
///
/// From RFC 5869, HKDF is defined as:
/// ```text
/// HKDF(salt, IKM, info, L) = HKDF-Expand(HKDF-Extract(salt, IKM), info, L)
/// ```
///
/// This enum allows executing the complete operation or individual phases.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HkdfMode {
    /// Perform only HMAC-Extract(salt, IKM) → PRK.
    ///
    /// Outputs a pseudorandom key (PRK) of hash output length. The salt
    /// parameter is optional but recommended. Use this mode when you want
    /// to derive the PRK once and perform multiple Expand operations.
    Extract,

    /// Perform only HKDF-Expand(PRK, info, L) → OKM.
    ///
    /// Takes a pseudorandom key (PRK) as input and expands it to the desired
    /// output length. The info parameter provides context binding. Use this
    /// mode when you already have a PRK from a previous Extract operation.
    Expand,

    /// Perform full HKDF: Extract followed by Expand.
    ///
    /// This is the standard HKDF operation that takes input keying material,
    /// extracts a PRK using the salt, then expands it using the info parameter
    /// to produce the final output keying material of the desired length.
    ExtractAndExpand,
}

define_type!(pub HkdfAlgo<'a>, hkdf_ossl::OsslHkdfAlgo<'a>, hkdf_cng::CngHkdfAlgo<'a>);
define_type!(pub KbkdfAlgo, kbkdf::KbkdfAlgo, kbkdf::KbkdfAlgo);

#[cfg(test)]
mod tests;

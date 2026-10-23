// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parser for `azihsm://` key URIs, used by `ENGINE_load_private_key`, the
//! AES ciphers' key control and the `GENERATE_KEY` command.
//!
//! Grammar (mirrors the OpenSSL 3.x provider's STORE):
//!
//! ```text
//! azihsm://<masked-key-file-path>;type=<ec|rsa|rsa-pss|aes|aes-gcm|aes-xts>[;bits=<n>]
//! ```
//!
//! The identifier is a filesystem path to a masked-key blob; `type=` is
//! mandatory. AES keys are not private keys: they are attached to a cipher
//! context (see [`crate::aes`]), and `ENGINE_load_private_key` rejects them.
//! `bits=`, the key size, applies to AES keys only.
//!
//! Note: unlike the provider's STORE — which ignores unrecognized attributes —
//! this parser is stricter and rejects unknown or malformed attributes, so a
//! typo fails fast rather than being silently dropped.

use std::path::PathBuf;
use std::str::FromStr;

use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;

const SCHEME: &str = "azihsm://";

/// Key type selected by the URI `type=` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ec,
    Rsa,
    RsaPss,
    Aes(AesKind),
}

/// The HSM's AES key kinds; a key serves only its own kind's cipher mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKind {
    /// `type=aes`: the HSM's plain AES key, used by AES-CBC.
    Cbc,
    /// `type=aes-gcm`.
    Gcm,
    /// `type=aes-xts`: an AES-XTS key pair.
    Xts,
}

impl FromStr for KeyType {
    type Err = EngineError;

    /// Parse a URI `type=` value into a [`KeyType`]. Case-insensitive, mirroring
    /// the provider's STORE (which compares with `strcasecmp`).
    fn from_str(value: &str) -> EngineResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ec" => Ok(KeyType::Ec),
            "rsa" => Ok(KeyType::Rsa),
            "rsa-pss" => Ok(KeyType::RsaPss),
            "aes" => Ok(KeyType::Aes(AesKind::Cbc)),
            "aes-gcm" => Ok(KeyType::Aes(AesKind::Gcm)),
            "aes-xts" => Ok(KeyType::Aes(AesKind::Xts)),
            _ => Err(EngineError::Other(format!(
                "unknown azihsm key type: {value}"
            ))),
        }
    }
}

/// A parsed `azihsm://<path>;type=<t>` key URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUri {
    /// Path to the masked-key blob on disk.
    pub masked_key_path: PathBuf,
    /// Declared key type.
    pub key_type: KeyType,
    /// Declared key size in bits (`bits=`, AES keys only).
    pub bits: Option<u32>,
}

/// Parse an `azihsm://` key URI.
pub fn parse(uri: &str) -> EngineResult<KeyUri> {
    let rest = uri
        .strip_prefix(SCHEME)
        .ok_or_else(|| EngineError::Other(format!("key id is not an {SCHEME} URI: {uri}")))?;

    let (path, attrs) = rest.split_once(';').unwrap_or((rest, ""));
    if path.is_empty() {
        return Err(EngineError::Other("azihsm URI has no key path".into()));
    }

    let mut key_type = None;
    let mut bits = None;
    for attr in attrs.split(';').filter(|a| !a.is_empty()) {
        let (key, value) = attr
            .split_once('=')
            .ok_or_else(|| EngineError::Other(format!("malformed azihsm URI attribute: {attr}")))?;
        // Attribute names are case-insensitive, mirroring the provider's STORE
        // (which compares with `strcasecmp`).
        match key.to_ascii_lowercase().as_str() {
            "type" => key_type = Some(value.parse::<KeyType>()?),
            "bits" => {
                bits = Some(value.parse::<u32>().map_err(|_| {
                    EngineError::Other(format!("azihsm URI bits= is not a number: {value}"))
                })?);
            }
            _ => {
                return Err(EngineError::Other(format!(
                    "unknown azihsm URI attribute: {key}"
                )));
            }
        }
    }

    let key_type = key_type
        .ok_or_else(|| EngineError::Other("azihsm URI missing required type= attribute".into()))?;
    if bits.is_some() && !matches!(key_type, KeyType::Aes(_)) {
        return Err("azihsm URI bits= applies to AES keys only".into());
    }

    Ok(KeyUri {
        masked_key_path: PathBuf::from(path),
        key_type,
        bits,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_relative_ec() {
        let u = parse("azihsm://./key.bin;type=ec").unwrap();
        assert_eq!(u.masked_key_path, PathBuf::from("./key.bin"));
        assert_eq!(u.key_type, KeyType::Ec);
    }

    #[test]
    fn parses_absolute_rsa() {
        let u = parse("azihsm:///var/lib/azihsm/k.bin;type=rsa").unwrap();
        assert_eq!(u.masked_key_path, PathBuf::from("/var/lib/azihsm/k.bin"));
        assert_eq!(u.key_type, KeyType::Rsa);
    }

    #[test]
    fn parses_rsa_pss() {
        assert_eq!(
            parse("azihsm://k;type=rsa-pss").unwrap().key_type,
            KeyType::RsaPss
        );
    }

    // The provider's STORE compares the attribute name and value with
    // strcasecmp, so mixed case must parse the same here.
    #[test]
    fn parses_uppercase_attr_name_and_value() {
        let u = parse("azihsm://./key.bin;TYPE=EC").unwrap();
        assert_eq!(u.key_type, KeyType::Ec);
    }

    #[test]
    fn parses_mixed_case_rsa_pss() {
        assert_eq!(
            parse("azihsm://k;Type=Rsa-PSS").unwrap().key_type,
            KeyType::RsaPss
        );
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(parse("./key.bin;type=ec").is_err());
    }

    #[test]
    fn rejects_empty_path() {
        assert!(parse("azihsm://;type=ec").is_err());
    }

    #[test]
    fn rejects_missing_type() {
        assert!(parse("azihsm://./key.bin").is_err());
    }

    #[test]
    fn rejects_unknown_type() {
        assert!(parse("azihsm://k;type=dsa").is_err());
    }

    #[test]
    fn parses_aes() {
        let u = parse("azihsm://k;type=AES").unwrap();
        assert_eq!(u.key_type, KeyType::Aes(AesKind::Cbc));
        assert_eq!(u.bits, None);
    }

    #[test]
    fn parses_aes_kinds_and_bits() {
        for (uri, kind, bits) in [
            ("azihsm://k;type=aes;bits=128", AesKind::Cbc, 128),
            ("azihsm://k;BITS=256;type=Aes-GCM", AesKind::Gcm, 256),
            ("azihsm://k;type=AES-XTS;bits=512", AesKind::Xts, 512),
        ] {
            let u = parse(uri).unwrap();
            assert_eq!(u.key_type, KeyType::Aes(kind), "{uri}");
            assert_eq!(u.bits, Some(bits), "{uri}");
        }
    }

    #[test]
    fn rejects_bad_bits() {
        for uri in [
            "azihsm://k;type=aes;bits=",
            "azihsm://k;type=aes;bits=abc",
            "azihsm://k;type=aes;bits=-128",
            "azihsm://k;type=ec;bits=256",
            "azihsm://k;type=rsa;bits=2048",
        ] {
            assert!(parse(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn rejects_unknown_attribute() {
        assert!(parse("azihsm://k;type=ec;foo=bar").is_err());
    }

    #[test]
    fn rejects_malformed_attribute() {
        assert!(parse("azihsm://k;type").is_err());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parser for `azihsm://` key URIs used by `ENGINE_load_private_key`.
//!
//! Grammar (mirrors the OpenSSL 3.x provider's STORE):
//!
//! ```text
//! azihsm://<masked-key-file-path>;type=<ec|rsa|rsa-pss>
//! ```
//!
//! The identifier is a filesystem path to a masked-key blob; `type=` is
//! mandatory. `aes` is a valid provider key type but is not loadable as a
//! private key here, so it is rejected.
//!
//! Note: unlike the provider's STORE — which ignores unrecognized attributes —
//! this parser is stricter and rejects unknown or malformed attributes, so a
//! typo fails fast rather than being silently dropped.

use std::path::PathBuf;

use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;

const SCHEME: &str = "azihsm://";

/// Key type selected by the URI `type=` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ec,
    Rsa,
    RsaPss,
}

/// A parsed `azihsm://<path>;type=<t>` key URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUri {
    /// Path to the masked-key blob on disk.
    pub masked_key_path: PathBuf,
    /// Declared key type.
    pub key_type: KeyType,
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
    for attr in attrs.split(';').filter(|a| !a.is_empty()) {
        let (key, value) = attr
            .split_once('=')
            .ok_or_else(|| EngineError::Other(format!("malformed azihsm URI attribute: {attr}")))?;
        // Attribute names are case-insensitive, mirroring the provider's STORE
        // (which compares with `strcasecmp`).
        match key.to_ascii_lowercase().as_str() {
            "type" => key_type = Some(parse_key_type(value)?),
            _ => {
                return Err(EngineError::Other(format!(
                    "unknown azihsm URI attribute: {key}"
                )));
            }
        }
    }

    let key_type = key_type
        .ok_or_else(|| EngineError::Other("azihsm URI missing required type= attribute".into()))?;

    Ok(KeyUri {
        masked_key_path: PathBuf::from(path),
        key_type,
    })
}

fn parse_key_type(value: &str) -> EngineResult<KeyType> {
    // Values are case-insensitive, mirroring the provider's STORE (`strcasecmp`).
    match value.to_ascii_lowercase().as_str() {
        "ec" => Ok(KeyType::Ec),
        "rsa" => Ok(KeyType::Rsa),
        "rsa-pss" => Ok(KeyType::RsaPss),
        "aes" => Err(EngineError::Other(
            "aes keys cannot be loaded via load_private_key".into(),
        )),
        _ => Err(EngineError::Other(format!(
            "unknown azihsm key type: {value}"
        ))),
    }
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
    fn rejects_aes() {
        assert!(parse("azihsm://k;type=aes").is_err());
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

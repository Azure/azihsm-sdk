// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provision masked key blobs for the engine.
//!
//! Opens the mock HSM from the ambient `AZIHSM_*` environment — the same
//! environment the engine-loading `openssl` process uses — and writes masked
//! key blobs the engine can later unmask via `ENGINE_load_private_key`.
//! Because both processes share the resiliency storage dir (the persisted
//! BMK), the OBK, and the POTA keypair, blobs provisioned here load there.
//!
//! Subcommands:
//!   ec-generate  --masked-out PATH
//!       Generate a persistent EC P-384 signing key in the HSM.
//!   rsa-import   (--input-key PATH | --wrapped-key PATH --bits N)
//!                [--usage sign|decrypt] --masked-out PATH [--pubkey-out PATH]
//!       Import an external RSA key. `--input-key` takes plaintext PKCS#1 or
//!       PKCS#8 DER and wraps it against the HSM's unwrapping key;
//!       `--wrapped-key` takes a pre-wrapped blob (SHA-256 OAEP, AES-256 KWP)
//!       whose modulus size must be given via `--bits`.
//!   wrapping-key --pubkey-out PATH
//!       Export the HSM's RSA-AES wrapping public key (SPKI DER) for
//!       wrapping keys offline.

#[cfg(feature = "integration")]
fn main() {
    if let Err(err) = run() {
        eprintln!("masked-keygen: {err}");
        std::process::exit(1);
    }
}

#[cfg(feature = "integration")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use azihsm_ossl_engine::integration;
    use azihsm_ossl_engine::integration::RsaKeyUsage;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, flags) = args
        .split_first()
        .ok_or("usage: masked-keygen <ec-generate|rsa-import|wrapping-key> [flags]")?;

    let mut input_key: Option<String> = None;
    let mut wrapped_key: Option<String> = None;
    let mut bits: Option<u32> = None;
    let mut usage = RsaKeyUsage::Sign;
    let mut masked_out: Option<String> = None;
    let mut pubkey_out: Option<String> = None;

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let mut value = || -> Result<String, Box<dyn std::error::Error>> {
            Ok(it
                .next()
                .ok_or_else(|| format!("{flag} requires a value"))?
                .clone())
        };
        match flag.as_str() {
            "--input-key" => input_key = Some(value()?),
            "--wrapped-key" => wrapped_key = Some(value()?),
            "--bits" => bits = Some(value()?.parse()?),
            "--usage" => {
                usage = match value()?.as_str() {
                    "sign" => RsaKeyUsage::Sign,
                    "decrypt" => RsaKeyUsage::Decrypt,
                    other => return Err(format!("unknown --usage '{other}'").into()),
                }
            }
            "--masked-out" => masked_out = Some(value()?),
            "--pubkey-out" => pubkey_out = Some(value()?),
            other => return Err(format!("unknown flag '{other}'").into()),
        }
    }

    match cmd.as_str() {
        "ec-generate" => {
            let out = masked_out.ok_or("ec-generate requires --masked-out")?;
            let blob = integration::generate_masked_ec_p384_from_env()?;
            write_secret(&out, &blob)?;
        }
        "rsa-import" => {
            let out = masked_out.ok_or("rsa-import requires --masked-out")?;
            let import = match (input_key, wrapped_key) {
                (Some(path), None) => {
                    if bits.is_some() {
                        return Err("--bits applies only to --wrapped-key imports".into());
                    }
                    // The DER is private key material; wipe our copy on exit.
                    let der = zeroize::Zeroizing::new(std::fs::read(path)?);
                    integration::import_masked_rsa_from_der_env(&der, usage)?
                }
                (None, Some(path)) => {
                    let bits = bits.ok_or("--wrapped-key imports require --bits")?;
                    let blob = std::fs::read(path)?;
                    integration::import_masked_rsa_from_wrapped_env(&blob, bits, usage)?
                }
                _ => {
                    return Err(
                        "rsa-import requires exactly one of --input-key or --wrapped-key".into(),
                    );
                }
            };
            write_secret(&out, &import.masked_key)?;
            if let Some(path) = pubkey_out {
                std::fs::write(path, &import.public_key_der)?;
            }
        }
        "wrapping-key" => {
            let out = pubkey_out.ok_or("wrapping-key requires --pubkey-out")?;
            let der = integration::rsa_wrapping_public_key_from_env()?;
            std::fs::write(out, &der)?;
        }
        other => {
            return Err(format!(
                "unknown command '{other}' (expected ec-generate, rsa-import, or wrapping-key)"
            )
            .into());
        }
    }
    Ok(())
}

/// Write key material with owner-only permissions.
#[cfg(feature = "integration")]
fn write_secret(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(feature = "integration"))]
fn main() {
    eprintln!("masked-keygen must be built with --features integration");
    std::process::exit(2);
}

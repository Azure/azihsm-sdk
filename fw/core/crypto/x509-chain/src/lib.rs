// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! X.509 certificate chain validation (ECC only).
//!
//! Validates an externally-provided X.509 certificate chain one
//! certificate at a time, suitable for memory-constrained `no_std`
//! environments. Uses double-buffering: the caller keeps the previous
//! certificate's DER alive while processing the current one, so the
//! validator borrows from both without copying.
//!
//! ## Supported algorithms
//!
//! | Signature       | Curve  |
//! |-----------------|--------|
//! | ECDSA-SHA-256   | P-256  |
//! | ECDSA-SHA-384   | P-384  |
//! | ECDSA-SHA-512   | P-521  |
//!
//! No RSA. No time validation, CRL, or policy processing.
//!
//! ## Usage
//!
//! ```ignore
//! let mut v = ChainValidator::new(3);
//!
//! // cert[0] = root (self-signed), loaded into buf_a
//! let cert_0 = parse_cert(&buf_a)?;
//! v.step(pal, io, None, &cert_0).await;             // NeedNext
//!
//! // cert[1] = intermediate, loaded into buf_b
//! let cert_1 = parse_cert(&buf_b)?;
//! v.step(pal, io, Some(&cert_0), &cert_1).await;    // NeedNext
//!
//! // cert[2] = leaf, loaded into buf_a (overwrites cert[0])
//! let cert_2 = parse_cert(&buf_a)?;
//! v.step(pal, io, Some(&cert_1), &cert_2).await;    // Valid { ... }
//! ```
//!
//! ## Checks performed (RFC 5280 §6.1, simplified)
//!
//! 1. ECDSA signature verification (via PAL hash + ecc_verify)
//! 2. Issuer↔subject name chaining (byte-exact DER comparison)
//! 3. AKID↔SKID matching (when both present)
//! 4. BasicConstraints cA=true for intermediate certificates
//! 5. KeyUsage keyCertSign for CA certificates
//! 6. Rejection of unrecognized critical extensions

mod ecdsa;
mod parse;
mod types;
mod validate;

pub use parse::parse_cert;
pub use types::key_usage;
pub use types::BasicConstraints;
pub use types::CertInfo;
pub use types::EcPubKey;
pub use types::SigAlgo;
pub use types::StepResult;
pub use validate::ChainValidator;

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Template-based X.509 certificate and PKCS#10 CSR builder.
//!
//! Runtime certificate/CSR construction from pre-generated DER TBS
//! (To-Be-Signed) templates: a generator tool (Linux-only, OpenSSL-based)
//! creates valid certificates with known placeholder byte patterns, then
//! the runtime code patches variable fields at known offsets and assembles
//! the final DER-encoded certificate with a caller-supplied ECDSA-P384
//! signature. The runtime path is `no_std`-friendly and cross-platform: it
//! performs no crypto itself, so callers sign the TBS with any backend
//! (e.g. `azihsm_crypto` on host, the PAL on device).

/// Runtime certificate builder for Root CA, Intermediate CA, and Leaf certificates.
pub mod cert_builder;

/// Runtime CSR (PKCS#10 CertificationRequest) builder.
pub mod csr_builder;

/// Low-level DER encoding helpers for ECDSA signatures and length fields.
pub mod der_helpers;

/// Device CSR (PKCS#10) TBS template — auto-generated.
pub mod device_csr;

/// Intermediate CA certificate TBS template — auto-generated.
pub mod intermediate_cert;

/// Leaf (end-entity) certificate TBS template — auto-generated.
pub mod leaf_cert;

/// Root CA (self-signed) certificate TBS template — auto-generated.
pub mod root_cert;

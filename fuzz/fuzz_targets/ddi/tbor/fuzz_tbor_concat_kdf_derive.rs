// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ConcatKdfDerive coverage with an independent outcome oracle.
//!
//! Valid on-device ECDH secrets reach both KDFs and cross-scope masking.
//! Single-fault cases isolate rejection paths; combined faults check validation
//! precedence. Session mismatches are backend checks, not handler coverage.
//! ECDH always grants derive permission, so this target cannot reach the
//! authenticated-secret-without-derive branch or observe internal zeroization.
//!
//! Reproducible seeds use an 18-byte selector prefix followed by payload bytes.
//! An all-zero prefix derives AES-128 with X9.63/SHA-256 in a cold CO session.
//! Changing only byte 0 to 31 instead exercises authentication-tag rejection.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::*;

/// Masking overhead inferred from the exported P-256 secret envelope size.
const MASK_OVERHEAD: usize = CONCAT_MASKED_SECRET_MIN_LEN - 32;
/// Ciphertext follows the envelope header, IV, and fixed masked-key metadata.
const CIPHERTEXT_OFFSET: usize = MASK_OVERHEAD - 16;
/// Metadata follows the envelope header and AES-GCM IV.
const METADATA_OFFSET: usize = azihsm_crypto::aead_envelope::HEADER_LEN + 12;

/// Independent selectors plus a borrowed payload; small inputs still execute
/// requests without needing to supply hundreds of bytes for boundary buffers.
#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzInput<'a> {
    scenario: u8,
    partition: u8,
    cu: bool,
    source_scope: u8,
    scope: u8,
    curve: u8,
    hash_algo: u8,
    kdf_alg: u8,
    key_type: u8,
    key_length: u8,
    session_id: u16,
    mutation: u8,
    offset: u16,
    mask: u8,
    info_length: u16,
    bytes: &'a [u8],
}

/// Known fixture state, selected independently of the output-scope selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Partition {
    /// Only the calling session's masking key is available.
    Cold,
    /// PartFinal has provisioned Local and Ephemeral masking keys.
    Finalized,
    /// A security domain additionally provides its masking key.
    SecurityDomain,
}

impl Partition {
    /// Bias toward inexpensive cold-partition iterations.
    fn from_byte(value: u8) -> Self {
        match value % 16 {
            0..=11 => Self::Cold,
            12..=14 => Self::Finalized,
            _ => Self::SecurityDomain,
        }
    }

    /// Select an available source/output scope without coupling their selectors.
    fn available_scope(self, value: u8) -> u8 {
        let scopes = [
            common::KeyScope::Session,
            common::KeyScope::Ephemeral,
            common::KeyScope::Local,
            common::KeyScope::SecurityDomain,
        ];
        let count = match self {
            Self::Cold => 1,
            Self::Finalized => 3,
            Self::SecurityDomain => 4,
        };
        scopes[usize::from(value) % count].to_tbor()
    }

    /// Determine output masking-key availability from fixture state.
    fn supports(self, scope: u8) -> bool {
        match scope {
            common::KEY_SCOPE_SESSION => true,
            common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => self != Self::Cold,
            common::KEY_SCOPE_SECURITY_DOMAIN => self == Self::SecurityDomain,
            _ => false,
        }
    }
}

/// Scenario weights reserve 40% for fully valid derivations and 10% for
/// combined faults; the remaining cases each isolate one validation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    /// Supported algorithms, output types, scopes, and buffers.
    Valid,
    /// A guaranteed mismatch with the file handle's active session.
    Session,
    /// An unsupported hash discriminant.
    Hash,
    /// An unsupported concatenation-KDF discriminant.
    Algorithm,
    /// An unsupported output-key discriminant.
    KeyType,
    /// A variable HMAC without its required explicit length.
    MissingLength,
    /// A variable HMAC immediately below its minimum length.
    BelowLength,
    /// A variable HMAC immediately above its maximum length.
    AboveLength,
    /// A raw variable-HMAC length, including valid and invalid values.
    RawLength,
    /// A raw output scope, including unspecified, internal, and unknown values.
    Scope,
    /// A non-Session output before partition initialization.
    ColdScope,
    /// A SecurityDomain output before its masking key is provisioned.
    MissingSd,
    /// An authenticated ECC private key instead of a shared secret.
    NonSecret,
    /// A corrupt envelope magic byte.
    Header,
    /// A corrupt masked-key metadata magic byte.
    Metadata,
    /// A changed ciphertext byte with intact framing and metadata.
    Ciphertext,
    /// A changed final authentication-tag byte.
    Tag,
    /// Shared envelope mutations, including genuine no-ops.
    Mutation,
    /// Bounded raw bytes with deliberately invalid envelope magic.
    RawSecret,
    /// Secret lengths at and immediately outside wire-schema boundaries.
    SecretLength,
    /// Info just beyond its wire-schema maximum.
    InfoLength,
    /// Raw scalars, session ID, info length, and a controlled blob mutation.
    Combined,
}

impl Scenario {
    /// Map one selector to explicitly weighted, reproducible scenarios.
    fn from_byte(value: u8) -> Self {
        match value % 40 {
            0..=15 => Self::Valid,
            16 => Self::Session,
            17 => Self::Hash,
            18 => Self::Algorithm,
            19 => Self::KeyType,
            20 => Self::MissingLength,
            21 => Self::BelowLength,
            22 => Self::AboveLength,
            23 => Self::RawLength,
            24 => Self::Scope,
            25 => Self::ColdScope,
            26 => Self::MissingSd,
            27 => Self::NonSecret,
            28 => Self::Header,
            29 => Self::Metadata,
            30 => Self::Ciphertext,
            31 => Self::Tag,
            32 => Self::Mutation,
            33 => Self::RawSecret,
            34 => Self::SecretLength,
            35 => Self::InfoLength,
            _ => Self::Combined,
        }
    }
}

/// Fill a bounded buffer from fuzz payload, repeating short payloads to reach
/// length boundaries; an empty payload uses the fuzzed mask byte.
fn payload(input: &FuzzInput<'_>, len: usize) -> Vec<u8> {
    if input.bytes.is_empty() {
        vec![input.mask; len]
    } else {
        input.bytes.iter().copied().cycle().take(len).collect()
    }
}

/// Bias info toward empty, short, maximum, and immediately adjacent lengths.
fn info_len(value: u16) -> usize {
    match value % 5 {
        0 => 0,
        1 => 1,
        2 => CONCAT_INFO_MAX_LEN - 1,
        3 => CONCAT_INFO_MAX_LEN,
        _ => usize::from(value) % (CONCAT_INFO_MAX_LEN + 1),
    }
}

/// Select all fixed and variable output types with legal initial lengths.
fn valid_target(input: &FuzzInput<'_>) -> (u8, u8) {
    let types = [
        KDF_KEY_TYPE_AES128,
        KDF_KEY_TYPE_AES192,
        KDF_KEY_TYPE_AES256,
        KDF_KEY_TYPE_HMAC_SHA256,
        KDF_KEY_TYPE_HMAC_SHA384,
        KDF_KEY_TYPE_HMAC_SHA512,
        KDF_KEY_TYPE_VAR_HMAC256,
        KDF_KEY_TYPE_VAR_HMAC384,
        KDF_KEY_TYPE_VAR_HMAC512,
    ];
    let key_type = types[usize::from(input.key_type) % types.len()];
    let length = match key_type {
        KDF_KEY_TYPE_VAR_HMAC256 => 32 + input.key_length % 33,
        KDF_KEY_TYPE_VAR_HMAC384 => 48 + input.key_length % 81,
        KDF_KEY_TYPE_VAR_HMAC512 => 64 + input.key_length % 65,
        _ => input.key_length,
    };
    (key_type, length)
}

/// Independently model the output length and variable-HMAC validation contract.
fn output_len(key_type: u8, length: u8) -> Result<usize, TborStatus> {
    let (min, max) = match key_type {
        KDF_KEY_TYPE_AES128 => return Ok(16),
        KDF_KEY_TYPE_AES192 => return Ok(24),
        KDF_KEY_TYPE_AES256 | KDF_KEY_TYPE_HMAC_SHA256 => return Ok(32),
        KDF_KEY_TYPE_HMAC_SHA384 => return Ok(48),
        KDF_KEY_TYPE_HMAC_SHA512 => return Ok(64),
        KDF_KEY_TYPE_VAR_HMAC256 => (32, 64),
        KDF_KEY_TYPE_VAR_HMAC384 => (48, 128),
        KDF_KEY_TYPE_VAR_HMAC512 => (64, 128),
        _ => return Err(TborStatus::InvalidKeyType),
    };
    if length == 0 {
        Err(TborStatus::InvalidKeyType)
    } else if !(min..=max).contains(&length) {
        Err(TborStatus::InvalidKeyLength)
    } else {
        Ok(usize::from(length))
    }
}

/// Generate authenticated IKM on the actual caller's session, or a correctly
/// sized authenticated P-256 private key for the non-secret rejection case.
fn make_secret(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    curve: common::EccCurve,
    non_secret: bool,
) -> Vec<u8> {
    let req = TborEccGenerateKeyReq {
        session_id,
        scope,
        curve: curve.to_tbor(),
        key_usage: KEY_USAGE_DERIVE,
        key_label: Vec::new(),
    };
    let a = ctx.tbor(&req).expect("valid ECC key generation");
    if non_secret {
        return a.masked_key;
    }
    let b = ctx.tbor(&req).expect("valid ECC peer key generation");
    let secret = ctx
        .tbor(&TborEcdhDeriveReq {
            session_id,
            scope,
            masked_key: a.masked_key,
            peer_pub_key: b.pub_key,
            key_label: Vec::new(),
        })
        .expect("valid ECDH secret derivation")
        .masked_secret;
    assert_eq!(secret.len(), MASK_OVERHEAD + curve.coord_len());
    secret
}

/// Reuse shared mutations while restricting flips to ciphertext so their
/// expected rejection is precise; classify effective no-ops before execution.
fn mutate_secret(input: &FuzzInput<'_>, secret: &mut Vec<u8>) -> Option<TborStatus> {
    let mutation = match input.mutation % 4 {
        0 => common::EnvelopeMutation::None,
        1 => common::EnvelopeMutation::FlipByte {
            offset: u16::try_from(
                CIPHERTEXT_OFFSET + usize::from(input.offset) % (secret.len() - MASK_OVERHEAD),
            )
            .expect("bounded ciphertext offset"),
            mask: input.mask,
        },
        2 => common::EnvelopeMutation::Truncate { len: input.offset },
        _ => common::EnvelopeMutation::Append(payload(input, usize::from(input.mask % 3))),
    };
    let noop = mutation.is_noop(secret);
    mutation.apply(secret);
    (!noop).then_some(TborStatus::AesGcmDecryptTagDoesNotMatch)
}

/// Predict the final request's outcome in backend/decoder/handler order.
/// All input masking keys were provisioned before generating the authentic IKM.
fn expected_outcome(
    req: &TborConcatKdfDeriveReq,
    session_id: u16,
    partition: Partition,
    secret_error: Option<TborStatus>,
) -> Result<usize, TborStatus> {
    if req.session_id != session_id {
        return Err(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    // Host derives do not enforce these bounds; firmware decode_mut does.
    if !(CONCAT_MASKED_SECRET_MIN_LEN..=CONCAT_MASKED_SECRET_MAX_LEN)
        .contains(&req.masked_secret.len())
        || req.info.len() > CONCAT_INFO_MAX_LEN
    {
        return Err(TborStatus::TborInvalidFixedLength);
    }
    if (req.scope != common::KEY_SCOPE_SESSION && partition == Partition::Cold)
        || !matches!(req.hash_algo, 1..=3)
        || !matches!(req.kdf_alg, CONCAT_KDF_ALG_X963 | CONCAT_KDF_ALG_SP800_56A)
    {
        return Err(TborStatus::InvalidArg);
    }
    let len = output_len(req.key_type, req.key_length)?;
    if let Some(status) = secret_error {
        return Err(status);
    }
    if !partition.supports(req.scope) {
        return Err(TborStatus::UnsupportedKeyScope);
    }
    Ok(len)
}

/// Accept only the predicted typed FW status or its numeric backend equivalent;
/// transport failures, malformed responses, and codec failures always panic.
fn assert_rejection(err: &DdiError, expected: TborStatus) {
    match err {
        DdiError::DdiError(code) => assert_eq!(*code, expected.0, "wrong backend status"),
        _ => assertions::assert_fw_rejects(err, expected),
    }
}

/// Run one bounded scenario with known fixture state and authenticated inputs.
fn run(input: &FuzzInput<'_>, ctx: &TestCtx) {
    let scenario = Scenario::from_byte(input.scenario);
    let partition = match scenario {
        Scenario::ColdScope => Partition::Cold,
        Scenario::MissingSd => Partition::Finalized,
        _ => Partition::from_byte(input.partition),
    };
    let co = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    match partition {
        Partition::Cold => {}
        Partition::Finalized => common::finalize_partition(ctx, &co),
        Partition::SecurityDomain => common::create_test_security_domain(ctx, &co),
    }
    let session = if input.cu {
        ctx.session_close(co.session_id)
            .expect("close setup CO session");
        bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK)
    } else {
        co
    };
    let curve = if scenario == Scenario::NonSecret {
        common::EccCurve::P256
    } else {
        [
            common::EccCurve::P256,
            common::EccCurve::P384,
            common::EccCurve::P521,
        ][usize::from(input.curve % 3)]
    };
    let (key_type, key_length) = valid_target(input);
    let mut req = TborConcatKdfDeriveReq {
        session_id: session.session_id,
        scope: partition.available_scope(input.scope),
        hash_algo: 1 + input.hash_algo % 3,
        kdf_alg: if input.kdf_alg % 2 == 0 {
            CONCAT_KDF_ALG_X963
        } else {
            CONCAT_KDF_ALG_SP800_56A
        },
        key_type,
        key_length,
        masked_secret: make_secret(
            ctx,
            session.session_id,
            partition.available_scope(input.source_scope),
            curve,
            scenario == Scenario::NonSecret,
        ),
        info: payload(input, info_len(input.info_length)),
    };
    let mut secret_error = None;
    match scenario {
        Scenario::Valid => {}
        Scenario::Session => {
            req.session_id = if input.session_id == session.session_id {
                input.session_id.wrapping_add(1)
            } else {
                input.session_id
            };
        }
        Scenario::Hash => {
            req.hash_algo = if matches!(input.hash_algo, 1..=3) {
                0
            } else {
                input.hash_algo
            };
        }
        Scenario::Algorithm => {
            req.kdf_alg = if matches!(input.kdf_alg, 1..=2) {
                0
            } else {
                input.kdf_alg
            };
        }
        Scenario::KeyType => {
            req.key_type = if output_len(input.key_type, 64).is_ok() {
                0
            } else {
                input.key_type
            };
        }
        Scenario::MissingLength
        | Scenario::BelowLength
        | Scenario::AboveLength
        | Scenario::RawLength => {
            let (kind, min, max) = [
                (KDF_KEY_TYPE_VAR_HMAC256, 32, 64),
                (KDF_KEY_TYPE_VAR_HMAC384, 48, 128),
                (KDF_KEY_TYPE_VAR_HMAC512, 64, 128),
            ][usize::from(input.key_type % 3)];
            req.key_type = kind;
            req.key_length = match scenario {
                Scenario::MissingLength => 0,
                Scenario::BelowLength => min - 1,
                Scenario::AboveLength => max + 1,
                _ => input.key_length,
            };
        }
        Scenario::Scope => req.scope = input.scope,
        Scenario::ColdScope => req.scope = common::KEY_SCOPE_LOCAL,
        Scenario::MissingSd => req.scope = common::KEY_SCOPE_SECURITY_DOMAIN,
        Scenario::NonSecret => secret_error = Some(TborStatus::InvalidKeyType),
        Scenario::Header => {
            req.masked_secret[0] ^= input.mask.max(1);
            secret_error = Some(TborStatus::InvalidArg);
        }
        Scenario::Metadata => {
            req.masked_secret[METADATA_OFFSET] ^= input.mask.max(1);
            secret_error = Some(TborStatus::MaskedKeyDecodeFailed);
        }
        Scenario::Ciphertext => {
            let offset = CIPHERTEXT_OFFSET + usize::from(input.offset) % curve.coord_len();
            req.masked_secret[offset] ^= input.mask.max(1);
            secret_error = Some(TborStatus::AesGcmDecryptTagDoesNotMatch);
        }
        Scenario::Tag => {
            *req.masked_secret
                .last_mut()
                .expect("generated secret has a tag") ^= input.mask.max(1);
            secret_error = Some(TborStatus::AesGcmDecryptTagDoesNotMatch);
        }
        Scenario::Mutation => secret_error = mutate_secret(input, &mut req.masked_secret),
        Scenario::RawSecret => {
            let len = secret_boundary(input.offset);
            req.masked_secret = payload(input, len);
            if let Some(first) = req.masked_secret.first_mut() {
                *first = 0; // Never a valid AEAD magic, regardless of payload.
            }
            secret_error = Some(TborStatus::InvalidArg);
        }
        Scenario::SecretLength => {
            let len = secret_boundary(input.offset);
            if len != req.masked_secret.len() {
                req.masked_secret.resize(len, input.mask);
                secret_error = Some(TborStatus::AesGcmDecryptTagDoesNotMatch);
            }
        }
        Scenario::InfoLength => {
            req.info = payload(
                input,
                CONCAT_INFO_MAX_LEN + 1 + usize::from(input.info_length % 16),
            );
        }
        Scenario::Combined => {
            req.session_id = input.session_id;
            req.scope = input.scope;
            req.hash_algo = input.hash_algo;
            req.kdf_alg = input.kdf_alg;
            req.key_type = input.key_type;
            req.key_length = input.key_length;
            req.info = payload(
                input,
                usize::from(input.info_length) % (CONCAT_INFO_MAX_LEN + 2),
            );
            secret_error = mutate_secret(input, &mut req.masked_secret);
        }
    }

    let expected = expected_outcome(&req, session.session_id, partition, secret_error);
    match (ctx.tbor(&req), expected) {
        (Ok(resp), Ok(len)) => {
            assert_eq!(resp.masked_key.len(), MASK_OVERHEAD + len);
            assert!(resp.masked_key.len() <= CONCAT_MASKED_KEY_MAX_LEN);
        }
        (Err(err), Err(status)) => assert_rejection(&err, status),
        (Ok(_), Err(status)) => {
            panic!("{scenario:?}: invalid request succeeded; expected {status:?}")
        }
        (Err(err), Ok(_)) => panic!("{scenario:?}: valid request failed: {err:?}"),
    }
    ctx.session_close(session.session_id)
        .expect("close caller session");
}

/// Cover exact curve envelope lengths and both wire-limit neighbors.
fn secret_boundary(value: u16) -> usize {
    [
        0,
        CONCAT_MASKED_SECRET_MIN_LEN - 1,
        CONCAT_MASKED_SECRET_MIN_LEN,
        MASK_OVERHEAD + common::EccCurve::P384.coord_len(),
        CONCAT_MASKED_SECRET_MAX_LEN,
        CONCAT_MASKED_SECRET_MAX_LEN + 1,
    ][usize::from(value % 6)]
}

fuzz_target!(|input: FuzzInput<'_>| {
    common::common_fuzz_test(&|ctx, _path| run(&input, ctx));
});

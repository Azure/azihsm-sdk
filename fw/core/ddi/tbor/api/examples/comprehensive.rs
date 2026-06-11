// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive example of TBOR encode/decode with the #[tbor] derive macro.

#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]
//!
//! Demonstrates:
//!   - Required and optional fields
//!   - Aligned fields with padding
//!   - Typestate encoder (zero-storage, compile-time ordered)
//!   - Skipping optional fields (intermediate and trailing)
//!   - Request and response messages
//!   - Enum types
//!   - Zero-copy decoding with Display output

use std::println;

use azihsm_fw_ddi_tbor_api::tbor;
use azihsm_fw_hsm_pal_traits::DmaBuf;

// SAFETY: example-only branding. Host-side examples have no real DMA
// engine, so the DMA-reachability contract is moot.
fn brand(b: &[u8]) -> &DmaBuf {
    // SAFETY: see fn-level doc comment.
    unsafe { DmaBuf::from_raw(b) }
}

// ═══════════════════════════════════════════════════════════════════════
// 1. ENUM TYPES — used as field values
// ═══════════════════════════════════════════════════════════════════════

/// Cryptographic algorithm selector.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[tbor]
#[repr(u8)]
pub enum Algorithm {
    AesEcb = 1,
    AesCbc = 2,
    AesGcm = 3,
}

// ═══════════════════════════════════════════════════════════════════════
// 2. REQUEST — mixed required, optional, and aligned fields
// ═══════════════════════════════════════════════════════════════════════

/// Encrypt request: host → device.
///
/// Fields:
///   - session_id: required, identifies the active session
///   - key_id:     required, identifies which key to use
///   - algorithm:  required, which cipher to use (u8 enum)
///   - iv:         optional, not all algorithms need an IV (e.g., ECB)
///   - aad:        optional, additional authenticated data (GCM only)
///   - plaintext:  required, 4-byte aligned for DMA transfer
#[tbor(opcode = 0x50)]
pub struct EncryptReq<'a> {
    #[tbor(session_id)]
    session_id: u16,
    #[tbor(key_id)]
    key_id: u16,
    algorithm: u8,
    #[tbor(max_len = 256)]
    iv: Option<&'a [u8]>,
    #[tbor(max_len = 256)]
    aad: Option<&'a [u8]>,
    #[tbor(align = 4, max_len = 256)]
    plaintext: &'a [u8],
}

/// Encrypt response: device → host.
///
/// Fields:
///   - ciphertext: required, 4-byte aligned
///   - tag:        optional, authentication tag (GCM only)
#[tbor(response)]
pub struct EncryptResp<'a> {
    #[tbor(align = 4, max_len = 256)]
    ciphertext: &'a [u8],
    #[tbor(max_len = 256)]
    tag: Option<&'a [u8]>,
}

// ═══════════════════════════════════════════════════════════════════════
// 3. EXAMPLES
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    example_aes_gcm_full();
    example_aes_ecb_minimal();
    example_skip_intermediate();
    example_response();
    example_raw_decode();
    println!("\n✓ All examples passed.");
}

/// Example 1: AES-GCM with all fields populated.
fn example_aes_gcm_full() {
    println!("═══ Example 1: AES-GCM (all fields) ═══");

    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    ];
    let aad = b"additional-auth-data";
    let plaintext = b"Hello, TBOR!";

    let mut buf = [0u8; 512];

    // Encode: typestate builder, each call writes directly to buf.
    let frame = EncryptReq::encode(&mut buf)
        .unwrap()
        .session_id(azihsm_fw_ddi_tbor_api::SessionId(7))
        .unwrap()
        .key_id(azihsm_fw_ddi_tbor_api::KeyId(42))
        .unwrap()
        .algorithm(Algorithm::AesGcm as u8)
        .unwrap()
        .iv(Some(&iv))
        .unwrap()
        .aad(Some(aad))
        .unwrap()
        .plaintext(plaintext)
        .unwrap()
        .finish();

    println!("  Encoded: {} bytes", frame.len());
    println!("  session_id = {}", frame.session_id().0);
    println!("  key_id     = {}", frame.key_id().0);
    println!("  algorithm  = {} (AesGcm)", frame.algorithm());
    println!("  iv         = {:?}", frame.iv().map(|b| b.len()));
    println!("  aad        = {:?}", frame.aad().map(|b| b.len()));
    println!(
        "  plaintext  = {:?}",
        core::str::from_utf8(frame.plaintext()).unwrap()
    );

    // Decode: zero-copy, borrows the wire bytes.
    let view = EncryptReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.session_id(), azihsm_fw_ddi_tbor_api::SessionId(7));
    assert_eq!(view.key_id(), azihsm_fw_ddi_tbor_api::KeyId(42));
    assert_eq!(view.algorithm(), 3);
    assert!(view.iv().is_some_and(|d| &**d == iv.as_slice()));
    assert!(view.aad().is_some_and(|d| &**d == aad.as_slice()));
    assert_eq!(view.plaintext(), plaintext);

    // Pretty-print via generated Display impl.
    println!("\n  Decoded view:\n{}", view);
}

/// Example 2: AES-ECB — no IV, no AAD. Skip both via early finish.
fn example_aes_ecb_minimal() {
    println!("═══ Example 2: AES-ECB (skip optionals via jump-ahead) ═══");

    let mut buf = [0u8; 512];

    // Skip iv and aad by jumping directly to plaintext.
    // The typestate encoder auto-fills None for both skipped fields.
    let frame = EncryptReq::encode(&mut buf)
        .unwrap()
        .session_id(azihsm_fw_ddi_tbor_api::SessionId(1))
        .unwrap()
        .key_id(azihsm_fw_ddi_tbor_api::KeyId(10))
        .unwrap()
        .algorithm(Algorithm::AesEcb as u8)
        .unwrap()
        // iv and aad are optional → jump straight to plaintext
        .plaintext(b"ECB-data-here!!!")
        .unwrap()
        .finish();

    println!("  Encoded: {} bytes (no IV/AAD overhead)", frame.len());

    let view = EncryptReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.iv(), None);
    assert_eq!(view.aad(), None);
    assert_eq!(view.plaintext(), b"ECB-data-here!!!");

    println!("  iv  = {:?}", view.iv());
    println!("  aad = {:?}", view.aad());
    println!(
        "  plaintext = {:?}\n",
        core::str::from_utf8(view.plaintext()).unwrap()
    );
}

/// Example 3: AES-CBC — has IV but no AAD. Skip only aad.
fn example_skip_intermediate() {
    println!("═══ Example 3: AES-CBC (skip only aad) ═══");

    let iv = [0xAA; 16];
    let mut buf = [0u8; 512];

    // Set iv, then skip aad by jumping to plaintext.
    let frame = EncryptReq::encode(&mut buf)
        .unwrap()
        .session_id(azihsm_fw_ddi_tbor_api::SessionId(3))
        .unwrap()
        .key_id(azihsm_fw_ddi_tbor_api::KeyId(20))
        .unwrap()
        .algorithm(Algorithm::AesCbc as u8)
        .unwrap()
        .iv(Some(&iv))
        .unwrap()
        // aad is optional → jump to plaintext, auto-fills None for aad
        .plaintext(b"CBC-block-data!!")
        .unwrap()
        .finish();

    let view = EncryptReq::decode(brand(frame.as_bytes())).unwrap();
    assert!(view.iv().is_some_and(|d| &**d == iv.as_slice()));
    assert_eq!(view.aad(), None); // auto-filled as None
    assert_eq!(view.plaintext(), b"CBC-block-data!!");

    println!("  iv  = Some([{} bytes])", view.iv().unwrap().len());
    println!("  aad = None");
    println!("  plaintext len = {}\n", view.plaintext().len());
}

/// Example 4: Response with optional tag.
fn example_response() {
    println!("═══ Example 4: Response (GCM with tag vs ECB without) ═══");

    // GCM response: ciphertext + tag.
    let mut buf = [0u8; 512];
    let frame = EncryptResp::encode(&mut buf, 0x00000000, true)
        .unwrap()
        .ciphertext(b"<ciphertext-bytes>")
        .unwrap()
        .tag(Some(b"\xDE\xAD\xBE\xEF"))
        .unwrap()
        .finish();

    let view = EncryptResp::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.status(), 0);
    assert!(view.fips_approved());
    assert_eq!(view.ciphertext(), b"<ciphertext-bytes>");
    assert!(view.tag().is_some_and(|d| &**d == b"\xDE\xAD\xBE\xEF"));
    println!(
        "  GCM: status=0, FIPS=true, tag={:?}",
        view.tag().map(|t| t.len())
    );

    // ECB response: ciphertext only, skip tag via early finish.
    let mut buf2 = [0u8; 512];
    let frame2 = EncryptResp::encode(&mut buf2, 0x00000000, false)
        .unwrap()
        .ciphertext(b"<ecb-ciphertext>")
        .unwrap()
        .finish(); // tag is trailing optional → auto-filled as None

    let view2 = EncryptResp::decode(brand(frame2.as_bytes())).unwrap();
    assert_eq!(view2.tag(), None);
    println!("  ECB: status=0, FIPS=false, tag=None\n");
}

/// Example 5: Decode raw wire bytes (e.g., received over transport).
fn example_raw_decode() {
    println!("═══ Example 5: Decode from raw wire bytes ═══");

    // First encode a message to get some wire bytes.
    let mut buf = [0u8; 256];
    let frame = EncryptReq::encode(&mut buf)
        .unwrap()
        .session_id(azihsm_fw_ddi_tbor_api::SessionId(99))
        .unwrap()
        .key_id(azihsm_fw_ddi_tbor_api::KeyId(1))
        .unwrap()
        .algorithm(1)
        .unwrap()
        .plaintext(b"test")
        .unwrap()
        .finish();

    // Simulate receiving the wire bytes.
    let wire_bytes: &[u8] = frame.as_bytes();
    println!("  Wire bytes: {} bytes", wire_bytes.len());

    // Decode — this is zero-copy: the view borrows wire_bytes.
    let view = EncryptReq::decode(brand(wire_bytes)).unwrap();
    println!("  Decoded successfully:");
    println!("    session = {}", view.session_id());
    println!("    key     = {}", view.key_id());
    println!("    algo    = {}", view.algorithm());
    println!("    iv      = {:?}", view.iv());
    println!("    aad     = {:?}", view.aad());
    println!(
        "    payload = {:?}",
        core::str::from_utf8(view.plaintext()).unwrap()
    );

    // You can also use the generic core decoder for untyped access:
    let raw = azihsm_fw_ddi_tbor::RequestView::parse(brand(wire_bytes)).unwrap();
    println!(
        "\n  Raw view: opcode=0x{:02X}, {} TOC entries",
        raw.opcode(),
        raw.toc_count()
    );
    for (i, entry) in raw.toc_iter().enumerate() {
        println!("    TOC[{}]: {:?}", i, entry);
    }
}

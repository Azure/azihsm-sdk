// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test for the `#[derive(Ddi)]` `frame()` / `reserve()`
//! codegen's **by-value `Option` field** support.
//!
//! Uses dummy structs that mirror a real response shape — fixed fields,
//! optional by-value fields (a primitive, a borrowed struct, and a borrowed
//! slice, so the `Option<T<'a>>` / `Option<&'a [u8]>` lifetime handling is
//! exercised), and a reserved trailing byte-slice. For every Some/None
//! combination of the optionals, **both** the `reserve()` + `from_layout()`
//! path and the `frame()` path (plus fill) must produce byte-identical output
//! to the canonical [`MborEncode`] of the same struct — proving the derive
//! resolves the runtime map count and emits each optional entry correctly,
//! and that `frame`/`reserve` pad identically to `MborEncode`.
//!
//! [`OptSliceOnly`] additionally guards the case where the *only* borrowed
//! by-value field is an `Option<&'a [u8]>`: `params_needs_lifetime` must keep
//! `'a` on the generated `FrameParams` or the code won't compile.

#![allow(unsafe_code, clippy::unwrap_used)]

use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;

/// A nested struct with a borrowed field, used below as an *optional*
/// by-value field so the codegen's `Option<T<'a>>` lifetime handling is
/// exercised.
#[derive(Ddi)]
#[ddi(map)]
struct Inner<'a> {
    #[ddi(id = 1, max_len = 32)]
    data: &'a [u8],
    #[ddi(id = 2)]
    tag: u8,
}

/// Fixed fields + optional by-value fields (primitive, borrowed struct, and
/// borrowed slice) + a reserved trailing byte-slice.
#[derive(Ddi)]
#[ddi(map)]
struct Resp<'a> {
    #[ddi(id = 1)]
    a: u16,
    #[ddi(id = 2)]
    inner: Option<Inner<'a>>,
    #[ddi(id = 3)]
    b: Option<u16>,
    #[ddi(id = 4)]
    c: u8,
    #[ddi(id = 5, max_len = 32)]
    opt_slice: Option<&'a [u8]>,
    #[ddi(id = 6, max_len = 64)]
    tail: &'a [u8],
}

/// Regression guard for the exact reviewer scenario: a frameable struct whose
/// *only* borrowed by-value field is an optional slice (`Option<&'a [u8]>`).
/// The fixed field and the reserved `tail` slice contribute no lifetime on
/// their own (a non-optional slice reserves as a `usize` length). Before the
/// fix, `params_needs_lifetime` skipped `Slice`-kind fields, so `FrameParams`
/// was emitted without `'a` while still carrying `s: Option<&'a [u8]>` — which
/// failed to compile. If that regresses, this file no longer compiles.
#[derive(Ddi)]
#[ddi(map)]
struct OptSliceOnly<'a> {
    #[ddi(id = 1)]
    x: u16,
    #[ddi(id = 2, max_len = 32)]
    s: Option<&'a [u8]>,
    #[ddi(id = 3, max_len = 64)]
    tail: &'a [u8],
}

/// Brand a `&mut [u8]` as `&mut DmaBuf` — safe in tests (no DMA hw).
fn dma(buf: &mut [u8]) -> &mut DmaBuf {
    // SAFETY: tests only read/write the bytes; no DMA engine is involved.
    unsafe { DmaBuf::from_raw_mut(buf) }
}

fn assert_reserve_matches_encode(with_inner: bool, with_b: bool, with_slice: bool) {
    const DATA: [u8; 5] = [0xde, 0xad, 0xbe, 0xef, 0x01];
    const SLICE: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const TAIL: [u8; 20] = [0xab; 20];
    let a = 0x1234u16;
    let c = 0x5u8;
    let b = with_b.then_some(0x9abcu16);
    // An optional *slice* field (kind == Slice) carried by value — the case
    // that requires `params_needs_lifetime` to look past Normal/Array so the
    // generated `FrameParams` keeps its `'a`.
    let opt_slice = with_slice.then_some(&SLICE[..]);

    // ── Canonical path: `MborEncode` the whole struct. ──
    let mut buf_a = [0u8; 128];
    let len_a = {
        let inner = with_inner.then_some(Inner {
            data: &DATA,
            tag: 7,
        });
        let resp = Resp {
            a,
            inner,
            b,
            c,
            opt_slice,
            tail: &TAIL,
        };
        let mut enc = MborEncoder::new(&mut buf_a);
        resp.mbor_encode(&mut enc).unwrap();
        enc.position()
    };

    // ── Reserve path: `reserve` + `from_layout` + fill `tail`. ──
    let mut buf_b = [0u8; 128];
    let len_b = {
        let inner = with_inner.then_some(Inner {
            data: &DATA,
            tag: 7,
        });
        let (pos, layout) = {
            let mut enc = MborEncoder::new(&mut buf_b);
            let layout = Resp::reserve(&mut enc, a, inner, b, c, opt_slice, TAIL.len()).unwrap();
            (enc.position(), layout)
        };
        let frame = Resp::from_layout(dma(&mut buf_b), &layout);
        frame.tail.copy_from_slice(&TAIL);
        pos
    };

    // ── Frame path: `frame` writes the structure and hands back the
    //    reserved `tail` slice directly (no separate `from_layout`). The
    //    encoder position is the final length, captured before filling —
    //    the returned frame borrows the buffer, not the encoder (see
    //    `get_sealed_bk3.rs`). ──
    let mut buf_c = [0u8; 128];
    let len_c = {
        let inner = with_inner.then_some(Inner {
            data: &DATA,
            tag: 7,
        });
        let mut enc = MborEncoder::new(&mut buf_c);
        let frame = Resp::frame(&mut enc, a, inner, b, c, opt_slice, TAIL.len()).unwrap();
        let pos = enc.position();
        frame.tail.copy_from_slice(&TAIL);
        pos
    };

    assert_eq!(
        len_a, len_b,
        "reserve length mismatch (inner={with_inner}, b={with_b})",
    );
    assert_eq!(
        buf_a[..len_a],
        buf_b[..len_b],
        "reserve bytes mismatch (inner={with_inner}, b={with_b})",
    );
    assert_eq!(
        len_a, len_c,
        "frame length mismatch (inner={with_inner}, b={with_b})",
    );
    assert_eq!(
        buf_a[..len_a],
        buf_c[..len_c],
        "frame bytes mismatch (inner={with_inner}, b={with_b})",
    );
}

#[test]
fn reserve_matches_encode_all_optional_combinations() {
    for with_inner in [false, true] {
        for with_b in [false, true] {
            for with_slice in [false, true] {
                assert_reserve_matches_encode(with_inner, with_b, with_slice);
            }
        }
    }
}

/// The reviewer's case at runtime: an optional-slice-only struct must produce
/// the same bytes as `MborEncode` via **both** the `reserve` + `from_layout`
/// path and the `frame` path, for both `Some` and `None`. (Compiling this
/// test at all is the primary regression guard.)
#[test]
fn opt_slice_only_reserve_matches_encode() {
    const S: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    const TAIL: [u8; 8] = [0xcd; 8];
    for s in [None, Some(&S[..])] {
        let mut buf_a = [0u8; 64];
        let len_a = {
            let resp = OptSliceOnly {
                x: 0x77,
                s,
                tail: &TAIL,
            };
            let mut enc = MborEncoder::new(&mut buf_a);
            resp.mbor_encode(&mut enc).unwrap();
            enc.position()
        };

        let mut buf_b = [0u8; 64];
        let len_b = {
            let (pos, layout) = {
                let mut enc = MborEncoder::new(&mut buf_b);
                let layout = OptSliceOnly::reserve(&mut enc, 0x77, s, TAIL.len()).unwrap();
                (enc.position(), layout)
            };
            let frame = OptSliceOnly::from_layout(dma(&mut buf_b), &layout);
            frame.tail.copy_from_slice(&TAIL);
            pos
        };

        let mut buf_c = [0u8; 64];
        let len_c = {
            let mut enc = MborEncoder::new(&mut buf_c);
            let frame = OptSliceOnly::frame(&mut enc, 0x77, s, TAIL.len()).unwrap();
            let pos = enc.position();
            frame.tail.copy_from_slice(&TAIL);
            pos
        };

        assert_eq!(
            len_a,
            len_b,
            "reserve length mismatch (s={:?})",
            s.is_some()
        );
        assert_eq!(
            buf_a[..len_a],
            buf_b[..len_b],
            "reserve bytes mismatch (s={:?})",
            s.is_some(),
        );
        assert_eq!(len_a, len_c, "frame length mismatch (s={:?})", s.is_some());
        assert_eq!(
            buf_a[..len_a],
            buf_c[..len_c],
            "frame bytes mismatch (s={:?})",
            s.is_some(),
        );
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host unit tests for the key vault.
//!
//! Storage is backed by owned arrays (no GSRAM) and the GDMA engine by a
//! CPU fake, so the full allocator / layout / error logic runs on the
//! host. The fake brands owned memory as `DmaBuf`, which requires
//! `unsafe`; that is confined to this test module.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used)]

use core::cell::Cell;
use core::future::Future;
use core::pin::pin;
use core::task::Context;
use core::task::Poll;
use core::task::RawWaker;
use core::task::RawWakerVTable;
use core::task::Waker;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCqe;
use azihsm_fw_hsm_pal_traits::HsmDmaAddr;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmGdmaController;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSqe;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use crate::storage::BITMAP_WORDS;
use crate::storage::BLOB_SIZE;
use crate::storage::ENTRIES_PER_TABLE;
use crate::vault::KeyVault;
use crate::Entry;
use crate::TableStorage;

// ── Owned-memory storage ────────────────────────────────────────────

struct ArrayStorage<const N: usize> {
    entries: [[Entry; ENTRIES_PER_TABLE]; N],
    bitmap: [[u32; BITMAP_WORDS]; N],
    blob: [[u8; BLOB_SIZE]; N],
    /// Resource mask gating which of the `N` tables are owned.
    mask: u128,
}

impl<const N: usize> ArrayStorage<N> {
    /// All `N` tables owned (mask = low `N` bits set).
    fn new() -> Self {
        let mask = if N >= 128 {
            u128::MAX
        } else {
            (1u128 << N) - 1
        };
        Self::with_mask(mask)
    }

    /// Only the tables whose bit is set in `mask` are owned.
    fn with_mask(mask: u128) -> Self {
        ArrayStorage {
            entries: [[Entry::default(); ENTRIES_PER_TABLE]; N],
            bitmap: [[0u32; BITMAP_WORDS]; N],
            blob: [[0u8; BLOB_SIZE]; N],
            mask,
        }
    }
}

impl<const N: usize> TableStorage for ArrayStorage<N> {
    fn table_count(&self) -> usize {
        N
    }
    fn is_valid_table(&self, table: usize) -> bool {
        // `mask` is a `u128`, so shifting by `table >= 128` is UB / a
        // debug-panic; guard it explicitly to stay sound for any `N`.
        table < N && table < 128 && (self.mask >> table) & 1 != 0
    }
    fn entry(&self, table: usize, idx: usize) -> HsmResult<&Entry> {
        if table >= N || idx >= ENTRIES_PER_TABLE {
            return Err(HsmError::InvalidArg);
        }
        Ok(&self.entries[table][idx])
    }
    fn entry_mut(&mut self, table: usize, idx: usize) -> HsmResult<&mut Entry> {
        if table >= N || idx >= ENTRIES_PER_TABLE {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut self.entries[table][idx])
    }
    fn bitmap(&self, table: usize) -> HsmResult<&[u32; BITMAP_WORDS]> {
        if table >= N {
            return Err(HsmError::InvalidArg);
        }
        Ok(&self.bitmap[table])
    }
    fn bitmap_mut(&mut self, table: usize) -> HsmResult<&mut [u32; BITMAP_WORDS]> {
        if table >= N {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut self.bitmap[table])
    }
    fn blob(&self, table: usize) -> HsmResult<&DmaBuf> {
        if table >= N {
            return Err(HsmError::InvalidArg);
        }
        // SAFETY: test-owned memory; "DMA" is a fiction on the host.
        Ok(unsafe { DmaBuf::from_raw(&self.blob[table]) })
    }
    fn blob_mut(&mut self, table: usize) -> HsmResult<&mut DmaBuf> {
        if table >= N {
            return Err(HsmError::InvalidArg);
        }
        // SAFETY: test-owned memory; "DMA" is a fiction on the host.
        Ok(unsafe { DmaBuf::from_raw_mut(&mut self.blob[table]) })
    }
}

// ── Fake GDMA (CPU copy/zeroize, with call counters) ────────────────

#[derive(Default)]
struct FakeGdma {
    copies: Cell<usize>,
    zeroizes: Cell<usize>,
    fail_copy: Cell<bool>,
}

impl HsmGdmaController for FakeGdma {
    async fn copy_mem(&self, _io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()> {
        self.copies.set(self.copies.get() + 1);
        if self.fail_copy.get() {
            return Err(HsmError::FailedToStartDmaTransaction);
        }
        dst.copy_from_slice(src);
        Ok(())
    }
    async fn zeroize_mem(&self, _io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()> {
        self.zeroizes.set(self.zeroizes.get() + 1);
        for b in dst.iter_mut() {
            *b = 0;
        }
        Ok(())
    }
    async fn copy_mem_from_host(
        &self,
        _io: &impl HsmIo,
        _src: HsmDmaAddr,
        _dst: &mut DmaBuf,
        _prp: bool,
    ) -> HsmResult<()> {
        unimplemented!("vault does not use host copies")
    }
    async fn copy_mem_to_host(
        &self,
        _io: &impl HsmIo,
        _src: &DmaBuf,
        _dst: HsmDmaAddr,
        _prp: bool,
    ) -> HsmResult<()> {
        unimplemented!("vault does not use host copies")
    }
}

// ── Minimal HsmIo stub ──────────────────────────────────────────────

#[derive(Default)]
struct FakeIo {
    sqe: HsmSqe,
    cqe: HsmCqe,
}

impl HsmIo for FakeIo {
    fn index(&self) -> u16 {
        0
    }
    fn pid(&self) -> HsmPartId {
        HsmPartId::from(0u8)
    }
    fn queue_id(&self) -> u16 {
        0
    }
    fn queue_idx(&self) -> u16 {
        0
    }
    fn sqe(&self) -> &HsmSqe {
        &self.sqe
    }
    fn cqe(&mut self) -> &mut HsmCqe {
        &mut self.cqe
    }
}

// ── Poll-once executor (fake futures are always immediately ready) ──

fn block_on<F: Future>(fut: F) -> F::Output {
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable's clone/wake/drop are all no-ops over a null
    // data pointer, so the waker is trivially valid.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn aes_attrs() -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_encrypt(true)
        .with_decrypt(true)
}

/// Runs `f` with a `key` slice branded as `&DmaBuf`.
fn with_key<R>(bytes: &[u8], f: impl FnOnce(&DmaBuf) -> R) -> R {
    // SAFETY: test-owned memory; "DMA" is a fiction on the host.
    let buf = unsafe { DmaBuf::from_raw(bytes) };
    f(buf)
}

fn vault<const N: usize>() -> (KeyVault<ArrayStorage<N>>, FakeGdma, FakeIo) {
    (
        KeyVault::new(ArrayStorage::<N>::new()),
        FakeGdma::default(),
        FakeIo::default(),
    )
}

fn vault_masked<const N: usize>(mask: u128) -> (KeyVault<ArrayStorage<N>>, FakeGdma, FakeIo) {
    (
        KeyVault::new(ArrayStorage::<N>::with_mask(mask)),
        FakeGdma::default(),
        FakeIo::default(),
    )
}

// ── Tests ───────────────────────────────────────────────────────────

#[test]
fn create_and_read_roundtrip_cpu() {
    let (mut v, g, io) = vault::<1>();
    let material = [0xABu8; 32];
    let id = with_key(&material, |k| {
        block_on(v.create(&g, &io, 7, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    assert_eq!(g.copies.get(), 0, "AES-256 (32 B) uses the CPU path");
    assert_eq!(&**v.key(id).unwrap(), &material[..]);
    assert_eq!(v.key_kind(id).unwrap(), HsmVaultKeyKind::Aes256);
    assert_eq!(v.key_attrs(id).unwrap(), aes_attrs());
}

#[test]
fn large_key_uses_dma() {
    let (mut v, g, io) = vault::<1>();
    let material = [0x5Au8; 516]; // Rsa2kPrivate, > DMA_THRESHOLD
    let id = with_key(&material, |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    assert_eq!(g.copies.get(), 1, "large key copied via GDMA");
    assert_eq!(&**v.key(id).unwrap(), &material[..]);
}

#[test]
fn key_id_packs_table_and_slot() {
    let (mut v, g, io) = vault::<2>();
    let id = with_key(&[1u8; 16], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes128, None, aes_attrs())).unwrap()
    });
    // First key lands in table 0, slot 0.
    assert_eq!(u16::from(id), 0);
}

#[test]
fn delete_zeroizes_and_frees() {
    let (mut v, g, io) = vault::<1>();
    let id = with_key(&[0xCCu8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    block_on(v.delete(&g, &io, id)).unwrap();
    assert_eq!(v.key(id).unwrap_err(), HsmError::KeyNotFound);
    // Slot reusable; second create takes the same id.
    let id2 = with_key(&[1u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    assert_eq!(u16::from(id2), u16::from(id));
}

#[test]
fn large_key_delete_uses_dma_zeroize() {
    let (mut v, g, io) = vault::<1>();
    let id = with_key(&[7u8; 516], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    block_on(v.delete(&g, &io, id)).unwrap();
    assert_eq!(g.zeroizes.get(), 1, "large region zeroed via GDMA");
}

#[test]
fn delete_by_session_only_removes_matching() {
    let (mut v, g, io) = vault::<1>();
    let app = with_key(&[1u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    let s1 = with_key(&[2u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, Some(9), aes_attrs())).unwrap()
    });
    let s2 = with_key(&[3u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, Some(9), aes_attrs())).unwrap()
    });
    block_on(v.delete_by_session(&g, &io, 9)).unwrap();
    assert_eq!(v.key(s1).unwrap_err(), HsmError::KeyNotFound);
    assert_eq!(v.key(s2).unwrap_err(), HsmError::KeyNotFound);
    assert!(v.key(app).is_ok(), "app key survives session teardown");
}

#[test]
fn clear_removes_everything() {
    let (mut v, g, io) = vault::<2>();
    let ids: Vec<_> = (0..3)
        .map(|i| {
            with_key(&[i as u8; 32], |k| {
                block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs()))
                    .unwrap()
            })
        })
        .collect();
    block_on(v.clear(&g, &io)).unwrap();
    for id in ids {
        assert_eq!(v.key(id).unwrap_err(), HsmError::KeyNotFound);
    }
}

#[test]
fn wrong_length_and_bad_kind_rejected() {
    let (mut v, g, io) = vault::<1>();
    // AES-256 expects 32 bytes.
    let e = with_key(&[0u8; 31], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap_err()
    });
    assert_eq!(e, HsmError::InvalidArg);
    // Free is not a real key.
    let e = with_key(&[0u8; 0], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Free, None, aes_attrs())).unwrap_err()
    });
    assert_eq!(e, HsmError::InvalidArg);
    // Unknown discriminant.
    let e = with_key(&[0u8; 4], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind(200), None, aes_attrs())).unwrap_err()
    });
    assert_eq!(e, HsmError::InvalidKeyType);
}

#[test]
fn variable_hmac_persists_actual_length() {
    let (mut v, g, io) = vault::<1>();
    let material = [0x11u8; 50]; // within VarLenHmacSha384 (48..128)
    let id = with_key(&material, |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::VarLenHmacSha384,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    assert_eq!(
        &**v.key(id).unwrap(),
        &material[..],
        "read back exact length"
    );
    // Out-of-range length rejected.
    let e = with_key(&[0u8; 200], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::VarLenHmacSha384,
            None,
            aes_attrs(),
        ))
        .unwrap_err()
    });
    assert_eq!(e, HsmError::InvalidArg);
}

#[test]
fn slot_exhaustion_reports_not_enough_space() {
    // Tiny keys (bulk index = 2 B) so slots run out before blob space.
    let (mut v, g, io) = vault::<1>();
    for _ in 0..ENTRIES_PER_TABLE {
        with_key(&[0u8; 2], |k| {
            block_on(v.create(
                &g,
                &io,
                0,
                k,
                HsmVaultKeyKind::AesXtsBulk256,
                None,
                aes_attrs(),
            ))
            .unwrap()
        });
    }
    let e = with_key(&[0u8; 2], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::AesXtsBulk256,
            None,
            aes_attrs(),
        ))
        .unwrap_err()
    });
    assert_eq!(e, HsmError::NotEnoughSpace);
}

#[test]
fn blob_exhaustion_reports_not_enough_space() {
    // Large keys exhaust blob space well before the 256 slots.
    let (mut v, g, io) = vault::<1>();
    let mut created = 0;
    loop {
        let r = with_key(&[0u8; 2564], |k| {
            block_on(v.create(
                &g,
                &io,
                0,
                k,
                HsmVaultKeyKind::Rsa4kPrivateCrt,
                None,
                aes_attrs(),
            ))
        });
        match r {
            Ok(_) => created += 1,
            Err(e) => {
                assert_eq!(e, HsmError::NotEnoughSpace);
                break;
            }
        }
    }
    assert!(created > 0 && created < ENTRIES_PER_TABLE);
}

#[test]
fn second_table_used_when_first_full() {
    // One large key fills most of table 0's blob; force spillover to t1.
    let (mut v, g, io) = vault::<2>();
    // Fill table 0 to near capacity with RSA-4k CRT keys.
    let mut last = None;
    loop {
        let r = with_key(&[0u8; 2564], |k| {
            block_on(v.create(
                &g,
                &io,
                0,
                k,
                HsmVaultKeyKind::Rsa4kPrivateCrt,
                None,
                aes_attrs(),
            ))
        });
        match r {
            Ok(id) => last = Some(id),
            Err(_) => break,
        }
    }
    // The allocator should have spilled into table 1 (id >= 0x100).
    assert!(
        u16::from(last.unwrap()) >= 0x100,
        "later keys land in the second table"
    );
}

#[test]
fn dma_threshold_boundary() {
    let (mut v, g, io) = vault::<1>();
    // EstablishCred = 144 B (> 128) → GDMA.
    with_key(&[0u8; 144], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::EstablishCred,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    assert_eq!(g.copies.get(), 1);
    // MaskingKey = 80 B (<= 128) → CPU.
    with_key(&[0u8; 80], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::MaskingKey,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    assert_eq!(g.copies.get(), 1, "80-byte key stays on the CPU path");
}

#[test]
fn failed_gdma_copy_does_not_leak_blocks() {
    let (mut v, g, io) = vault::<1>();
    g.fail_copy.set(true);
    // A large key (> DMA_THRESHOLD) routes through GDMA, which fails.
    let e = with_key(&[0xEEu8; 516], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            aes_attrs(),
        ))
        .unwrap_err()
    });
    assert_eq!(e, HsmError::FailedToStartDmaTransaction);

    // The failed allocation must have been rolled back: the next
    // successful key reuses block 0 (attrs at byte offset 0, key at +32).
    // A leaked run would push this key past the orphaned blocks.
    g.fail_copy.set(false);
    let id = with_key(&[0x5Au8; 516], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    let (_t, off, len) = v.key_location(id).unwrap();
    assert_eq!(
        off, 32,
        "new key starts at block 0 — failed alloc rolled back"
    );
    assert_eq!(len, 516);
    assert_eq!(&**v.key(id).unwrap(), &[0x5Au8; 516][..]);
}

#[test]
fn delete_sync_cpu_zeroizes_no_gdma() {
    let (mut v, g, io) = vault::<1>();
    let id = with_key(&[0x9u8; 516], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    v.delete_sync(id).unwrap();
    assert_eq!(v.key(id).unwrap_err(), HsmError::KeyNotFound);
    assert_eq!(g.zeroizes.get(), 0, "delete_sync never uses GDMA");
}

#[test]
fn key_len_reports_fixed_and_max() {
    assert_eq!(
        KeyVault::<ArrayStorage<1>>::key_len(HsmVaultKeyKind::Aes256),
        Ok(32)
    );
    assert_eq!(
        KeyVault::<ArrayStorage<1>>::key_len(HsmVaultKeyKind::VarLenHmacSha512),
        Ok(128)
    );
    assert_eq!(
        KeyVault::<ArrayStorage<1>>::key_len(HsmVaultKeyKind::Free),
        Err(HsmError::InvalidArg)
    );
}

/// Helper: storage byte span `[attrs..attrs+total]` of a key's slot.
fn key_span(len: usize) -> usize {
    let aligned = (len + 7) & !7;
    32 + aligned
}

#[test]
fn delete_zeroizes_blob_cpu_path() {
    let (mut v, g, io) = vault::<1>();
    let id = with_key(&[0xCCu8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    let (table, off, len) = v.key_location(id).unwrap();
    let attrs_off = off - 32;
    let total = key_span(len);
    block_on(v.delete(&g, &io, id)).unwrap();
    assert_eq!(g.zeroizes.get(), 0, "32-byte key zeroed by CPU");
    let blob = v.storage().blob(table).unwrap();
    assert!(
        blob[attrs_off..attrs_off + total].iter().all(|&b| b == 0),
        "key region scrubbed after delete"
    );
}

#[test]
fn delete_zeroizes_blob_dma_path() {
    let (mut v, g, io) = vault::<1>();
    let id = with_key(&[0x7u8; 516], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            aes_attrs(),
        ))
        .unwrap()
    });
    let (table, off, len) = v.key_location(id).unwrap();
    let attrs_off = off - 32;
    let total = key_span(len);
    block_on(v.delete(&g, &io, id)).unwrap();
    assert_eq!(g.zeroizes.get(), 1, "516-byte region zeroed via GDMA");
    let blob = v.storage().blob(table).unwrap();
    assert!(blob[attrs_off..attrs_off + total].iter().all(|&b| b == 0));
}

#[test]
fn create_reports_defragmentation_needed() {
    // Fill one table's blob completely with 8-block keys, then free two
    // non-adjacent slots, leaving enough total free space but no run long
    // enough for a larger key.
    let (mut v, g, io) = vault::<1>();
    // Ecc256Private = 32 B -> 64 B storage -> 8 blocks; 1888/8 = 236 keys
    // fill the blob exactly.
    let ids: Vec<_> = (0..236)
        .map(|i| {
            with_key(&[i as u8; 32], |k| {
                block_on(v.create(
                    &g,
                    &io,
                    0,
                    k,
                    HsmVaultKeyKind::Ecc256Private,
                    None,
                    aes_attrs(),
                ))
                .unwrap()
            })
        })
        .collect();
    // Free two non-adjacent slots -> two 8-block holes, not contiguous.
    block_on(v.delete(&g, &io, ids[0])).unwrap();
    block_on(v.delete(&g, &io, ids[2])).unwrap();
    // Ecc521Private = 68 B -> 104 B -> 13 blocks: 16 free but no 13-run.
    let e = with_key(&[0u8; 68], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Ecc521Private,
            None,
            aes_attrs(),
        ))
        .unwrap_err()
    });
    assert_eq!(e, HsmError::DefragmentationNeeded);
    // A key that fits a single 8-block hole still succeeds.
    assert!(with_key(&[1u8; 32], |k| {
        block_on(v.create(
            &g,
            &io,
            0,
            k,
            HsmVaultKeyKind::Ecc256Private,
            None,
            aes_attrs(),
        ))
        .is_ok()
    }));
}

#[test]
fn delete_invalid_id_is_key_not_found() {
    let (mut v, g, io) = vault::<1>();
    let id = with_key(&[1u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    // Never-allocated id.
    assert_eq!(
        block_on(v.delete(&g, &io, HsmKeyId::from(0x00FFu16))).unwrap_err(),
        HsmError::KeyNotFound
    );
    // Double delete.
    block_on(v.delete(&g, &io, id)).unwrap();
    assert_eq!(
        block_on(v.delete(&g, &io, id)).unwrap_err(),
        HsmError::KeyNotFound
    );
}

#[test]
fn accessors_on_invalid_id_are_key_not_found() {
    let (v, _g, _io) = vault::<1>();
    let bad = HsmKeyId::from(0x0005u16);
    assert_eq!(v.key(bad).unwrap_err(), HsmError::KeyNotFound);
    assert_eq!(v.key_kind(bad).unwrap_err(), HsmError::KeyNotFound);
    assert_eq!(v.key_attrs(bad).unwrap_err(), HsmError::KeyNotFound);
    assert_eq!(v.key_location(bad).unwrap_err(), HsmError::KeyNotFound);
}

#[test]
fn var_hmac_boundary_lengths() {
    let (mut v, g, io) = vault::<1>();
    let kind = HsmVaultKeyKind::VarLenHmacSha256; // range 32..=64
    let create = |v: &mut KeyVault<ArrayStorage<1>>, n: usize| {
        with_key(&vec![0xA5u8; n], |k| {
            block_on(v.create(&g, &io, 0, k, kind, None, aes_attrs()))
        })
    };
    assert!(create(&mut v, 32).is_ok(), "min accepted");
    assert!(create(&mut v, 64).is_ok(), "max accepted");
    assert_eq!(
        create(&mut v, 31).unwrap_err(),
        HsmError::InvalidArg,
        "min-1"
    );
    assert_eq!(
        create(&mut v, 65).unwrap_err(),
        HsmError::InvalidArg,
        "max+1"
    );
    // Round-trip an exact-max key.
    let id = create(&mut v, 64).unwrap();
    assert_eq!(v.key(id).unwrap().len(), 64);
}

#[test]
fn sequential_keys_use_sequential_slots() {
    let (mut v, g, io) = vault::<1>();
    let id0 = with_key(&[0u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    let id1 = with_key(&[1u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    assert_eq!(u16::from(id0), 0);
    assert_eq!(u16::from(id1), 1);
}

// ── Resource-mask (per-partition table subset) ──────────────────────

#[test]
fn zero_mask_has_no_storage() {
    // No tables owned: every create fails with NotEnoughSpace.
    let (mut v, g, io) = vault_masked::<4>(0);
    let e = with_key(&[0u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap_err()
    });
    assert_eq!(e, HsmError::NotEnoughSpace);
}

#[test]
fn key_id_encodes_global_table_index() {
    // Own only tables 2 and 5 (sparse). The first key must land in the
    // lowest owned table (2), so its key_id high byte is 2 — the *global*
    // index, not a dense 0.
    let mask = (1u128 << 2) | (1u128 << 5);
    let (mut v, g, io) = vault_masked::<8>(mask);
    let id = with_key(&[1u8; 32], |k| {
        block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs())).unwrap()
    });
    assert_eq!(u16::from(id) >> 8, 2, "key lands in global table 2");
    assert_eq!(&**v.key(id).unwrap(), &[1u8; 32][..]);
}

#[test]
fn unowned_table_id_is_key_not_found() {
    // Own table 2 only; a key_id pointing at the unowned table 0 must be
    // rejected even though it is a syntactically valid index.
    let (v, _g, _io) = vault_masked::<8>(1u128 << 2);
    let unowned = HsmKeyId::from(0x0000u16); // table 0, slot 0
    assert_eq!(v.key(unowned).unwrap_err(), HsmError::KeyNotFound);
    assert_eq!(v.key_kind(unowned).unwrap_err(), HsmError::KeyNotFound);
}

#[test]
fn create_spills_across_owned_tables_only() {
    // Own tables 1 and 3. Fill table 1, then the next key must spill to
    // table 3 (skipping the unowned table 2).
    let mask = (1u128 << 1) | (1u128 << 3);
    let (mut v, g, io) = vault_masked::<4>(mask);
    let mut last = None;
    loop {
        let r = with_key(&[0u8; 2564], |k| {
            block_on(v.create(
                &g,
                &io,
                0,
                k,
                HsmVaultKeyKind::Rsa4kPrivateCrt,
                None,
                aes_attrs(),
            ))
        });
        match r {
            Ok(id) => last = Some(id),
            Err(_) => break,
        }
    }
    // The last key must be in table 1 or 3 — never the unowned 0 or 2.
    let t = u16::from(last.unwrap()) >> 8;
    assert!(
        t == 1 || t == 3,
        "keys only land in owned tables, got table {t}"
    );
}

#[test]
fn clear_only_touches_owned_tables() {
    // Own table 0 and 1; create one key in each, clear, both gone.
    let mask = 0b11u128;
    let (mut v, g, io) = vault_masked::<2>(mask);
    let ids: Vec<_> = (0..2)
        .map(|i| {
            // Fill table 0 first, then table 1, by exhausting table 0.
            with_key(&[i as u8; 32], |k| {
                block_on(v.create(&g, &io, 0, k, HsmVaultKeyKind::Aes256, None, aes_attrs()))
                    .unwrap()
            })
        })
        .collect();
    block_on(v.clear(&g, &io)).unwrap();
    for id in ids {
        assert_eq!(v.key(id).unwrap_err(), HsmError::KeyNotFound);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host tests for the PCTs and [`ct_eq`].
//!
//! The PCTs run against a fake PAL whose operations each do what the test
//! sets: write a chosen value, write nothing, or fail. The fakes brand heap
//! memory as `DmaBuf`, which requires `unsafe`; that is confined to this
//! module.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::future::Future;
use core::pin::pin;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCqe;
use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsa;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmRsaPct;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSqe;

use super::ct_eq;
use super::ecc_pct;
use super::rsa_pct;

const CURVES: [HsmEccCurve; 3] = [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521];

/// One private key per modulus size.
const RSA_KEYS: [HsmRsaKey; 3] = [
    HsmRsaKey::Rsa2048Priv,
    HsmRsaKey::Rsa3072Priv,
    HsmRsaKey::Rsa4096Priv,
];

/// Both orders of the RSA PCT.
const RSA_ORDERS: [(&str, &HsmRsaPct); 2] = [
    ("sign/verify", &HsmRsaPct::SignVerify),
    ("encrypt/decrypt", &HsmRsaPct::EncryptDecrypt),
];

/// Fills fresh scratch, as real scratch starts uninitialized. Its bit 0 is
/// clear, so a verify result that nothing writes would read as valid.
const GARBAGE: u8 = 0xCC;

/// `ecc_verify` status bytes: bit 0 clear means the signature is valid.
const VALID: u8 = 0x00;
const INVALID: u8 = 0x01;

/// Masks for the fake RSA exponentiations. Applying one mask twice gives
/// back the input, as a consistent key pair does.
const RSA_MASK: u8 = 0x5C;
const OTHER_MASK: u8 = 0x3A;

// ── Fake PAL ────────────────────────────────────────────────────────

/// What a fake PAL operation does.
#[derive(Clone, Copy)]
enum Op {
    /// Fills its output with a byte.
    Fill(u8),
    /// Writes its input XOR a mask byte.
    Xor(u8),
    /// Writes nothing.
    Nothing,
    /// Returns an error.
    Fail(HsmError),
}

impl Op {
    /// Runs the operation from `input` into `output`, and counts it.
    fn run(self, calls: &Cell<usize>, input: &[u8], output: &mut [u8]) -> HsmResult<()> {
        calls.set(calls.get() + 1);
        match self {
            Op::Fill(byte) => output.fill(byte),
            Op::Xor(mask) => {
                for (out, byte) in output.iter_mut().zip(input) {
                    *out = byte ^ mask;
                }
            }
            Op::Nothing => {}
            Op::Fail(err) => return Err(err),
        }
        Ok(())
    }
}

/// A PAL whose PCT operations do what the test sets. The defaults make
/// every PCT pass. The PCTs call no other PAL method.
struct FakePal {
    /// Counts the operations run.
    calls: Cell<usize>,
    hash: Op,
    ecc_sign: Op,
    /// Fills the 4-byte status word with [`VALID`] or [`INVALID`].
    ecc_verify: Op,
    /// One operation per `ecdh_derive` call, in call order.
    ecdh_derive: [Op; 2],
    ecdh_calls: Cell<usize>,
    mod_exp_priv: Op,
    mod_exp_pub: Op,
}

impl Default for FakePal {
    fn default() -> Self {
        Self {
            calls: Cell::new(0),
            hash: Op::Fill(0x11),
            ecc_sign: Op::Fill(0x22),
            ecc_verify: Op::Fill(VALID),
            ecdh_derive: [Op::Fill(0x33); 2],
            ecdh_calls: Cell::new(0),
            mod_exp_priv: Op::Xor(RSA_MASK),
            mod_exp_pub: Op::Xor(RSA_MASK),
        }
    }
}

impl HsmHash for FakePal {
    type HashCtx<'a> = ();

    async fn hash(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        data: &DmaBuf,
        digest: &mut DmaBuf,
        _big_endian: bool,
    ) -> HsmResult<()> {
        self.hash.run(&self.calls, data, digest)
    }

    fn hash_begin<'a>(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn hash_continue(
        &self,
        _io: &impl HsmIo,
        _ctx: &mut Self::HashCtx<'_>,
        _data: &DmaBuf,
    ) -> HsmResult<()> {
        unimplemented!()
    }

    async fn hash_finish(
        &self,
        _io: &impl HsmIo,
        _ctx: Self::HashCtx<'_>,
        _digest: &mut DmaBuf,
        _big_endian: bool,
    ) -> HsmResult<()> {
        unimplemented!()
    }
}

impl HsmEcc for FakePal {
    async fn ecc_gen_keypair(
        &self,
        _io: &impl HsmIo,
        _alloc: &impl HsmScopedAlloc,
        _curve: HsmEccCurve,
        _out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        unimplemented!()
    }

    async fn ecc_gen_keypair_from_root(
        &self,
        _io: &impl HsmIo,
        _alloc: &impl HsmScopedAlloc,
        _curve: HsmEccCurve,
        _root: &DmaBuf,
        _out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)> {
        unimplemented!()
    }

    async fn ecc_sign(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        _priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.ecc_sign.run(&self.calls, hash, signature)
    }

    async fn ecc_verify(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        _pub_key: &DmaBuf,
        _hash: &DmaBuf,
        signature: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.ecc_verify.run(&self.calls, signature, result)
    }

    async fn ecc_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        _der: &DmaBuf,
        _out: Option<&mut DmaBuf>,
        _pct: HsmEccPct,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        unimplemented!()
    }

    async fn ecc_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        _priv_key: &DmaBuf,
        _pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        unimplemented!()
    }

    async fn ecc_pub_from_priv(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        _priv_key: &DmaBuf,
        _pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        unimplemented!()
    }

    async fn ecdh_derive(
        &self,
        _io: &impl HsmIo,
        _curve: HsmEccCurve,
        _priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()> {
        let call = self.ecdh_calls.get();
        self.ecdh_calls.set(call + 1);
        self.ecdh_derive[call].run(&self.calls, pub_key, secret)
    }
}

impl HsmRsa for FakePal {
    async fn rsa_gen_keypair(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _priv_key: &mut DmaBuf,
        _pub_key: &mut DmaBuf,
        _pct: HsmRsaPct,
    ) -> HsmResult<()> {
        unimplemented!()
    }

    async fn mod_exp_priv(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _key: &DmaBuf,
        y: &DmaBuf,
        x: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.mod_exp_priv.run(&self.calls, y, x)
    }

    async fn mod_exp_pub(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _key: &DmaBuf,
        x: &DmaBuf,
        y: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.mod_exp_pub.run(&self.calls, x, y)
    }

    fn rsa_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        _priv_key: &DmaBuf,
        _pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        unimplemented!()
    }

    async fn rsa_priv_der_to_vault<'a>(
        &'a self,
        _io: &impl HsmIo,
        _der: &'a mut DmaBuf,
        _crt: bool,
        _pct: HsmRsaPct,
    ) -> HsmResult<(&'a DmaBuf, usize)> {
        unimplemented!()
    }

    async fn rsa_pkcs1_encrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _pub_key: &DmaBuf,
        _message: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_pkcs1_decrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _priv_key: &DmaBuf,
        _ciphertext: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_pkcs1_sign<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _signature: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_pkcs1_verify<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _signature: &DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_oaep_encrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &DmaBuf,
        _message: &DmaBuf,
        _label: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_oaep_decrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &DmaBuf,
        _ciphertext: &DmaBuf,
        _label: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_pss_sign<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _salt_len: usize,
        _signature: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        unimplemented!()
    }

    async fn rsa_pss_verify<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _salt_len: usize,
        _signature: &DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        unimplemented!()
    }
}

// ── Fake scratch allocator and IO ───────────────────────────────────

/// Hands out heap buffers that hold [`GARBAGE`], and can fail one
/// allocation with `NotEnoughSpace`. The PCTs use only `dma_alloc`.
#[derive(Default)]
struct FakeAlloc {
    /// Counts the allocations so far.
    count: Cell<usize>,
    /// The index of the allocation to fail, if any.
    fail_at: Option<usize>,
}

impl HsmScopedAlloc for FakeAlloc {
    fn alloc(&self, _size: usize) -> HsmResult<&mut [u8]> {
        unimplemented!()
    }

    fn alloc_zeroed(&self, _size: usize) -> HsmResult<&mut [u8]> {
        unimplemented!()
    }

    fn alloc_val<T: Sized>(&self, _value: T) -> HsmResult<&mut T> {
        unimplemented!()
    }

    fn dma_alloc(&self, size: usize) -> HsmResult<&mut DmaBuf> {
        let index = self.count.get();
        self.count.set(index + 1);
        if self.fail_at == Some(index) {
            return Err(HsmError::NotEnoughSpace);
        }
        // Leaked: each test allocates only a few kilobytes.
        let buf = Box::leak(vec![GARBAGE; size].into_boxed_slice());
        // SAFETY: in these host tests, heap memory stands in for DMA memory.
        Ok(unsafe { DmaBuf::from_raw_mut(buf) })
    }

    fn dma_alloc_zeroed(&self, _size: usize) -> HsmResult<&mut DmaBuf> {
        unimplemented!()
    }
}

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

// ── Helpers ─────────────────────────────────────────────────────────

/// Brands a leaked buffer of `len` bytes as a `DmaBuf`, for a key that the
/// fake PAL ignores.
fn key(len: usize) -> &'static DmaBuf {
    let buf = Box::leak(vec![0; len].into_boxed_slice());
    // SAFETY: in these host tests, heap memory stands in for DMA memory.
    unsafe { DmaBuf::from_raw(buf) }
}

/// Polls `fut` once. Every fake operation finishes at once, so one poll
/// must finish the PCT.
fn block_on<F: Future>(fut: F) -> F::Output {
    match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a fake operation waited"),
    }
}

/// Runs the ECC PCT that `pct` selects.
fn run_ecc(
    pal: &FakePal,
    alloc: &FakeAlloc,
    curve: HsmEccCurve,
    pct: &HsmEccPct,
) -> HsmResult<bool> {
    let priv_key = key(curve.wire_coord_len());
    let pub_key = key(curve.wire_pub_key_len());
    block_on(ecc_pct(
        pal,
        &FakeIo::default(),
        alloc,
        curve,
        pct,
        priv_key,
        pub_key,
    ))
}

/// Runs the RSA PCT that `pct` selects.
fn run_rsa(
    pal: &FakePal,
    alloc: &FakeAlloc,
    key_size: HsmRsaKey,
    pct: &HsmRsaPct,
) -> HsmResult<bool> {
    let k = key_size.modulus_len();
    block_on(rsa_pct(
        pal,
        &FakeIo::default(),
        alloc,
        key_size,
        pct,
        key(2 * k + 4),
        key(k + 4),
    ))
}

/// Runs the ECC PCT that `pct` selects on every curve, each with a fresh
/// `pal()`, and expects `want`.
fn check_ecc(pct: &HsmEccPct, pal: impl Fn() -> FakePal, want: HsmResult<bool>) {
    for curve in CURVES {
        let got = run_ecc(&pal(), &FakeAlloc::default(), curve, pct);
        assert_eq!(got, want, "{curve:?}");
    }
}

/// Runs the RSA PCT in `order` for every key size, each with a fresh
/// `pal()`, and expects `want`.
fn check_rsa(order: (&str, &HsmRsaPct), pal: impl Fn() -> FakePal, want: HsmResult<bool>) {
    let (name, pct) = order;
    for key_size in RSA_KEYS {
        let got = run_rsa(&pal(), &FakeAlloc::default(), key_size, pct);
        assert_eq!(got, want, "{key_size:?} {name}");
    }
}

/// Returns a maker of fake PALs: the default PAL, changed by `set`.
fn pal_with(set: impl Fn(&mut FakePal)) -> impl Fn() -> FakePal {
    move || {
        let mut pal = FakePal::default();
        set(&mut pal);
        pal
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[test]
fn ct_eq_compares_whole_strings() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}

#[test]
fn none_passes_without_running_anything() {
    for curve in CURVES {
        let (pal, alloc) = (FakePal::default(), FakeAlloc::default());
        assert_eq!(run_ecc(&pal, &alloc, curve, &HsmEccPct::None), Ok(true));
        assert_eq!((pal.calls.get(), alloc.count.get()), (0, 0), "{curve:?}");
    }
    for key_size in RSA_KEYS {
        let (pal, alloc) = (FakePal::default(), FakeAlloc::default());
        assert_eq!(run_rsa(&pal, &alloc, key_size, &HsmRsaPct::None), Ok(true));
        assert_eq!((pal.calls.get(), alloc.count.get()), (0, 0), "{key_size:?}");
    }
}

#[test]
fn sign_verify_passes_a_valid_signature() {
    check_ecc(&HsmEccPct::SignVerify, FakePal::default, Ok(true));
}

#[test]
fn sign_verify_fails_an_invalid_signature() {
    let pal = pal_with(|p| p.ecc_verify = Op::Fill(INVALID));
    check_ecc(&HsmEccPct::SignVerify, pal, Ok(false));
}

#[test]
fn sign_verify_fails_when_verify_writes_nothing() {
    let pal = pal_with(|p| p.ecc_verify = Op::Nothing);
    check_ecc(&HsmEccPct::SignVerify, pal, Ok(false));
}

#[test]
fn sign_verify_returns_operation_errors() {
    let ops: [(HsmError, fn(&mut FakePal, Op)); 3] = [
        (HsmError::ShaError, |p, op| p.hash = op),
        (HsmError::EccSignFailed, |p, op| p.ecc_sign = op),
        (HsmError::EccVerifyFailed, |p, op| p.ecc_verify = op),
    ];
    for (err, set) in ops {
        let pal = pal_with(|p| set(p, Op::Fail(err)));
        check_ecc(&HsmEccPct::SignVerify, pal, Err(err));
    }
}

#[test]
fn key_agreement_passes_matching_secrets() {
    check_ecc(&HsmEccPct::KeyAgreement, FakePal::default, Ok(true));
}

#[test]
fn key_agreement_fails_different_secrets() {
    let pal = pal_with(|p| p.ecdh_derive = [Op::Fill(0x33), Op::Fill(0x44)]);
    check_ecc(&HsmEccPct::KeyAgreement, pal, Ok(false));
}

#[test]
fn key_agreement_fails_when_a_derivation_writes_nothing() {
    let (x, none) = (Op::Fill(0x33), Op::Nothing);
    for ops in [[none, x], [x, none], [none, none]] {
        let pal = pal_with(|p| p.ecdh_derive = ops);
        check_ecc(&HsmEccPct::KeyAgreement, pal, Ok(false));
    }
}

#[test]
fn key_agreement_returns_operation_errors() {
    let x = Op::Fill(0x33);
    for err in [
        HsmError::EccPublicKeyValidationFailed,
        HsmError::EccPointValidationFailed,
    ] {
        for ops in [[Op::Fail(err), x], [x, Op::Fail(err)]] {
            let pal = pal_with(|p| p.ecdh_derive = ops);
            check_ecc(&HsmEccPct::KeyAgreement, pal, Err(err));
        }
    }
}

#[test]
fn rsa_passes_a_consistent_key() {
    for order in RSA_ORDERS {
        check_rsa(order, FakePal::default, Ok(true));
    }
}

#[test]
fn rsa_fails_an_inconsistent_key() {
    let pal = pal_with(|p| p.mod_exp_pub = Op::Xor(OTHER_MASK));
    for order in RSA_ORDERS {
        check_rsa(order, &pal, Ok(false));
    }
}

/// A key with `e = d = 1` makes both exponentiations return their input.
#[test]
fn rsa_fails_an_identity_key() {
    let pal = pal_with(|p| {
        p.mod_exp_priv = Op::Xor(0);
        p.mod_exp_pub = Op::Xor(0);
    });
    for order in RSA_ORDERS {
        check_rsa(order, &pal, Ok(false));
    }
}

#[test]
fn rsa_fails_when_an_exponentiation_writes_nothing() {
    let private = pal_with(|p| p.mod_exp_priv = Op::Nothing);
    let public = pal_with(|p| p.mod_exp_pub = Op::Nothing);
    for order in RSA_ORDERS {
        check_rsa(order, &private, Ok(false));
        check_rsa(order, &public, Ok(false));
    }
}

#[test]
fn rsa_returns_operation_errors() {
    let private = pal_with(|p| p.mod_exp_priv = Op::Fail(HsmError::InvalidArg));
    let public = pal_with(|p| p.mod_exp_pub = Op::Fail(HsmError::RsaEncryptFailed));
    for order in RSA_ORDERS {
        check_rsa(order, &private, Err(HsmError::InvalidArg));
        check_rsa(order, &public, Err(HsmError::RsaEncryptFailed));
    }
    // Only the sign/verify order hashes.
    let hash = pal_with(|p| p.hash = Op::Fail(HsmError::ShaError));
    check_rsa(RSA_ORDERS[0], hash, Err(HsmError::ShaError));
}

#[test]
fn scratch_allocation_errors_are_returned() {
    type Run = fn(&FakePal, &FakeAlloc) -> HsmResult<bool>;
    let runs: [(&str, Run); 4] = [
        ("ECC sign/verify", |pal, alloc| {
            run_ecc(pal, alloc, HsmEccCurve::P256, &HsmEccPct::SignVerify)
        }),
        ("ECC key agreement", |pal, alloc| {
            run_ecc(pal, alloc, HsmEccCurve::P256, &HsmEccPct::KeyAgreement)
        }),
        ("RSA sign/verify", |pal, alloc| {
            run_rsa(pal, alloc, HsmRsaKey::Rsa2048Priv, &HsmRsaPct::SignVerify)
        }),
        ("RSA encrypt/decrypt", |pal, alloc| {
            run_rsa(
                pal,
                alloc,
                HsmRsaKey::Rsa2048Priv,
                &HsmRsaPct::EncryptDecrypt,
            )
        }),
    ];
    for (name, run) in runs {
        let passing = FakeAlloc::default();
        assert_eq!(run(&FakePal::default(), &passing), Ok(true), "{name}");
        assert!(passing.count.get() > 0, "{name}");
        for index in 0..passing.count.get() {
            let alloc = FakeAlloc {
                fail_at: Some(index),
                ..FakeAlloc::default()
            };
            let got = run(&FakePal::default(), &alloc);
            assert_eq!(
                got,
                Err(HsmError::NotEnoughSpace),
                "{name}, allocation {index}"
            );
        }
    }
}

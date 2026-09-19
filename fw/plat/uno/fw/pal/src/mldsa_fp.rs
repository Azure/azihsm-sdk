// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA offload from CP1 to FP1.
//!
//! CP1 cannot run ML-DSA itself — key generation does not fit in this part's
//! RAM at any parameter set, and the RustCrypto implementation that made the
//! proof of concept work cannot ship. FP1 runs wolfCrypt instead, and this
//! module is the client side of that arrangement: it marshals a request into
//! the shared payload buffer, posts a descriptor, and reads the result back.
//!
//! # How a request travels
//!
//! The IPC slot is 64 bytes, so it carries only a descriptor — operation,
//! parameter set, payload length. The data itself lives at a fixed address in
//! FP1's DTCM which both cores can reach:
//!
//! ```text
//! FP1 local  0x20000000
//! CP view    0xA3200000     (SocMemMap offset 0x43200000)
//! ```
//!
//! One buffer serves both directions: FP1 writes its answer over the request.
//! That is safe because wolfCrypt imports a key into its own structure before
//! using it, and it makes the buffer `max(in, out)` rather than `in + out`.
//!
//! Byte-at-a-time access is deliberate. Byte reads and writes across this
//! window are the only ones proven to work on silicon; wider accesses have
//! never been tried, and a 4,896-byte key is not where to find out.
//!
//! # What this module does not do
//!
//! **There is no locking.** The payload buffer is one fixed region and
//! `IpcDriver::send` serialises only the send, not the writes that precede
//! it, so two ML-DSA commands in flight would corrupt each other. That is a
//! deliberate bring-up decision, not an oversight: FP1 is single threaded and
//! this is a proof of concept. It must be fixed before the path carries real
//! traffic.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmPal;
use crate::pal::IpcChannel;

/// Shared payload buffer, as the CP addresses it.
const PAYLOAD: *mut u8 = 0xA320_0000 as *mut u8;

/// Payload buffer size. The worst case is an ML-DSA-87 verify request at
/// 12 + 2592 + 4627 + msg bytes.
const PAYLOAD_LEN: usize = 0x2800;

/// Descriptor opcodes, matching `MessageHandler.h` on the FP side.
const OP_KEYGEN: u32 = 0x50;
const OP_SIGN: u32 = 0x51;
const OP_VERIFY: u32 = 0x52;

/// `MlDsaParamSet_t`. Values are wolfCrypt's `level` argument.
const PARAM_87: u32 = 5;

/// FIPS 204 seed length.
pub const ML_DSA_SEED_LEN: usize = 32;

/// Status codes from `MlDsaService.cpp`.
const STS_OK: u8 = 0;
const STS_BAD_REQUEST: u8 = 1;
const STS_BAD_KEY: u8 = 2;
const STS_NO_MEMORY: u8 = 3;

/// Word offsets within the 16-word reply.
///
/// The slot is `msgOp:7|resp:1`, `tag`, `sts`, `length`, then `data[]`, so the
/// status sits in byte 2 of word 0 and `MlDsaIpcResp_t` begins at word 1.
const RESP_STS_WORD: usize = 0;
const RESP_LEN_WORD: usize = 1;
const RESP_VERIFY_WORD: usize = 2;

impl UnoHsmPal {
    /// Writes one byte into the shared payload buffer.
    ///
    /// # Safety
    ///
    /// `off` must be within [`PAYLOAD_LEN`]; every caller below bounds-checks
    /// its whole range before starting.
    #[inline]
    fn fp_wr(off: usize, v: u8) {
        // SAFETY: bounds checked by the caller; the window is device memory
        // that is always mapped once FP1 has booted.
        unsafe { PAYLOAD.add(off).write_volatile(v) }
    }

    /// Reads one byte from the shared payload buffer.
    #[inline]
    fn fp_rd(off: usize) -> u8 {
        // SAFETY: as `fp_wr`.
        unsafe { PAYLOAD.add(off).read_volatile() }
    }

    fn fp_wr32(off: usize, v: u32) {
        for (i, b) in v.to_le_bytes().iter().enumerate() {
            Self::fp_wr(off + i, *b);
        }
    }

    fn fp_wr_bytes(off: usize, src: &[u8]) {
        for (i, b) in src.iter().enumerate() {
            Self::fp_wr(off + i, *b);
        }
    }

    fn fp_rd_bytes(off: usize, dst: &mut [u8]) {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = Self::fp_rd(off + i);
        }
    }

    /// Posts a descriptor and waits for FP1.
    ///
    /// Returns `(resp_len, verify_result)`. An ML-DSA-87 signature takes
    /// around half a second on FP1 and has measured 1.3 s at worst, so this
    /// await is long by the standards of everything else on this core — but
    /// it is an await, not a spin, so the executor keeps running.
    async fn fp_request(&self, op: u32, payload_len: usize) -> HsmResult<(u32, u32)> {
        let msg: [u32; 3] = [op, PARAM_87, payload_len as u32];
        let mut reply = [0u32; 16];

        // The payload writes above must land before FP1 can observe the
        // descriptor. FP1 TCM is not cached on this core, so ordering is all
        // that is needed and no cache maintenance applies.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        self.ipc
            .send(IpcChannel::FpMessage as u8, &msg, &mut reply)
            .await;

        let sts = ((reply[RESP_STS_WORD] >> 16) & 0xFF) as u8;

        // Preserve the distinction FP1 drew. Collapsing everything to
        // "sign failed" told a caller with a structurally invalid key that
        // the device had broken, rather than that its key was bad.
        if sts != STS_OK {
            return Err(match sts {
                STS_BAD_KEY => HsmError::MlDsaInvalidSigningKey,
                STS_BAD_REQUEST => HsmError::InvalidArg,
                STS_NO_MEMORY => HsmError::DmaBufferAllocFailure,
                _ => HsmError::MlDsaSignFailed,
            });
        }

        Ok((reply[RESP_LEN_WORD], reply[RESP_VERIFY_WORD]))
    }

    /// Generates an ML-DSA-87 keypair on FP1 from `seed`.
    ///
    /// Writes the encoded verifying key into `vk` and the encoded signing key
    /// into `sk`. Either may be empty if the caller does not want that half —
    /// the DDI returns the seed rather than the signing key, so `keygen` there
    /// asks only for the verifying key.
    pub async fn ml_dsa_fp_keygen(
        &self,
        seed: &[u8; ML_DSA_SEED_LEN],
        vk: &mut [u8],
        sk: &mut [u8],
    ) -> HsmResult<()> {
        // `MlDsaKeyGenPayload_t`: two lengths then `data[]`.
        const HDR: usize = 8;

        Self::fp_wr32(0, 0);
        Self::fp_wr32(4, 0);
        Self::fp_wr_bytes(HDR, seed);

        let (resp_len, _) = self.fp_request(OP_KEYGEN, HDR + ML_DSA_SEED_LEN).await?;

        // FP1 reports what it wrote; the header says how it is divided.
        let vk_len = u32::from_le_bytes([
            Self::fp_rd(0),
            Self::fp_rd(1),
            Self::fp_rd(2),
            Self::fp_rd(3),
        ]) as usize;
        let sk_len = u32::from_le_bytes([
            Self::fp_rd(4),
            Self::fp_rd(5),
            Self::fp_rd(6),
            Self::fp_rd(7),
        ]) as usize;

        // Cross-check the two against each other before trusting either as a
        // length to copy by.
        if resp_len as usize != HDR + vk_len + sk_len
            || HDR + vk_len + sk_len > PAYLOAD_LEN
            || (!vk.is_empty() && vk.len() != vk_len)
            || (!sk.is_empty() && sk.len() != sk_len)
        {
            return Err(HsmError::MlDsaKeyGenFailed);
        }

        if !vk.is_empty() {
            Self::fp_rd_bytes(HDR, vk);
        }
        if !sk.is_empty() {
            Self::fp_rd_bytes(HDR + vk_len, sk);
        }

        Ok(())
    }

    /// Signs `msg` on FP1 under the encoded signing key `sk`.
    ///
    /// Deterministic: FP1 signs with `rnd = 0^32`, so this returns the same
    /// signature RustCrypto computes for the same key and message.
    pub async fn ml_dsa_fp_sign(&self, sk: &[u8], msg: &[u8], sig: &mut [u8]) -> HsmResult<()> {
        // `MlDsaSignPayload_t`: key length, message length, then `data[]`.
        const HDR: usize = 8;
        let payload_len = HDR + sk.len() + msg.len();

        // The response overwrites the request, and FP1 stages the signature
        // past the end of it, so both must fit.
        if payload_len > PAYLOAD_LEN || payload_len + sig.len() > PAYLOAD_LEN {
            return Err(HsmError::InvalidArg);
        }

        Self::fp_wr32(0, sk.len() as u32);
        Self::fp_wr32(4, msg.len() as u32);
        Self::fp_wr_bytes(HDR, sk);
        Self::fp_wr_bytes(HDR + sk.len(), msg);

        let (resp_len, _) = self.fp_request(OP_SIGN, payload_len).await?;

        if resp_len as usize != sig.len() {
            return Err(HsmError::MlDsaSignFailed);
        }

        // FP1 moves the signature down over the request before replying.
        Self::fp_rd_bytes(0, sig);
        Ok(())
    }

    /// Verifies `sig` over `msg` under the encoded verifying key `vk`.
    ///
    /// A signature that does not verify is a completed request with a
    /// negative answer, not a failed one, so this returns `Ok(false)` rather
    /// than an error — the caller decides which wire status that becomes.
    pub async fn ml_dsa_fp_verify(&self, vk: &[u8], sig: &[u8], msg: &[u8]) -> HsmResult<bool> {
        // `MlDsaVerifyPayload_t`: three lengths then `data[]`.
        const HDR: usize = 12;
        let payload_len = HDR + vk.len() + sig.len() + msg.len();

        if payload_len > PAYLOAD_LEN {
            return Err(HsmError::InvalidArg);
        }

        Self::fp_wr32(0, vk.len() as u32);
        Self::fp_wr32(4, sig.len() as u32);
        Self::fp_wr32(8, msg.len() as u32);
        Self::fp_wr_bytes(HDR, vk);
        Self::fp_wr_bytes(HDR + vk.len(), sig);
        Self::fp_wr_bytes(HDR + vk.len() + sig.len(), msg);

        let (_, verified) = self.fp_request(OP_VERIFY, payload_len).await?;
        Ok(verified == 1)
    }
}

impl azihsm_fw_hsm_pal_traits::HsmMlDsa for UnoHsmPal {
    /// Runs on FP1. `io` is unused: the offload addresses FP1's DTCM
    /// directly rather than going through this core's DMA.
    async fn ml_dsa_keygen(
        &self,
        _io: &impl azihsm_fw_hsm_pal_traits::HsmIo,
        seed: &[u8; 32],
        vk: &mut [u8],
        sk: &mut [u8],
    ) -> HsmResult<()> {
        self.ml_dsa_fp_keygen(seed, vk, sk).await
    }

    async fn ml_dsa_sign(
        &self,
        _io: &impl azihsm_fw_hsm_pal_traits::HsmIo,
        sk: &[u8],
        msg: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()> {
        self.ml_dsa_fp_sign(sk, msg, sig).await
    }

    async fn ml_dsa_verify(
        &self,
        _io: &impl azihsm_fw_hsm_pal_traits::HsmIo,
        vk: &[u8],
        sig: &[u8],
        msg: &[u8],
    ) -> HsmResult<bool> {
        self.ml_dsa_fp_verify(vk, sig, msg).await
    }
}

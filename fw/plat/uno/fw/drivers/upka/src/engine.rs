// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Context;
use core::task::Poll;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_uno_error::HsmResult;

use crate::api::UpkaDriver;
use crate::executor::EngineExecutor;
use crate::opcode::*;
use crate::UpkaEccCurve;
use crate::UpkaError;
use crate::UpkaRsaKeyType;

/// Exclusive handle to one PKA engine.
///
/// This handle is obtained from the driver acquisition APIs and grants
/// exclusive access to one hardware engine until released.
pub struct UpkaEngine<'a, const DEPTH: usize, const ENGINES: usize> {
    pub(crate) driver: &'a UpkaDriver<DEPTH, ENGINES>,
    pub(crate) id: u8,
    pub(crate) released: bool,
}

impl<const DEPTH: usize, const ENGINES: usize> core::fmt::Debug for UpkaEngine<'_, DEPTH, ENGINES> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpkaEngine")
            .field("id", &self.id)
            .field("released", &self.released)
            .finish()
    }
}

impl<const DEPTH: usize, const ENGINES: usize> UpkaEngine<'_, DEPTH, ENGINES> {
    const RESULT_WORD_LEN: usize = 4;

    fn ensure_cmd_input(valid: bool) -> HsmResult<()> {
        if valid {
            Ok(())
        } else {
            Err(UpkaError::CMD_ERROR)
        }
    }

    fn ensure_result_word(result: &DmaBuf) -> HsmResult<()> {
        Self::ensure_cmd_input(result.len() >= Self::RESULT_WORD_LEN)
    }

    /// Return the engine identifier.
    ///
    /// # Returns
    ///
    /// - Engine index associated with this handle.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Sign a digest using ECDSA.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `hash`: DMA-capable digest buffer.
    /// - `signature`: DMA-capable output buffer for `r || s`.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Signature was generated and written to `signature`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn ecc_sign(
        &mut self,
        curve: UpkaEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()> {
        Self::ensure_cmd_input(
            !priv_key.is_empty()
                && hash.len() >= hash_size(curve)
                && signature.len() >= signature_size(curve),
        )?;

        self.execute_cmd(
            ecc_sign_opcode(curve),
            signature.as_mut_ptr() as u32,
            hash.as_ptr() as u32,
            priv_key.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Verify an ECDSA signature.
    ///
    /// The verify command internally computes and consumes a Montgomery
    /// constant for `curve` as a required PKA setup step (performed on the
    /// same engine acquisition, before the verification), writing the
    /// transient constant into `mont_result` (see below). All hardware writes
    /// go through DMA into the caller-provided buffers, so those buffers must
    /// live in DMA-reachable memory (GSRAM, e.g. from the PAL scoped
    /// allocator's `dma_alloc`).
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `pub_key`: DMA-capable public key buffer.
    /// - `hash`: DMA-capable digest buffer.
    /// - `signature`: DMA-capable signature buffer.
    /// - `result`: DMA-capable output buffer that receives the 4-byte
    ///   hardware status word.
    /// - `prime`: DMA-capable curve prime buffer (LE).
    /// - `mont_result`: DMA-capable transient scratch for the Montgomery-
    ///   constant setup write. Its contents are consumed by the engine as
    ///   part of the verify command's internal state; the DMA output is not
    ///   surfaced to the caller and the buffer can be released as soon as
    ///   the verify future resolves.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Verification completed and status was written to `result`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    #[allow(clippy::too_many_arguments)]
    pub async fn ecc_verify(
        &mut self,
        curve: UpkaEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
        result: &mut DmaBuf,
        prime: &DmaBuf,
        mont_result: &mut DmaBuf,
    ) -> HsmResult<()> {
        // pub_key (X || Y) and signature (R || S) are consumed by the PKA in
        // wire format: two coordinates each padded to `hsm_point_size` (P-521
        // = 68, not the 66-byte field width). Validate against the full wire
        // width so an undersized buffer cannot make the hardware DMA read past
        // the caller's allocation.
        Self::ensure_cmd_input(
            pub_key.len() >= hsm_point_size(curve) * 2
                && hash.len() >= hash_size(curve)
                && signature.len() >= hsm_point_size(curve) * 2
                && result.len() >= Self::RESULT_WORD_LEN
                && prime.len() >= hsm_point_size(curve)
                && mont_result.len() >= hsm_point_size(curve),
        )?;

        // Required PKA setup: compute the Montgomery constant for the curve
        // prime on this engine before the verify (mirrors ecdh_derive). The
        // verify command consumes the engine state this leaves behind; the
        // `mont_result` DMA output itself is transient scratch. Both commands
        // run on the same engine acquisition (`execute_cmd` does not wipe
        // between commands).
        self.execute_cmd(
            mont_const_calc_opcode(curve),
            mont_result.as_mut_ptr() as u32,
            prime.as_ptr() as u32,
            0,
            0,
        )
        .await?;

        self.execute_cmd(
            ecc_verify_opcode(curve),
            result.as_mut_ptr() as u32,
            hash.as_ptr() as u32,
            pub_key.as_ptr() as u32,
            signature.as_ptr() as u32,
        )
        .await
    }

    /// Generate an ECC key pair.
    ///
    /// Hardware writes `pub_key_hsm || priv_key_hsm` contiguously into
    /// `key_buf`.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `key_buf`: DMA-capable output buffer for generated key material.
    ///
    /// # Returns
    ///
    /// - `Ok(usize)`: Total HSM wire-format bytes written.
    /// - `Err(UpkaError::CMD_ERROR)`: Output buffer is too small or hardware
    ///   rejected the command.
    pub async fn ecc_gen_keypair(
        &mut self,
        curve: UpkaEccCurve,
        key_buf: &mut DmaBuf,
    ) -> HsmResult<usize> {
        let total_len = hsm_point_size(curve) * 3;
        Self::ensure_cmd_input(key_buf.len() >= total_len)?;

        self.execute_cmd(
            ecc_key_gen_opcode(curve),
            key_buf.as_mut_ptr() as u32,
            0,
            0,
            0,
        )
        .await?;

        Ok(total_len)
    }

    /// Derive an ECDH shared secret.
    ///
    /// The point-multiplication internally computes and consumes a Montgomery
    /// constant for `curve` as a required PKA setup step (performed on the
    /// same engine acquisition, before the point-multiply), writing the
    /// transient constant into `mont_result` (see below). All hardware writes
    /// go through DMA into the caller-provided buffers, so those buffers must
    /// live in DMA-reachable memory (GSRAM, e.g. from the PAL scoped
    /// allocator's `dma_alloc`).
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `pub_key`: DMA-capable peer public key buffer.
    /// - `secret`: DMA-capable output buffer for the derived secret.
    /// - `prime`: DMA-capable curve prime buffer (LE).
    /// - `mont_result`: DMA-capable transient scratch for the Montgomery-
    ///   constant setup write. Its contents are consumed by the engine as
    ///   part of the point-multiply's internal state; the DMA output is not
    ///   surfaced to the caller and the buffer can be released as soon as
    ///   the derive future resolves.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Shared secret was written to `secret`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn ecdh_derive(
        &mut self,
        curve: UpkaEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
        prime: &DmaBuf,
        mont_result: &mut DmaBuf,
    ) -> HsmResult<()> {
        Self::ensure_cmd_input(
            priv_key.len() >= hsm_point_size(curve)
                && pub_key.len() >= hsm_point_size(curve) * 2
                && secret.len() >= point_size(curve)
                && prime.len() >= hsm_point_size(curve)
                && mont_result.len() >= hsm_point_size(curve),
        )?;

        // Required PKA setup: compute the Montgomery constant for the curve
        // prime on this engine before the point multiplication. This leaves
        // engine state the point-mul consumes; both run on the same engine
        // acquisition (execute_cmd does not wipe between commands).
        self.execute_cmd(
            mont_const_calc_opcode(curve),
            mont_result.as_mut_ptr() as u32,
            prime.as_ptr() as u32,
            0,
            0,
        )
        .await?;

        // ECDH point multiply: result = shared secret X (LE);
        // arg1 = peer public point (X || Y, LE); arg2 = private scalar (LE).
        self.execute_cmd(
            ecc_point_mul_opcode(curve),
            secret.as_mut_ptr() as u32,
            pub_key.as_ptr() as u32,
            priv_key.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Run an RSA private-key modular exponentiation.
    ///
    /// `key_type` selects both modulus size and key format (standard or CRT).
    /// Input and output buffers must match the selected modulus size.
    ///
    /// # Parameters
    ///
    /// - `key_type`: RSA key type (size + format selector).
    /// - `key`: DMA-capable private key buffer.
    /// - `input`: DMA-capable input block buffer.
    /// - `output`: DMA-capable output block buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Result block was written to `output`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn rsa_mod_exp_priv(
        &mut self,
        key_type: UpkaRsaKeyType,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        let mod_size = rsa_mod_size(key_type);
        Self::ensure_cmd_input(
            !key.is_empty() && input.len() == mod_size && output.len() == mod_size,
        )?;

        self.execute_cmd(
            rsa_priv_opcode(key_type),
            output.as_mut_ptr() as u32,
            input.as_ptr() as u32,
            key.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Run an RSA public-key modular exponentiation.
    ///
    /// `key_type` selects modulus size. Input and output buffers must match
    /// the selected modulus size.
    ///
    /// # Parameters
    ///
    /// - `key_type`: RSA key type (size selector for public exponent path).
    /// - `key`: DMA-capable public key buffer.
    /// - `input`: DMA-capable input block buffer.
    /// - `output`: DMA-capable output block buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Result block was written to `output`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn rsa_mod_exp_pub(
        &mut self,
        key_type: UpkaRsaKeyType,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        let mod_size = rsa_mod_size(key_type);
        Self::ensure_cmd_input(
            !key.is_empty() && input.len() == mod_size && output.len() == mod_size,
        )?;

        self.execute_cmd(
            rsa_pub_opcode(key_type),
            output.as_mut_ptr() as u32,
            input.as_ptr() as u32,
            key.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Validate that a public key is on the specified ECC curve.
    ///
    /// `result` is a caller-allocated DMA-capable buffer (at least 4 bytes)
    /// that receives the hardware validation status word.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `pub_key`: DMA-capable public key buffer.
    /// - `result`: DMA-capable output status word buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Validation completed and status was written to `result`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn ecc_point_validate(
        &mut self,
        curve: UpkaEccCurve,
        pub_key: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        Self::ensure_result_word(result)?;
        self.execute_cmd(
            ecc_point_validate_opcode(curve),
            result.as_mut_ptr() as u32,
            0,
            pub_key.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Derive a public key from a private key.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `pub_key`: DMA-capable output buffer for the derived public key.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Public key was written to `pub_key`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn ecc_gen_pub_key(
        &mut self,
        curve: UpkaEccCurve,
        priv_key: &DmaBuf,
        pub_key: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.execute_cmd(
            ecc_point_mul_opcode(curve),
            pub_key.as_mut_ptr() as u32,
            priv_key.as_ptr() as u32,
            0,
            0,
        )
        .await
    }

    // =====================================================================
    // Deterministic-sign step primitives (RFC 6979 P-384 ECDSA)
    // =====================================================================
    //
    // Public single-command PKA ops the PAL orchestrates (via `with_engine`)
    // to build the deterministic ECDSA sign for the on-the-fly cert-chain PID
    // leaf. The PAL allocates every operand/scratch DMA buffer and keeps the
    // whole sequence on ONE held engine so a `ecc_mont_const_calc`'s Montgomery
    // state stays resident for the ops that follow (`execute_cmd` does not wipe
    // between commands). All operands are PKA little-endian. The modular ops are
    // exposed for all three NIST curves via the driver's per-op opcode selectors;
    // the deterministic PID-leaf sign only exercises P-384 (the alias key curve).

    /// Compute the Montgomery constant for `modulus` (curve prime or order)
    /// and leave it resident in the engine for the next op to consume.
    /// `mont_result` is scratch for the constant; its contents are not used
    /// by the caller directly. The constant is a value `< modulus`, so it fits
    /// the curve point width (matching `ecc_verify`/`ecdh_derive`, which issue
    /// the same opcode with a `hsm_point_size` scratch buffer).
    pub async fn ecc_mont_const_calc(
        &mut self,
        curve: UpkaEccCurve,
        modulus: &DmaBuf,
        mont_result: &mut DmaBuf,
    ) -> HsmResult<()> {
        Self::ensure_cmd_input(
            modulus.len() >= hsm_point_size(curve) && mont_result.len() >= hsm_point_size(curve),
        )?;

        self.execute_cmd(
            mont_const_calc_opcode(curve),
            mont_result.as_mut_ptr() as u32,
            modulus.as_ptr() as u32,
            0,
            0,
        )
        .await
    }

    /// Point-multiply `result = (scalar * point).x`, where `point` is the
    /// affine `x ‖ y` (contiguous, PKA little-endian). Requires a prior
    /// `ecc_mont_const_calc` over the curve prime on this engine.
    pub async fn ecc_point_mul(
        &mut self,
        curve: UpkaEccCurve,
        point_xy: &DmaBuf,
        scalar: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        Self::ensure_cmd_input(
            point_xy.len() >= hsm_point_size(curve) * 2
                && scalar.len() >= hsm_point_size(curve)
                && result.len() >= point_size(curve),
        )?;

        self.execute_cmd(
            ecc_point_mul_opcode(curve),
            result.as_mut_ptr() as u32,
            point_xy.as_ptr() as u32,
            scalar.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Modular reduction `result = arg1 mod n`. Requires a prior
    /// `ecc_mont_const_calc` over the order `n`.
    pub async fn ecc_mod_reduction(
        &mut self,
        curve: UpkaEccCurve,
        result: &mut DmaBuf,
        arg1: &DmaBuf,
    ) -> HsmResult<()> {
        let opcode = mod_reduction_opcode(curve);
        Self::ensure_cmd_input(
            result.len() >= point_size(curve) && arg1.len() >= hsm_point_size(curve) * 2,
        )?;
        self.execute_cmd(
            opcode,
            result.as_mut_ptr() as u32,
            arg1.as_ptr() as u32,
            0,
            0,
        )
        .await
    }

    /// Convert `arg1` into Montgomery representation.
    pub async fn ecc_mont_repr_in(
        &mut self,
        curve: UpkaEccCurve,
        result: &mut DmaBuf,
        arg1: &DmaBuf,
    ) -> HsmResult<()> {
        let opcode = mont_repr_in_opcode(curve);
        Self::ensure_cmd_input(
            result.len() >= mont_operand_size(curve) && arg1.len() >= hsm_point_size(curve),
        )?;
        self.execute_cmd(
            opcode,
            result.as_mut_ptr() as u32,
            arg1.as_ptr() as u32,
            0,
            0,
        )
        .await
    }

    /// Convert `arg1` out of Montgomery representation.
    pub async fn ecc_mont_repr_out(
        &mut self,
        curve: UpkaEccCurve,
        result: &mut DmaBuf,
        arg1: &DmaBuf,
    ) -> HsmResult<()> {
        let opcode = mont_repr_out_opcode(curve);
        Self::ensure_cmd_input(
            result.len() >= point_size(curve) && arg1.len() >= mont_operand_size(curve),
        )?;
        self.execute_cmd(
            opcode,
            result.as_mut_ptr() as u32,
            arg1.as_ptr() as u32,
            0,
            0,
        )
        .await
    }

    /// Modular inverse `result = arg1^-1 mod n`. Requires a prior
    /// `ecc_mont_const_calc` over the order `n`.
    pub async fn ecc_mod_inverse(
        &mut self,
        curve: UpkaEccCurve,
        result: &mut DmaBuf,
        arg1: &DmaBuf,
    ) -> HsmResult<()> {
        let opcode = mod_inverse_opcode(curve);
        Self::ensure_cmd_input(
            result.len() >= mont_operand_size(curve) && arg1.len() >= mont_operand_size(curve),
        )?;
        self.execute_cmd(
            opcode,
            result.as_mut_ptr() as u32,
            arg1.as_ptr() as u32,
            0,
            0,
        )
        .await
    }

    /// Modular multiplication `result = arg1 * arg2 mod n`.
    /// Operands and result are in Montgomery representation.
    pub async fn ecc_mod_mul(
        &mut self,
        curve: UpkaEccCurve,
        result: &mut DmaBuf,
        arg1: &DmaBuf,
        arg2: &DmaBuf,
    ) -> HsmResult<()> {
        let opcode = mod_multiplication_opcode(curve);
        Self::ensure_cmd_input(
            result.len() >= mont_operand_size(curve)
                && arg1.len() >= mont_operand_size(curve)
                && arg2.len() >= mont_operand_size(curve),
        )?;
        self.execute_cmd(
            opcode,
            result.as_mut_ptr() as u32,
            arg1.as_ptr() as u32,
            arg2.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Modular addition `result = arg1 + arg2 mod n`. Operands
    /// and result are in Montgomery representation.
    pub async fn ecc_mod_add(
        &mut self,
        curve: UpkaEccCurve,
        result: &mut DmaBuf,
        arg1: &DmaBuf,
        arg2: &DmaBuf,
    ) -> HsmResult<()> {
        let opcode = mod_addition_opcode(curve);
        Self::ensure_cmd_input(
            result.len() >= mont_operand_size(curve)
                && arg1.len() >= mont_operand_size(curve)
                && arg2.len() >= mont_operand_size(curve),
        )?;
        self.execute_cmd(
            opcode,
            result.as_mut_ptr() as u32,
            arg1.as_ptr() as u32,
            arg2.as_ptr() as u32,
            0,
        )
        .await
    }

    /// Wipe the engine's internal state.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Wipe completed successfully.
    /// - `Err(HsmError)`: Wipe command failed.
    pub async fn memory_wipe(&mut self) -> HsmResult<()> {
        self.execute_cmd(UPKA_MEM_WIPE, 0, 0, 0, 0).await
    }

    /// Wipe and release the engine back to the pool.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Engine was wiped and returned to the scheduler pool.
    /// - `Err(UpkaError::WIPE_FAILED)`: Wipe command failed.
    pub async fn release(mut self) -> HsmResult<()> {
        if self.memory_wipe().await.is_err() {
            return Err(UpkaError::WIPE_FAILED);
        }

        self.released = true;
        self.driver.release_engine(self.id);
        Ok(())
    }

    fn sync_wipe_and_release(&mut self) {
        EngineExecutor::wait_until_idle(self.id);
        self.issue_command(UPKA_MEM_WIPE, 0, 0, 0, 0);
        EngineExecutor::wait_until_idle(self.id);
        self.driver.release_engine(self.id);
    }

    async fn execute_cmd(
        &mut self,
        opcode: u32,
        result: u32,
        arg1: u32,
        arg2: u32,
        arg3: u32,
    ) -> HsmResult<()> {
        self.prepare_for_command();
        self.issue_command(opcode, result, arg1, arg2, arg3);
        poll_fn(|cx| self.poll_completion(cx)).await
    }

    fn prepare_for_command(&self) {
        self.driver.state.with(|s| {
            let slot = &mut s.engine_slots[self.id as usize];
            slot.arm_completion_wait();
        });
    }

    fn issue_command(&self, opcode: u32, result: u32, arg1: u32, arg2: u32, arg3: u32) {
        EngineExecutor::submit_engine_command(self.id, opcode, result, arg1, arg2, arg3);
    }

    fn poll_completion(&self, cx: &mut Context<'_>) -> Poll<HsmResult<()>> {
        self.driver.state.with(|s| {
            let slot = &mut s.engine_slots[self.id as usize];
            if let Some(status) = slot.take_completion_status() {
                Poll::Ready(map_status(status))
            } else {
                slot.register_waiter(cx);
                Poll::Pending
            }
        })
    }
}

impl<const DEPTH: usize, const ENGINES: usize> Drop for UpkaEngine<'_, DEPTH, ENGINES> {
    fn drop(&mut self) {
        if !self.released {
            self.sync_wipe_and_release();
            self.released = true;
        }
    }
}

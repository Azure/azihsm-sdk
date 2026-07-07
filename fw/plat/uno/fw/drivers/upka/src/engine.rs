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
    /// `result` is a caller-allocated DMA-capable buffer (at least 4 bytes)
    /// that receives the hardware status word.
    ///
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `pub_key`: DMA-capable public key buffer.
    /// - `hash`: DMA-capable digest buffer.
    /// - `signature`: DMA-capable signature buffer.
    /// - `result`: DMA-capable output status word buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Verification completed and status was written to `result`.
    /// - `Err(UpkaError::CMD_ERROR)`: Input or output buffer shape is invalid,
    ///   or hardware rejected the command.
    pub async fn ecc_verify(
        &mut self,
        curve: UpkaEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
        result: &mut DmaBuf,
    ) -> HsmResult<()> {
        Self::ensure_cmd_input(
            !pub_key.is_empty()
                && hash.len() >= hash_size(curve)
                && signature.len() >= signature_size(curve)
                && result.len() >= Self::RESULT_WORD_LEN,
        )?;

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
    /// # Parameters
    ///
    /// - `curve`: ECC curve selector.
    /// - `priv_key`: DMA-capable private key buffer.
    /// - `pub_key`: DMA-capable peer public key buffer.
    /// - `secret`: DMA-capable output buffer for the derived secret.
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
    ) -> HsmResult<()> {
        Self::ensure_cmd_input(
            priv_key.len() >= hsm_point_size(curve)
                && pub_key.len() >= hsm_point_size(curve) * 2
                && secret.len() >= point_size(curve),
        )?;

        self.execute_cmd(
            ecc_point_mul_opcode(curve),
            secret.as_mut_ptr() as u32,
            priv_key.as_ptr() as u32,
            pub_key.as_ptr() as u32,
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

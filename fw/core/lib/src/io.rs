// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO dispatch and opcode handling for [`Hsm`].
//!
//! # Pipeline
//!
//! ```text
//!  poll_io ──► handle_io ──► handle_op ──► handle_{generic,flush}_op
//!                  │              │                    │
//!                  │         validate SQE         validate op
//!                  │         dispatch opcode      in-DMA
//!                  │                              session validate
//!                  │                              DDI dispatch
//!                  │                              out-DMA
//!              populate CQE
//!              complete_io
//! ```
//!
//! # Error handling
//!
//! Two-tier model matching mcr-hsm:
//!
//! - **Pre-decode** (SQE validation, inbound DMA, header decode):
//!   Errors return [`OpError`] → CQE gets host status code, no DDI body.
//!
//! - **Post-decode** (session validation, DDI dispatch, command exec):
//!   Errors encode a [`DdiErrCmdResp`] into smem and continue to outbound
//!   DMA. CQE status = Success; host reads error from DDI response body.
//!
//! # Session control
//!
//! Each DDI op maps to a [`SessionCtrl`] kind (NoSession, Open,
//! InSession, Close). Session hijack protection validates the SQE
//! session flags against the decoded DDI header before dispatch.
//! Session state flows back via [`HsmOpStatus`] → CQE DW0/DW1.

use azihsm_fw_ddi::DdiDecoder;
use azihsm_fw_ddi_types::DdiReqHdr;

use super::*;

impl<P: HsmPal> Hsm<P> {
    /// Top-level IO handler invoked by each Embassy send-task.
    ///
    /// Populates CQE header fields, runs the command pipeline, then
    /// writes session fields and status to the CQE before completion.
    pub async fn handle_io(&self, mut io: P::Io) {
        // Gate on partition state — drop IOs for non-enabled partitions.
        {
            let pid = io.pid();
            let enabled = self
                .pal()
                .part_state(pid)
                .is_ok_and(|s| s == PartState::Enabled);
            if !enabled {
                debug!("core", "dropping IO for disabled partition {}", pid);
                if let Err(_e) = self.pal().drop_io(io).await {
                    error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
                }
                return;
            }
        }

        // Populate CQE header fields before dispatch
        {
            let sqe = Sqe::from(io.sqe());
            let cmd_id = sqe.cmd_id();
            let sq_id = io.queue_id();
            let cqe = io.cqe();
            let mut cqe = Cqe::from(cqe);
            cqe.clear();
            cqe.set_cmd_id(cmd_id);
            cqe.set_sq_id(sq_id);
        }

        match self.handle_op(&mut io).await {
            Ok(status) => {
                let cqe = io.cqe();
                let mut cqe = Cqe::from(cqe);
                cqe.set_dw0(CqeDw0::from(status.cqe_dw0_session).with_dst_len(status.resp_len));
                cqe.set_dw1(CqeDw1::from(status.cqe_dw1));
            }
            Err(e) => {
                let cqe = io.cqe();
                let mut cqe = Cqe::from(cqe);
                cqe.set_status(e.status);
                error!("core", e.err, "handle_op failed");
            }
        }

        if let Err(_e) = self.pal().complete_io(io).await {
            error!(
                "core",
                HsmError::CompleteIoFailure,
                "complete_io failed: {:?}",
                _e
            );
        }
    }

    /// Validates common SQE fields and dispatches to the opcode handler.
    async fn handle_op(&self, io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        let sqe = io.sqe();
        let sqe = Sqe::from(sqe);
        sqe.validate()?;
        match sqe.op() {
            OP_GENERIC => self.handle_generic_op(io).await,
            OP_FLUSH => self.handle_flush_op(io).await,
            _ => Err(OpError::new(
                HsmError::UnsupportedCmd,
                HostStatus::INVALID_COMMAND_OPCODE,
            )),
        }
    }

    /// Handles an [`OP_GENERIC`] IO command.
    ///
    /// **Phase 1 (pre-decode)** — SQE validation, inbound DMA, header
    /// decode. Errors → [`OpError`] → CQE host status, no DDI body.
    ///
    /// **Phase 2 (post-decode)** — Session validation, DDI dispatch.
    /// Errors → DDI error response DMA'd to host, CQE Success.
    async fn handle_generic_op(&self, io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        let sqe = io.sqe();
        let sqe = Sqe::from(sqe);
        sqe.validate_generic_op()?;

        let part_id = io.pid();
        let src_len = sqe.src_len() as usize;

        // ── Phase 1: inbound DMA (yield 1) ─────────────────────────
        {
            let src_addr = sqe.src_prp1();
            let (_, smem) = io.mem();
            self.copy_host_to_mem(part_id, src_addr, &mut smem[..src_len])
                .await?;
        }

        // ── Phase 2: decode + validate + dispatch (no yield) ───────
        // All Phase 2 locals scoped so they die before yield 2.
        let (resp_len, session_ctrl) = {
            let session_flags = Sqe::from(io.sqe()).session_flags();
            let sqe_session_id = Sqe::from(io.sqe()).session_id();

            let (fmem, smem) = io.mem();
            let split = src_len.next_multiple_of(4);
            let (req_padded, resp_buf) = smem.split_at_mut(split);
            let req = &req_padded[..src_len];

            let mut decoder = DdiDecoder::new(req);
            let hdr: DdiReqHdr = decoder.decode_hdr().op_err(
                "core",
                HsmError::DdiDecodeFailed,
                HostStatus::REQ_HDR_DECODE_ERR,
            )?;

            let session_ctrl = SessionCtrl::from_op(hdr.op);

            // Session hijack protection
            let resp_len = if let Err(status) =
                Self::validate_session(&hdr, session_ctrl, session_flags, sqe_session_id)
            {
                ddi::encode_ddi_err(hdr.op, status, resp_buf)
                    .op_status("core", HostStatus::INTERNAL_ERROR)?
            } else {
                match ddi::dispatch(&hdr, &mut decoder, part_id, self.pal(), fmem, resp_buf).await {
                    Ok(len) => len,
                    Err(status) => ddi::encode_ddi_err(hdr.op, status, resp_buf)
                        .op_status("core", HostStatus::INTERNAL_ERROR)?,
                }
            };

            (resp_len, session_ctrl)
        };

        // ── Outbound DMA (yield 2) ─────────────────────────────────
        {
            let dst_addr = Sqe::from(io.sqe()).dst_prp1();
            let (_, smem) = io.mem();
            let split = src_len.next_multiple_of(4);
            let resp = &smem[split..split + resp_len];
            self.copy_mem_to_host(part_id, resp, dst_addr).await?;
        }

        Ok(HsmOpStatus::new(resp_len, session_ctrl, None, None, false))
    }

    /// Validate SQE session flags against the decoded DDI header.
    ///
    /// Three rules matching mcr-hsm `validate_session_hijack_protection`:
    ///
    /// 1. SQE `session_ctrl` must match the DDI op's expected kind.
    /// 2. `ctrl`/`id_valid` combinations must be consistent.
    /// 3. SQE `session_id` must match DDI header `sess_id`.
    fn validate_session(
        hdr: &DdiReqHdr,
        expected: SessionCtrl,
        flags: SessionFlags,
        sqe_session_id: u16,
    ) -> HsmResult<()> {
        // Rule 1: SQE ctrl must match DDI op
        if flags.ctrl() != expected as u8 {
            return Err(HsmError::InvalidArg);
        }

        // Rule 2: ctrl/id_valid combinations
        match (expected, flags.id_valid()) {
            (SessionCtrl::NoSession, true) => return Err(HsmError::InvalidArg),
            (SessionCtrl::Open, true) => return Err(HsmError::SessionNotExpected),
            (SessionCtrl::Close, false) => return Err(HsmError::InvalidArg),
            (SessionCtrl::InSession, false) => return Err(HsmError::InvalidArg),
            _ => {}
        }

        // Rule 3: SQE session_id must match DDI header sess_id
        if flags.id_valid() {
            match hdr.sess_id {
                Some(id) if id == sqe_session_id => {}
                _ => return Err(HsmError::InvalidArg),
            }
        } else if hdr.sess_id.is_some() {
            return Err(HsmError::InvalidArg);
        }

        Ok(())
    }

    async fn copy_host_to_mem(
        &self,
        part_id: u8,
        src_prp: HsmDmaAddr,
        dest: &mut [u8],
    ) -> Result<(), OpError> {
        self.pal()
            .copy_mem_from_host(part_id, src_prp, dest, true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )
    }

    async fn copy_mem_to_host(
        &self,
        part_id: u8,
        src: &[u8],
        dst_prp: HsmDmaAddr,
    ) -> Result<(), OpError> {
        self.pal()
            .copy_mem_to_host(part_id, src, dst_prp, true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )
    }

    /// Handles an [`OP_FLUSH`] IO command.
    ///
    /// Returns [`HsmError::IoChannelUnknownOp`] — flush is not yet supported.
    async fn handle_flush_op(&self, _io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        Err(OpError::new(
            HsmError::IoChannelUnknownOp,
            HostStatus::INVALID_COMMAND_OPCODE,
        ))
    }
}

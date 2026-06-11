// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO dispatch and opcode handling for [`Hsm`].
//!
//! # Pipeline
//!
//! ```text
//!  poll_io ──► handle_io ──► handle_{mbor,tbor,flush}_op
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
//! Two-tier model:
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
//! Each MBOR DDI op maps to a [`SessionCtrl`] kind (NoSession, Open,
//! InSession, Close). Session hijack protection validates the SQE
//! session flags against the decoded DDI header before dispatch.
//! Session state flows back via [`HsmOpStatus`] → CQE DW0/DW1.
//!
//! TBOR commands derive their [`SessionCtrl`] from the wire opcode
//! via [`SessionCtrl::from_tbor_opcode`]: `GetApiRev` and
//! `OpenSessionInit` are session-less; `OpenSessionFinish` and
//! `ChangePsk` require the SQE to carry the targeted slot's
//! `session_id`; `CloseSession` is classified as `Close` so the CQE
//! reflects the slot teardown.

use azihsm_fw_ddi_mbor_api::DdiDecoder;
use azihsm_fw_ddi_mbor_types::DdiReqHdr;
use azihsm_fw_ddi_tbor::RequestView as TborRequestView;

use super::*;

impl<P: HsmPal> Hsm<P> {
    /// Top-level IO handler invoked by each Embassy send-task.
    ///
    /// Populates CQE header fields, runs the command pipeline, then
    /// writes session fields and status to the CQE before completion.
    pub async fn handle_io(&self, mut io: P::Io) {
        // Gate on partition state — drop IOs for non-enabled partitions.
        if !self.partition_enabled(&io) {
            debug!("core", "dropping IO for disabled partition {:?}", io.pid());
            if let Err(_e) = self.pal().drop_io(io).await {
                error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
            }
            return;
        }

        // Single SQE parse — extract all fields once, populate CQE, validate,
        // and dispatch.
        let (op, validated) = Self::init_cqe_from_sqe(&mut io);

        let op_result = match validated {
            Err(e) => Err(e),
            Ok(()) => match op {
                OP_MBOR => self.handle_mbor_op(&mut io).await,
                OP_TBOR => self.handle_tbor_op(&mut io).await,
                OP_FLUSH => self.handle_flush_op(&mut io).await,
                _ => Err(OpError::new(
                    HsmError::UnsupportedCmd,
                    HostStatus::INVALID_COMMAND_OPCODE,
                )),
            },
        };
        Self::finalize_cqe(&mut io, op_result);

        if let Err(_e) = self.pal().complete_io(io).await {
            error!(
                "core",
                HsmError::CompleteIoFailure,
                "complete_io failed: {:?}",
                _e
            );
        }
    }

    /// Returns `true` if the partition for this IO can accept host traffic.
    #[inline]
    fn partition_enabled(&self, io: &P::Io) -> bool {
        self.pal()
            .part_state(io)
            .is_ok_and(|s| matches!(s, PartState::Enabled | PartState::Initializing))
    }

    /// Parses the SQE once, populates the CQE header, and returns the
    /// op code along with the SQE-validation result.
    #[inline]
    fn init_cqe_from_sqe(io: &mut P::Io) -> (u16, Result<(), OpError>) {
        let (cmd_id, op, validated) = {
            let sqe = Sqe::from(io.sqe());
            (sqe.cmd_id(), sqe.op(), sqe.validate())
        };
        let sq_id = io.queue_id();
        let mut cqe = Cqe::from(io.cqe());
        cqe.clear();
        cqe.set_cmd_id(cmd_id);
        cqe.set_sq_id(sq_id);
        (op, validated)
    }

    /// Writes the final CQE status from the dispatch result.
    #[inline]
    fn finalize_cqe(io: &mut P::Io, op_result: Result<HsmOpStatus, OpError>) {
        let mut cqe = Cqe::from(io.cqe());
        match op_result {
            Ok(status) => {
                cqe.set_dw0(CqeDw0::from(status.cqe_dw0_session).with_dst_len(status.resp_len));
                cqe.set_dw1(CqeDw1::from(status.cqe_dw1));
            }
            Err(e) => {
                cqe.set_status(e.status);
                error!("core", e.err, "handle_op failed");
            }
        }
    }

    /// Handles an [`OP_MBOR`] IO command.
    ///
    /// **Phase 1 (pre-decode)** — SQE validation, inbound DMA, header
    /// decode. Errors → [`OpError`] → CQE host status, no DDI body.
    ///
    /// **Phase 2 (post-decode)** — Session validation, DDI dispatch.
    /// Errors → DDI error response DMA'd to host, CQE Success.
    async fn handle_mbor_op(&self, io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        let params = Self::decode_io_sqe(io)?;
        let split = params.src_len.next_multiple_of(4);
        let req_buf = self
            .pal()
            .dma_alloc(io, split)
            .op_status(HostStatus::ALLOC_ERR)?;

        // ── Phase 1: inbound DMA (yield 1) ─────────────────────────
        self.pal()
            .copy_mem_from_host(io, params.src_addr, &mut req_buf[..params.src_len], true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        // ── Phase 2: decode + validate + dispatch (no yield) ───────
        let (resp, session_ctrl) = {
            let req = &mut req_buf[..params.src_len];
            let mut decoder = DdiDecoder::new(req);
            let hdr: DdiReqHdr = decoder.decode_hdr().op_err(
                "core",
                HsmError::DdiDecodeFailed,
                HostStatus::REQ_HDR_DECODE_ERR,
            )?;

            let session_ctrl = SessionCtrl::from_op(hdr.op);

            let dispatch_result = match Self::validate_session(
                &hdr,
                session_ctrl,
                params.session_flags,
                params.sqe_session_id,
            ) {
                Ok(()) => ddi::mbor::dispatch(self.pal(), io, &mut decoder, &hdr).await,
                Err(e) => Err(e),
            };

            let resp: &DmaBuf = dispatch_result.or_else(|status| {
                self.pal()
                    .dma_alloc_var(io, |buf| ddi::mbor::encode_ddi_err(hdr.op, status, buf))
                    .op_status(HostStatus::INTERNAL_ERROR)
                    .map(|b| &*b)
            })?;

            (resp, session_ctrl)
        };

        let resp_len = resp.len();

        // ── Outbound DMA (yield 2) ─────────────────────────────────
        self.pal()
            .copy_mem_to_host(io, resp, params.dst_addr, true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        Ok(HsmOpStatus::new(resp_len, session_ctrl, None, None, false))
    }

    /// Handles an [`OP_TBOR`] IO command.
    ///
    /// Mirrors [`Self::handle_mbor_op`] but parses the request body via
    /// the TBOR codec and dispatches by raw `u8` opcode. TBOR commands
    /// are currently sessionless; SQE session flags must indicate
    /// [`SessionCtrl::NoSession`].
    ///
    /// **Phase 1 (pre-decode)** — SQE validation, inbound DMA, TBOR
    /// `RequestView::parse`. Errors → [`OpError`] → CQE host status.
    ///
    /// **Phase 2 (post-decode)** — Dispatch by opcode. Errors are
    /// returned as a TBOR response carrying a non-zero `status` field
    /// (built by the per-opcode handlers via the encoder API). For now,
    /// dispatch errors that cannot construct a typed error response
    /// surface as CQE-level host status codes.
    async fn handle_tbor_op(&self, io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        let params = Self::decode_io_sqe(io)?;
        let split = params.src_len.next_multiple_of(4);
        let req_buf = self
            .pal()
            .dma_alloc(io, split)
            .op_status(HostStatus::ALLOC_ERR)?;

        // ── Phase 1: inbound DMA (yield 1) ─────────────────────────
        self.pal()
            .copy_mem_from_host(io, params.src_addr, &mut req_buf[..params.src_len], true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        // ── Phase 2: parse TBOR header, validate session, dispatch ─
        let (resp, session_ctrl) = {
            // Capture `opcode` via a short-lived shared reborrow so
            // the parsed `RequestView` is dropped before `dispatch`
            // takes a mutable borrow of the same buffer.  AEAD-path
            // handlers (`OpenSessionFinish` / `ChangePsk` / `PartInit`)
            // open envelope sub-views in place via `decode_mut`,
            // which requires `&mut DmaBuf` end-to-end.
            let opcode = {
                let req_view = TborRequestView::parse(&req_buf[..params.src_len]).op_err(
                    "core",
                    HsmError::DdiDecodeFailed,
                    HostStatus::REQ_HDR_DECODE_ERR,
                )?;
                req_view.opcode()
            };

            // Per-opcode session-flag validation: GetApiRev /
            // OpenSessionInit must be sessionless; OpenSessionFinish /
            // CloseSession / ChangePsk must carry the SQE session_id
            // for the targeted slot.  Unknown opcodes are classified as
            // NoSession here so dispatch reaches the handler layer and
            // surfaces `UnsupportedCmd` via a typed TBOR response.
            let session_ctrl = SessionCtrl::from_tbor_opcode(opcode);
            if let Err(_e) = Self::validate_tbor_session_flags(session_ctrl, params.session_flags) {
                let resp: &DmaBuf = self
                    .pal()
                    .dma_alloc_var(io, |buf| {
                        ddi::tbor::encode_tbor_err(opcode, HsmError::InvalidArg, buf)
                    })
                    .op_status(HostStatus::INTERNAL_ERROR)?;
                (resp, session_ctrl)
            } else {
                let dispatch_result = ddi::tbor::dispatch(
                    self.pal(),
                    io,
                    &mut req_buf[..params.src_len],
                    opcode,
                    params.sqe_session_id,
                )
                .await;
                let resp: &DmaBuf = dispatch_result.or_else(|err| {
                    self.pal()
                        .dma_alloc_var(io, |buf| ddi::tbor::encode_tbor_err(opcode, err, buf))
                        .op_status(HostStatus::INTERNAL_ERROR)
                        .map(|b| &*b)
                })?;
                (resp, session_ctrl)
            }
        };

        let resp_len = resp.len();

        // ── Outbound DMA (yield 2) ─────────────────────────────────
        self.pal()
            .copy_mem_to_host(io, resp, params.dst_addr, true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        Ok(HsmOpStatus::new(resp_len, session_ctrl, None, None, false))
    }

    /// Validates the SQE for an MBOR / TBOR IO command and extracts the
    /// fields used by [`Self::handle_mbor_op`] / [`Self::handle_tbor_op`].
    #[inline]
    fn decode_io_sqe(io: &P::Io) -> Result<IoSqeParams, OpError> {
        let sqe = Sqe::from(io.sqe());
        sqe.validate_io_op()?;
        Ok(IoSqeParams {
            src_len: sqe.src_len() as usize,
            src_addr: sqe.src_prp1(),
            dst_addr: sqe.dst_prp1(),
            session_flags: sqe.session_flags(),
            sqe_session_id: sqe.session_id(),
        })
    }

    /// Validate SQE session flags against the decoded DDI header.
    #[inline(always)]
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

    /// TBOR-side analogue of [`Self::validate_session`] that checks
    /// only the SQE-flag shape against the opcode's expected
    /// [`SessionCtrl`].
    ///
    /// Cross-checking the SQE `session_id` against the inline body
    /// `session_id` TOC entry happens in [`ddi::tbor::dispatch`] for
    /// every in-session / close opcode (i.e. every opcode whose
    /// [`SessionCtrl`] requires `id_valid = true`).  This validator
    /// only enforces the `ctrl` / `id_valid` consistency.
    #[inline(always)]
    fn validate_tbor_session_flags(expected: SessionCtrl, flags: SessionFlags) -> HsmResult<()> {
        if flags.ctrl() != expected as u8 {
            return Err(HsmError::InvalidArg);
        }
        match (expected, flags.id_valid()) {
            (SessionCtrl::NoSession, true) => Err(HsmError::InvalidArg),
            (SessionCtrl::Open, true) => Err(HsmError::SessionNotExpected),
            (SessionCtrl::Close, false) => Err(HsmError::InvalidArg),
            (SessionCtrl::InSession, false) => Err(HsmError::InvalidArg),
            _ => Ok(()),
        }
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

/// Fields extracted from a validated MBOR / TBOR IO SQE.
struct IoSqeParams {
    src_len: usize,
    src_addr: HsmDmaAddr,
    dst_addr: HsmDmaAddr,
    session_flags: SessionFlags,
    sqe_session_id: u16,
}

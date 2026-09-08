// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Regression coverage for the platform dispatch hook
//! (`HsmCustomDispatch`) on the MBOR path.
//!
//! When the core's opcode match finds no handler it returns
//! `UnsupportedCmd`, and `io.rs` treats that as its cue to offer the
//! untouched request to the platform. `StdHsmPal` — the PAL the
//! emulator runs — claims nothing and answers `UnsupportedCmd` in turn,
//! so an unclaimed opcode must reach the host as exactly that status.
//!
//! Without this test the whole path is invisible: a wiring mistake that
//! stopped the hook being consulted, or a platform that started
//! claiming opcodes it should not, would leave every existing test
//! passing, because "core rejected it" and "platform declined it"
//! produce the identical status.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// An opcode no core handler implements and no platform claims.
///
/// Picked from the unallocated space, well clear of the `DdiOp` range
/// the core matches on and of `2004`, which uno's `mcr_test_action`
/// build claims for `TestAction`.
const UNCLAIMED_OP: DdiOp = DdiOp(0x7fff_0001);

/// An opcode neither the core nor the platform implements is reported to
/// the host as `UnsupportedCmd`.
#[test]
fn unclaimed_mbor_opcode_reports_unsupported() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Borrow `GetApiRev`'s request shape purely as a carrier —
            // the body is an empty map, so what is exercised is the
            // opcode routing, not the payload.
            let req = DdiGetApiRevCmdReq {
                hdr: DdiReqHdr {
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    op: UNCLAIMED_OP,
                    sess_id: Some(session_id),
                },
                data: DdiGetApiRevReq {},
                ext: None,
            };

            let resp = dev.exec_op_mbor(&req, &mut None);

            assert!(
                matches!(resp, Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))),
                "an unclaimed opcode must surface as UnsupportedCmd, got {resp:?}",
            );
        },
    );
}

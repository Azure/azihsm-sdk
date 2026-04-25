// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for StdHsm.
//!
//! Due to the global HSM OnceLock, only one StdHsm can be active per
//! process. All tests share a single instance via LazyLock.

use std::sync::Arc;

use azihsm_fw_hsm_std::StdHsm;

/// A 4K-aligned buffer for DMA testing.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: AlignedBuf owns its allocation exclusively.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        Self { ptr, len }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    #[allow(dead_code)]
    fn fill(&mut self, val: u8) {
        self.as_mut_slice().fill(val);
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(self.len, 4096).unwrap();
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

/// Build a minimal SQE with cmd_id and no DMA.
fn sqe(cmd_id: u16) -> [u32; 16] {
    let mut data = [0u32; 16];
    data[0] = (cmd_id as u32) << 16;
    data
}

/// Build an SQE with cmd_id and PRP addresses pointing to 4K-aligned buffers.
fn sqe_with_dma(cmd_id: u16, src: &[u8], dst: &mut [u8]) -> [u32; 16] {
    let mut data = [0u32; 16];
    data[0] = (cmd_id as u32) << 16;
    data[1] = src.len() as u32;
    data[6] = dst.len() as u32;

    let src_addr = src.as_ptr() as u64;
    data[2] = src_addr as u32;
    data[3] = (src_addr >> 32) as u32;

    let dst_addr = dst.as_mut_ptr() as u64;
    data[7] = dst_addr as u32;
    data[8] = (dst_addr >> 32) as u32;

    data
}

static HSM: std::sync::LazyLock<Arc<StdHsm>> = std::sync::LazyLock::new(|| Arc::new(StdHsm::new()));

#[tokio::test]
async fn single_io() {
    let c = HSM.submit(sqe(42), 0, 0, 0).await;
    assert_eq!(c.cqe[3] & 0xFFFF, 42);
}

#[tokio::test]
async fn single_io_with_dma() {
    use azihsm_ddi_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    // Encode a DdiGetApiRevCmdReq as the DMA source
    let req_hdr = DdiReqHdr {
        rev: None,
        op: DdiOp::GetApiRev,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(req_hdr, DdiGetApiRevReq {}, src.as_mut_slice(), false)
        .expect("encode");

    let c = HSM
        .submit(
            sqe_with_dma(99, &src.as_slice()[..req_len], dst.as_mut_slice()),
            0,
            0,
            0,
        )
        .await;
    assert_eq!(c.cqe[3] & 0xFFFF, 99);

    // Verify response was written
    let resp_len = (c.cqe[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "response length is zero");
}

#[tokio::test]
async fn multiple_sequential_ios() {
    for i in 0..10u16 {
        let c = HSM.submit(sqe(i), 0, 0, 0).await;
        assert_eq!(c.cqe[3] & 0xFFFF, i as u32);
    }
}

#[tokio::test]
async fn concurrent_ios() {
    let mut handles = Vec::new();
    for i in 100..110u16 {
        let hsm = Arc::clone(&HSM);
        handles.push(tokio::spawn(async move {
            let c = hsm.submit(sqe(i), 0, 0, 0).await;
            assert_eq!(c.cqe[3] & 0xFFFF, i as u32);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn fifty_concurrent_ios() {
    let mut handles = Vec::new();
    for i in 200..250u16 {
        let hsm = Arc::clone(&HSM);
        handles.push(tokio::spawn(async move {
            let c = hsm.submit(sqe(i), 0, 0, 0).await;
            assert_eq!(c.cqe[3] & 0xFFFF, i as u32);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn ddi_get_api_rev() {
    use azihsm_ddi_types::*;

    // Encode a DdiGetApiRevCmdReq
    let mut req_buf = AlignedBuf::new(4096);
    let req_hdr = DdiReqHdr {
        rev: None,
        op: DdiOp::GetApiRev,
        sess_id: None,
    };
    let req_data = DdiGetApiRevReq {};
    let req_len = DdiEncoder::encode_parts(req_hdr, req_data, req_buf.as_mut_slice(), false)
        .expect("encode req");

    // Allocate response buffer
    let mut resp_buf = AlignedBuf::new(4096);

    // Submit with DMA PRPs pointing to our buffers
    let sqe = sqe_with_dma(
        1002,
        &req_buf.as_slice()[..req_len],
        resp_buf.as_mut_slice(),
    );
    let c = HSM.submit(sqe, 0, 0, 0).await;
    assert_eq!(c.cqe[3] & 0xFFFF, 1002, "cmd_id mismatch");

    // Extract actual response length from CQE DW0[15:0]
    let resp_len = (c.cqe[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "response length is zero");

    // Decode the response using actual length
    let mut decoder = DdiDecoder::new(&resp_buf.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.op, DdiOp::GetApiRev);
    assert_eq!(resp_hdr.status, DdiStatus::Success);

    let resp_data: DdiGetApiRevResp = decoder.decode_data().expect("decode resp data");
    assert_eq!(resp_data.min.major, 1);
    assert_eq!(resp_data.min.minor, 0);
    assert_eq!(resp_data.max.major, 1);
    assert_eq!(resp_data.max.minor, 0);

    // CQE status must be Success (0)
    let status = (c.cqe[3] >> 17) & 0x7FF;
    assert_eq!(status, 0, "expected Success status");
}

/// Extract CQE DW3 host status code (bits 27:17).
fn cqe_status(cqe: &[u32; 4]) -> u32 {
    (cqe[3] >> 17) & 0x7FF
}

#[tokio::test]
async fn cqe_status_on_invalid_src_len() {
    // SQE with src_len=0 → InvalidSrcLenFieldInCommand (0x0C1)
    let c = HSM.submit(sqe(500), 0, 0, 0).await;
    assert_eq!(c.cqe[3] & 0xFFFF, 500, "cmd_id");
    assert_eq!(cqe_status(&c.cqe), 0x0C1, "expected InvalidSrcLen");
}

#[tokio::test]
async fn cqe_status_on_invalid_psdt() {
    // SQE with PSDT=1 → InvalidPsdtFieldInCommand (0x0C0)
    let mut data = [0u32; 16];
    data[0] = (501u32 << 16) | (1 << 14); // cmd_id=501, psdt=1
    data[1] = 64; // valid src_len
    data[6] = 64; // valid dst_len
    let c = HSM.submit(data, 0, 0, 0).await;
    assert_eq!(c.cqe[3] & 0xFFFF, 501, "cmd_id");
    assert_eq!(cqe_status(&c.cqe), 0x0C0, "expected InvalidPsdt");
}

#[tokio::test]
async fn cqe_status_success_on_ddi() {
    use azihsm_ddi_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);
    let req_hdr = DdiReqHdr {
        rev: None,
        op: DdiOp::GetApiRev,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(req_hdr, DdiGetApiRevReq {}, src.as_mut_slice(), false)
        .expect("encode");
    let c = HSM
        .submit(
            sqe_with_dma(502, &src.as_slice()[..req_len], dst.as_mut_slice()),
            0,
            0,
            0,
        )
        .await;
    assert_eq!(c.cqe[3] & 0xFFFF, 502, "cmd_id");
    assert_eq!(cqe_status(&c.cqe), 0, "expected Success");
    assert!((c.cqe[0] & 0xFFFF) > 0, "expected non-zero dst_len");
}

#[tokio::test]
async fn ddi_error_response_on_unsupported_rev() {
    use azihsm_ddi_types::*;

    // Encode GetApiRev with rev=Some(...) — triggers DDI_UNSUPPORTED_REV
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);
    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev {
            major: 99,
            minor: 0,
        }),
        op: DdiOp::GetApiRev,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(req_hdr, DdiGetApiRevReq {}, src.as_mut_slice(), false)
        .expect("encode");

    let c = HSM
        .submit(
            sqe_with_dma(600, &src.as_slice()[..req_len], dst.as_mut_slice()),
            0,
            0,
            0,
        )
        .await;

    // Post-decode error: CQE status = Success (error is in DDI body)
    assert_eq!(c.cqe[3] & 0xFFFF, 600, "cmd_id");
    assert_eq!(
        cqe_status(&c.cqe),
        0,
        "expected CQE Success for post-decode error"
    );

    // DDI response body should contain error status
    let resp_len = (c.cqe[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected DDI error response body");

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.op, DdiOp::GetApiRev);
    assert_eq!(
        resp_hdr.status,
        DdiStatus::UnsupportedRevision,
        "expected UnsupportedRevision in DDI response"
    );
}

#[tokio::test]
async fn cqe_session_fields_on_get_api_rev() {
    use azihsm_ddi_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);
    let req_hdr = DdiReqHdr {
        rev: None,
        op: DdiOp::GetApiRev,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(req_hdr, DdiGetApiRevReq {}, src.as_mut_slice(), false)
        .expect("encode");

    // SQE DW11 = 0 → ctrl=NoSession, id_valid=false
    let c = HSM
        .submit(
            sqe_with_dma(700, &src.as_slice()[..req_len], dst.as_mut_slice()),
            0,
            0,
            0,
        )
        .await;

    // CQE DW0: session_ctrl=0 (NoSession), id_valid=false
    let dw0 = c.cqe[0];
    let session_ctrl = (dw0 >> 16) & 0x3;
    let id_valid = (dw0 >> 18) & 0x1;
    assert_eq!(session_ctrl, 0, "expected NoSession");
    assert_eq!(id_valid, 0, "expected id_valid=false");

    // CQE DW1: session_id=0, app_vault_id=0
    assert_eq!(c.cqe[1], 0, "expected session_id=0, app_vault_id=0");
}

#[tokio::test]
async fn session_hijack_mismatched_ctrl() {
    use azihsm_ddi_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    // Encode GetApiRev (NoSession op) but set SQE ctrl=InSession (2)
    let req_hdr = DdiReqHdr {
        rev: None,
        op: DdiOp::GetApiRev,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(req_hdr, DdiGetApiRevReq {}, src.as_mut_slice(), false)
        .expect("encode");

    let mut sqe_data = sqe_with_dma(701, &src.as_slice()[..req_len], dst.as_mut_slice());
    // DW11: set ctrl=2 (InSession) — mismatch with GetApiRev (NoSession)
    sqe_data[11] = 2;

    let c = HSM.submit(sqe_data, 0, 0, 0).await;

    // Post-decode error → CQE Success, DDI error in body
    assert_eq!(c.cqe[3] & 0xFFFF, 701, "cmd_id");
    assert_eq!(
        cqe_status(&c.cqe),
        0,
        "expected CQE Success for session error"
    );

    let resp_len = (c.cqe[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected DDI error response");

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(
        resp_hdr.status,
        DdiStatus::InvalidArg,
        "expected InvalidArg for session ctrl mismatch"
    );
}

#[tokio::test]
async fn ddi_get_device_info() {
    use azihsm_ddi_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetDeviceInfo,
        sess_id: None,
    };
    let req_len =
        DdiEncoder::encode_parts(req_hdr, DdiGetDeviceInfoReq {}, src.as_mut_slice(), false)
            .expect("encode req");

    let c = HSM
        .submit(
            sqe_with_dma(800, &src.as_slice()[..req_len], dst.as_mut_slice()),
            0,
            0,
            0,
        )
        .await;

    assert_eq!(c.cqe[3] & 0xFFFF, 800, "cmd_id");
    assert_eq!(cqe_status(&c.cqe), 0, "expected Success");

    let resp_len = (c.cqe[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected non-zero response");

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.op, DdiOp::GetDeviceInfo);
    assert_eq!(resp_hdr.status, DdiStatus::Success);
    // Rev echoed back
    assert_eq!(resp_hdr.rev, Some(DdiApiRev { major: 1, minor: 0 }));

    let resp_data: DdiGetDeviceInfoResp = decoder.decode_data().expect("decode resp data");
    assert_eq!(resp_data.kind, DdiDeviceKind::Physical);
    assert_eq!(resp_data.tables, 1);
    assert!(!resp_data.fips_approved);
}

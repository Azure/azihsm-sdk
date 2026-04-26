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

/// Partition used by all IO tests. Allocated once via [`ensure_io_part`].
const IO_PID: u8 = 10;

/// Ensure the IO test partition is allocated. Safe to call multiple times.
async fn ensure_io_part() {
    // Ignore AlreadyAllocated — means another test already set it up.
    let _ = HSM.part_alloc(IO_PID, 1).await;
}

#[tokio::test]
async fn single_io() {
    ensure_io_part().await;
    let c = HSM.io(sqe(42), IO_PID, 0, 0).await.expect("io");
    assert_eq!(c[3] & 0xFFFF, 42);
}

#[tokio::test]
async fn single_io_with_dma() {
    use azihsm_ddi_types::*;

    ensure_io_part().await;
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
        .io(
            sqe_with_dma(99, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");
    assert_eq!(c[3] & 0xFFFF, 99);

    // Verify response was written
    let resp_len = (c[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "response length is zero");
}

#[tokio::test]
async fn multiple_sequential_ios() {
    ensure_io_part().await;
    for i in 0..10u16 {
        let c = HSM.io(sqe(i), IO_PID, 0, 0).await.expect("io");
        assert_eq!(c[3] & 0xFFFF, i as u32);
    }
}

#[tokio::test]
async fn concurrent_ios() {
    ensure_io_part().await;
    let mut handles = Vec::new();
    for i in 100..110u16 {
        let hsm = Arc::clone(&HSM);
        handles.push(tokio::spawn(async move {
            let c = hsm.io(sqe(i), IO_PID, 0, 0).await.expect("io");
            assert_eq!(c[3] & 0xFFFF, i as u32);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn fifty_concurrent_ios() {
    ensure_io_part().await;
    let mut handles = Vec::new();
    for i in 200..250u16 {
        let hsm = Arc::clone(&HSM);
        handles.push(tokio::spawn(async move {
            let c = hsm.io(sqe(i), IO_PID, 0, 0).await.expect("io");
            assert_eq!(c[3] & 0xFFFF, i as u32);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn ddi_get_api_rev() {
    use azihsm_ddi_types::*;

    ensure_io_part().await;

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
    let c = HSM.io(sqe, IO_PID, 0, 0).await.expect("io");
    assert_eq!(c[3] & 0xFFFF, 1002, "cmd_id mismatch");

    // Extract actual response length from CQE DW0[15:0]
    let resp_len = (c[0] & 0xFFFF) as usize;
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
    let status = (c[3] >> 17) & 0x7FF;
    assert_eq!(status, 0, "expected Success status");
}

/// Extract CQE DW3 host status code (bits 27:17).
fn cqe_status(cqe: &[u32; 4]) -> u32 {
    (cqe[3] >> 17) & 0x7FF
}

#[tokio::test]
async fn cqe_status_on_invalid_src_len() {
    ensure_io_part().await;
    // SQE with src_len=0 → InvalidSrcLenFieldInCommand (0x0C1)
    let c = HSM.io(sqe(500), IO_PID, 0, 0).await.expect("io");
    assert_eq!(c[3] & 0xFFFF, 500, "cmd_id");
    assert_eq!(cqe_status(&c), 0x0C1, "expected InvalidSrcLen");
}

#[tokio::test]
async fn cqe_status_on_invalid_psdt() {
    ensure_io_part().await;
    // SQE with PSDT=1 → InvalidPsdtFieldInCommand (0x0C0)
    let mut data = [0u32; 16];
    data[0] = (501u32 << 16) | (1 << 14); // cmd_id=501, psdt=1
    data[1] = 64; // valid src_len
    data[6] = 64; // valid dst_len
    let c = HSM.io(data, IO_PID, 0, 0).await.expect("io");
    assert_eq!(c[3] & 0xFFFF, 501, "cmd_id");
    assert_eq!(cqe_status(&c), 0x0C0, "expected InvalidPsdt");
}

#[tokio::test]
async fn cqe_status_success_on_ddi() {
    use azihsm_ddi_types::*;

    ensure_io_part().await;
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
        .io(
            sqe_with_dma(502, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");
    assert_eq!(c[3] & 0xFFFF, 502, "cmd_id");
    assert_eq!(cqe_status(&c), 0, "expected Success");
    assert!((c[0] & 0xFFFF) > 0, "expected non-zero dst_len");
}

#[tokio::test]
async fn ddi_error_response_on_unsupported_rev() {
    use azihsm_ddi_types::*;

    ensure_io_part().await;

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
        .io(
            sqe_with_dma(600, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    // Post-decode error: CQE status = Success (error is in DDI body)
    assert_eq!(c[3] & 0xFFFF, 600, "cmd_id");
    assert_eq!(
        cqe_status(&c),
        0,
        "expected CQE Success for post-decode error"
    );

    // DDI response body should contain error status
    let resp_len = (c[0] & 0xFFFF) as usize;
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

    ensure_io_part().await;
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
        .io(
            sqe_with_dma(700, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    // CQE DW0: session_ctrl=0 (NoSession), id_valid=false
    let dw0 = c[0];
    let session_ctrl = (dw0 >> 16) & 0x3;
    let id_valid = (dw0 >> 18) & 0x1;
    assert_eq!(session_ctrl, 0, "expected NoSession");
    assert_eq!(id_valid, 0, "expected id_valid=false");

    // CQE DW1: session_id=0, app_vault_id=0
    assert_eq!(c[1], 0, "expected session_id=0, app_vault_id=0");
}

#[tokio::test]
async fn session_hijack_mismatched_ctrl() {
    use azihsm_ddi_types::*;

    ensure_io_part().await;
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

    let c = HSM.io(sqe_data, IO_PID, 0, 0).await.expect("io");

    // Post-decode error → CQE Success, DDI error in body
    assert_eq!(c[3] & 0xFFFF, 701, "cmd_id");
    assert_eq!(cqe_status(&c), 0, "expected CQE Success for session error");

    let resp_len = (c[0] & 0xFFFF) as usize;
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
async fn io_dropped_on_disabled_partition() {
    // Partition 63 is never allocated — IO should be dropped.
    let result = HSM.io(sqe(900), 63, 0, 0).await;
    assert!(
        result.is_err(),
        "IO on disabled partition should be dropped"
    );
}

// ---------------------------------------------------------------------------
// Partition sideband tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn part_alloc_single() {
    let result = HSM.part_alloc(0, 1).await;
    assert!(result.is_ok(), "part_alloc(0, 1) failed: {result:?}");
    // Free so subsequent tests see a clean partition 0.
    let _ = HSM.part_free(0).await;
}

#[tokio::test]
async fn part_alloc_free_lifecycle() {
    let pid = 1;
    // Allocate
    HSM.part_alloc(pid, 2).await.expect("alloc");
    // Free
    HSM.part_free(pid).await.expect("free");
    // Should be able to re-allocate after free
    HSM.part_alloc(pid, 3).await.expect("re-alloc");
    HSM.part_free(pid).await.expect("re-free");
}

#[tokio::test]
async fn part_alloc_invalid_pid() {
    let result = HSM.part_alloc(65, 1).await;
    assert!(result.is_err(), "pid=65 should fail");

    let result = HSM.part_alloc(255, 1).await;
    assert!(result.is_err(), "pid=255 should fail");
}

#[tokio::test]
async fn part_free_invalid_pid() {
    let result = HSM.part_free(65).await;
    assert!(result.is_err(), "free pid=65 should fail");
}

#[tokio::test]
async fn part_free_disabled() {
    // Partition 60 was never allocated — freeing should fail.
    let result = HSM.part_free(60).await;
    assert!(result.is_err(), "free of disabled partition should fail");
}

#[tokio::test]
async fn part_double_alloc() {
    let pid = 2;
    HSM.part_alloc(pid, 1).await.expect("first alloc");
    let result = HSM.part_alloc(pid, 1).await;
    assert!(result.is_err(), "double alloc should fail");
    HSM.part_free(pid).await.expect("cleanup");
}

#[tokio::test]
async fn part_resource_exhaustion() {
    // Allocate partitions using up to 65 total resources.
    // Use pids 50..55 with res_count=13 each → 5×13 = 65
    for pid in 50..55u8 {
        HSM.part_alloc(pid, 13).await.expect("alloc");
    }

    // Next allocation should fail — even res_count=1 exceeds budget
    let result = HSM.part_alloc(55, 1).await;
    assert!(
        result.is_err(),
        "should fail when total resources would exceed 65"
    );

    // Cleanup
    for pid in 50..55u8 {
        HSM.part_free(pid).await.expect("cleanup");
    }
}

#[tokio::test]
async fn part_resource_accounting_after_free() {
    // Allocate 3 partitions: 20 + 20 + 20 = 60
    for pid in 40..43u8 {
        HSM.part_alloc(pid, 20).await.expect("alloc");
    }

    // Can't alloc 6 more (60 + 6 > 65)
    let result = HSM.part_alloc(43, 6).await;
    assert!(result.is_err(), "60+6 > 65 should fail");

    // Free one (back to 40 used)
    HSM.part_free(41).await.expect("free middle");

    // Now can alloc up to 25 (40 + 25 = 65)
    HSM.part_alloc(43, 25).await.expect("alloc after free");

    // Cleanup
    for pid in [40u8, 42, 43] {
        HSM.part_free(pid).await.expect("cleanup");
    }
}

#[tokio::test]
async fn ddi_get_device_info() {
    use azihsm_ddi_types::*;

    ensure_io_part().await;
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
        .io(
            sqe_with_dma(800, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(c[3] & 0xFFFF, 800, "cmd_id");
    assert_eq!(cqe_status(&c), 0, "expected Success");

    let resp_len = (c[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected non-zero response");

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.op, DdiOp::GetDeviceInfo);
    assert_eq!(resp_hdr.status, DdiStatus::Success);
    // Rev echoed back
    assert_eq!(resp_hdr.rev, Some(DdiApiRev { major: 1, minor: 0 }));

    let resp_data: DdiGetDeviceInfoResp = decoder.decode_data().expect("decode resp data");
    assert_eq!(resp_data.kind, DdiDeviceKind::Physical);
    // tables = part_res_count for IO_PID (allocated with 1 resource)
    assert_eq!(resp_data.tables, 1);
    assert!(!resp_data.fips_approved);
}

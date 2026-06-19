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

/// Ensure the IO test partition is allocated and enabled. Safe to call multiple times.
async fn ensure_io_part() {
    // Ignore errors — means another test already set it up.
    let _ = HSM.part_alloc(IO_PID, 1u128 << IO_PID).await;
    let _ = HSM.part_enable(IO_PID).await;
}

#[tokio::test]
async fn single_io() {
    ensure_io_part().await;
    let c = HSM.io(sqe(42), IO_PID, 0, 0).await.expect("io");
    assert_eq!(c[3] & 0xFFFF, 42);
}

#[tokio::test]
async fn single_io_with_dma() {
    use azihsm_ddi_mbor_types::*;

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
    use azihsm_ddi_mbor_types::*;

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
    use azihsm_ddi_mbor_types::*;

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
    use azihsm_ddi_mbor_types::*;

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
    use azihsm_ddi_mbor_types::*;

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
    use azihsm_ddi_mbor_types::*;

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
    let result = HSM.part_alloc(0, 1u128 << 0).await;
    assert!(result.is_ok(), "part_alloc(0, mask) failed: {result:?}");
    // Free so subsequent tests see a clean partition 0.
    let _ = HSM.part_free(0).await;
}

#[tokio::test]
async fn part_alloc_free_lifecycle() {
    let pid = 1;
    // Allocate with 2 resources (bits 10,11)
    HSM.part_alloc(pid, 0b11 << 10).await.expect("alloc");
    // Free
    HSM.part_free(pid).await.expect("free");
    // Should be able to re-allocate after free with different mask
    HSM.part_alloc(pid, 0b111 << 10).await.expect("re-alloc");
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
    HSM.part_alloc(pid, 1u128 << 20).await.expect("first alloc");
    let result = HSM.part_alloc(pid, 1u128 << 21).await;
    assert!(result.is_err(), "double alloc should fail");
    HSM.part_free(pid).await.expect("cleanup");
}

#[tokio::test]
async fn part_resource_exhaustion() {
    // Allocate partitions using up to 65 total resources via bitmasks.
    // pid 50: bits 0..12 (13 bits), pid 51: bits 13..25, etc.
    for (i, pid) in (50..55u8).enumerate() {
        let shift = i * 13;
        let mask = ((1u128 << 13) - 1) << shift;
        HSM.part_alloc(pid, mask).await.expect("alloc");
    }

    // All 65 resources allocated (5×13). Next should overlap.
    let result = HSM.part_alloc(55, 1u128 << 0).await;
    assert!(result.is_err(), "should fail when resources overlap");

    // Cleanup
    for pid in 50..55u8 {
        HSM.part_free(pid).await.expect("cleanup");
    }
}

#[tokio::test]
async fn part_resource_accounting_after_free() {
    // Allocate 3 partitions with non-overlapping masks: 20 bits each.
    // pid 40: bits 0..19, pid 41: bits 20..39, pid 42: bits 40..59
    for (i, pid) in (40..43u8).enumerate() {
        let shift = i * 20;
        let mask = ((1u128 << 20) - 1) << shift;
        HSM.part_alloc(pid, mask).await.expect("alloc");
    }

    // Can't alloc overlapping bit (bit 0 already taken by pid 40)
    let result = HSM.part_alloc(43, 1u128 << 0).await;
    assert!(result.is_err(), "overlapping resource should fail");

    // Free pid 41 (releases bits 20..39)
    HSM.part_free(41).await.expect("free middle");

    // Now can alloc bits 20..39 + bits 60..64 = 25 resources
    let mask = ((1u128 << 20) - 1) << 20 | ((1u128 << 5) - 1) << 60;
    HSM.part_alloc(43, mask).await.expect("alloc after free");

    // Cleanup
    for pid in [40u8, 42, 43] {
        HSM.part_free(pid).await.expect("cleanup");
    }
}

#[tokio::test]
async fn ddi_get_device_info() {
    use azihsm_ddi_mbor_types::*;

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

// ---------------------------------------------------------------------------
// Certificate chain tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_cert_chain_info_slot0() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetCertChainInfo,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(
        req_hdr,
        DdiGetCertChainInfoReq { slot_id: 0 },
        src.as_mut_slice(),
        false,
    )
    .expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(1108, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(cqe_status(&c), 0, "expected Success");

    let resp_len = (c[0] & 0xFFFF) as usize;
    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let hdr: DdiRespHdr = decoder.decode_hdr().expect("decode hdr");
    assert_eq!(hdr.op, DdiOp::GetCertChainInfo);
    assert_eq!(hdr.status, DdiStatus::Success);

    let data: DdiGetCertChainInfoResp = decoder.decode_data().expect("decode data");
    assert_eq!(data.num_certs, 4, "slot 0 should have 4 certs");
    assert_eq!(data.thumbprint.len(), 32, "thumbprint should be 32 bytes");
    // Thumbprint must not be all zeros
    assert!(
        data.thumbprint.as_slice().iter().any(|&b| b != 0),
        "thumbprint must not be all zeros"
    );
}

#[tokio::test]
async fn get_cert_chain_info_invalid_slot() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetCertChainInfo,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(
        req_hdr,
        DdiGetCertChainInfoReq { slot_id: 1 },
        src.as_mut_slice(),
        false,
    )
    .expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(1108, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    // DDI errors are returned inside the response body with a non-Success status
    let resp_len = (c[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected error response body");
    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let hdr: DdiRespHdr = decoder.decode_hdr().expect("decode hdr");
    assert_ne!(hdr.status, DdiStatus::Success, "expected error status");
}

/// Helper to retrieve a single certificate by index.
async fn get_cert_der(idx: u8) -> Vec<u8> {
    use azihsm_ddi_mbor_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetCertificate,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(
        req_hdr,
        DdiGetCertificateReq {
            slot_id: 0,
            cert_id: idx,
        },
        src.as_mut_slice(),
        false,
    )
    .expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(1109, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(cqe_status(&c), 0, "cert idx {idx}: expected Success");

    let resp_len = (c[0] & 0xFFFF) as usize;
    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let hdr: DdiRespHdr = decoder.decode_hdr().expect("decode hdr");
    assert_eq!(hdr.op, DdiOp::GetCertificate);
    assert_eq!(hdr.status, DdiStatus::Success);

    let data: DdiGetCertificateResp = decoder.decode_data().expect("decode data");
    data.certificate.as_slice().to_vec()
}

#[tokio::test]
async fn get_certificate_all_indices() {
    ensure_io_part().await;

    for idx in 0..4u8 {
        let cert = get_cert_der(idx).await;
        assert!(
            cert.len() > 100,
            "cert idx {idx}: cert too short ({})",
            cert.len()
        );
    }
}

#[tokio::test]
async fn get_certificate_invalid_index() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetCertificate,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(
        req_hdr,
        DdiGetCertificateReq {
            slot_id: 0,
            cert_id: 4,
        },
        src.as_mut_slice(),
        false,
    )
    .expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(1109, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    // DDI errors are returned inside the response body with a non-Success status
    let resp_len = (c[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected error response body");
    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let hdr: DdiRespHdr = decoder.decode_hdr().expect("decode hdr");
    assert_ne!(hdr.status, DdiStatus::Success, "expected error status");
}

#[tokio::test]
async fn get_certificate_chain_validation() {
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    ensure_io_part().await;

    // Retrieve all 4 certs
    let root_der = get_cert_der(0).await;
    let deviceid_der = get_cert_der(1).await;
    let alias_der = get_cert_der(2).await;
    let leaf_der = get_cert_der(3).await;

    // Parse all certs
    let root = X509Certificate::from_der(&root_der).expect("parse root");
    let deviceid = X509Certificate::from_der(&deviceid_der).expect("parse deviceid");
    let alias = X509Certificate::from_der(&alias_der).expect("parse alias");
    let leaf = X509Certificate::from_der(&leaf_der).expect("parse leaf");

    // Validate chain: leaf → alias → deviceid → root
    assert!(
        leaf.validate_chain(&[alias, deviceid, root])
            .expect("validate chain"),
        "cert chain validation failed"
    );
}

#[tokio::test]
async fn get_cert_thumbprint_consistency() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;

    // Call GetCertChainInfo twice — thumbprint must be identical
    let get_thumbprint = || async {
        let mut src = AlignedBuf::new(4096);
        let mut dst = AlignedBuf::new(4096);

        let req_hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
            op: DdiOp::GetCertChainInfo,
            sess_id: None,
        };
        let req_len = DdiEncoder::encode_parts(
            req_hdr,
            DdiGetCertChainInfoReq { slot_id: 0 },
            src.as_mut_slice(),
            false,
        )
        .expect("encode req");

        let c = HSM
            .io(
                sqe_with_dma(1108, &src.as_slice()[..req_len], dst.as_mut_slice()),
                IO_PID,
                0,
                0,
            )
            .await
            .expect("io");

        let resp_len = (c[0] & 0xFFFF) as usize;
        let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
        let _: DdiRespHdr = decoder.decode_hdr().expect("hdr");
        let data: DdiGetCertChainInfoResp = decoder.decode_data().expect("data");
        data.thumbprint.as_slice().to_vec()
    };

    let tp1 = get_thumbprint().await;
    let tp2 = get_thumbprint().await;
    assert_eq!(tp1, tp2, "thumbprint must be stable across calls");
}

#[tokio::test]
async fn dump_cert_chain_openssl() {
    ensure_io_part().await;

    let names = ["Root CA", "DeviceId CA", "Alias CA", "Partition Leaf"];

    for idx in 0..4u8 {
        let der = get_cert_der(idx).await;

        // Write DER to a temp file
        let path = std::env::temp_dir().join(format!("azihsm_cert_{idx}.der"));
        std::fs::write(&path, &der).expect("write cert");

        // Run openssl x509 to dump cert text
        let output = std::process::Command::new("openssl")
            .args(["x509", "-inform", "DER", "-in"])
            .arg(&path)
            .args(["-text", "-noout"])
            .output()
            .expect("openssl x509");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "openssl failed for cert {idx} ({}):\n{stderr}",
            names[idx as usize]
        );

        eprintln!("=== [{idx}] {} ===\n{stdout}", names[idx as usize]);

        // Clean up
        let _ = std::fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------
// SHA Digest tests (NIST FIPS 180-4 KAT: message = "abc")
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ddi_sha1_digest() {
    use azihsm_ddi_mbor_codec::MborByteArray;
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::ShaDigest,
        sess_id: None,
    };
    let req_data = DdiShaDigestReq {
        sha_mode: DdiHashAlgorithm::Sha1,
        msg: MborByteArray::from_slice(b"abc").expect("msg"),
    };
    let req_len =
        DdiEncoder::encode_parts(req_hdr, req_data, src.as_mut_slice(), false).expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(900, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(cqe_status(&c), 0, "expected Success");
    let resp_len = (c[0] & 0xFFFF) as usize;

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.status, DdiStatus::Success);

    let resp_data: DdiShaDigestResp = decoder.decode_data().expect("decode resp data");

    let expected = hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
    assert_eq!(resp_data.digest.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn ddi_sha256_digest() {
    use azihsm_ddi_mbor_codec::MborByteArray;
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::ShaDigest,
        sess_id: None,
    };
    let req_data = DdiShaDigestReq {
        sha_mode: DdiHashAlgorithm::Sha256,
        msg: MborByteArray::from_slice(b"abc").expect("msg"),
    };
    let req_len =
        DdiEncoder::encode_parts(req_hdr, req_data, src.as_mut_slice(), false).expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(901, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(cqe_status(&c), 0, "expected Success");
    let resp_len = (c[0] & 0xFFFF) as usize;

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.status, DdiStatus::Success);

    let resp_data: DdiShaDigestResp = decoder.decode_data().expect("decode resp data");

    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
    assert_eq!(resp_data.digest.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn ddi_sha384_digest() {
    use azihsm_ddi_mbor_codec::MborByteArray;
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::ShaDigest,
        sess_id: None,
    };
    let req_data = DdiShaDigestReq {
        sha_mode: DdiHashAlgorithm::Sha384,
        msg: MborByteArray::from_slice(b"abc").expect("msg"),
    };
    let req_len =
        DdiEncoder::encode_parts(req_hdr, req_data, src.as_mut_slice(), false).expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(902, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(cqe_status(&c), 0, "expected Success");
    let resp_len = (c[0] & 0xFFFF) as usize;

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.status, DdiStatus::Success);

    let resp_data: DdiShaDigestResp = decoder.decode_data().expect("decode resp data");

    let expected = hex::decode(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    )
    .unwrap();
    assert_eq!(resp_data.digest.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn ddi_sha512_digest() {
    use azihsm_ddi_mbor_codec::MborByteArray;
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::ShaDigest,
        sess_id: None,
    };
    let req_data = DdiShaDigestReq {
        sha_mode: DdiHashAlgorithm::Sha512,
        msg: MborByteArray::from_slice(b"abc").expect("msg"),
    };
    let req_len =
        DdiEncoder::encode_parts(req_hdr, req_data, src.as_mut_slice(), false).expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(903, &src.as_slice()[..req_len], dst.as_mut_slice()),
            IO_PID,
            0,
            0,
        )
        .await
        .expect("io");

    assert_eq!(cqe_status(&c), 0, "expected Success");
    let resp_len = (c[0] & 0xFFFF) as usize;

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode resp hdr");
    assert_eq!(resp_hdr.status, DdiStatus::Success);

    let resp_data: DdiShaDigestResp = decoder.decode_data().expect("decode resp data");

    let expected = hex::decode(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )
    .unwrap();
    assert_eq!(resp_data.digest.as_slice(), expected.as_slice());
}

// ---------------------------------------------------------------------------
// GetEstablishCredEncryptionKey tests
// ---------------------------------------------------------------------------

/// Helper: encode a GetEstablishCredEncryptionKey request and submit IO.
/// Returns (CQE, response bytes).
async fn submit_get_establish_cred_enc_key(
    pid: u8,
    cmd_id: u16,
    sess_id: Option<u16>,
) -> ([u32; 4], Vec<u8>) {
    use azihsm_ddi_mbor_types::*;

    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetEstablishCredEncryptionKey,
        sess_id,
    };
    let req_len = DdiEncoder::encode_parts(
        req_hdr,
        DdiGetEstablishCredEncryptionKeyReq {},
        src.as_mut_slice(),
        false,
    )
    .expect("encode req");

    let c = HSM
        .io(
            sqe_with_dma(cmd_id, &src.as_slice()[..req_len], dst.as_mut_slice()),
            pid,
            0,
            0,
        )
        .await
        .expect("io");

    let resp_len = (c[0] & 0xFFFF) as usize;
    let resp_bytes = dst.as_slice()[..resp_len].to_vec();
    (c, resp_bytes)
}

#[tokio::test]
async fn get_establish_cred_encryption_key_basic() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;

    let (c, resp_bytes) = submit_get_establish_cred_enc_key(IO_PID, 1101, None).await;

    assert_eq!(c[3] & 0xFFFF, 1101, "cmd_id");
    assert_eq!(cqe_status(&c), 0, "expected CQE Success");
    assert!(!resp_bytes.is_empty(), "expected non-empty response");

    let mut decoder = DdiDecoder::new(&resp_bytes, false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode hdr");
    assert_eq!(resp_hdr.op, DdiOp::GetEstablishCredEncryptionKey);
    assert_eq!(resp_hdr.status, DdiStatus::Success);

    let resp_data: DdiGetEstablishCredEncryptionKeyResp =
        decoder.decode_data().expect("decode data");

    // Public key should be non-zero (96 bytes for P-384 x∥y)
    let pub_key_bytes = resp_data.pub_key.der.as_slice();
    assert!(!pub_key_bytes.is_empty(), "expected non-empty public key");
    assert_eq!(resp_data.pub_key.key_kind, DdiKeyType::Ecc384Public);

    // Nonce must be 32 bytes
    assert_eq!(resp_data.nonce.len(), 32);
    assert_ne!(resp_data.nonce, [0u8; 32], "nonce should not be all zeros");

    // Signature must be non-empty (96 bytes for P-384 r∥s)
    let sig = resp_data.pub_key_signature.as_slice();
    assert!(!sig.is_empty(), "expected non-empty signature");
}

#[tokio::test]
async fn get_establish_cred_encryption_key_idempotent() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;

    let (_, resp_bytes1) = submit_get_establish_cred_enc_key(IO_PID, 1102, None).await;
    let (_, resp_bytes2) = submit_get_establish_cred_enc_key(IO_PID, 1103, None).await;

    let mut dec1 = DdiDecoder::new(&resp_bytes1, false);
    let _: DdiRespHdr = dec1.decode_hdr().expect("hdr1");
    let data1: DdiGetEstablishCredEncryptionKeyResp = dec1.decode_data().expect("data1");

    let mut dec2 = DdiDecoder::new(&resp_bytes2, false);
    let _: DdiRespHdr = dec2.decode_hdr().expect("hdr2");
    let data2: DdiGetEstablishCredEncryptionKeyResp = dec2.decode_data().expect("data2");

    assert_eq!(
        data1.pub_key.der.as_slice(),
        data2.pub_key.der.as_slice(),
        "public key must be stable across calls"
    );
    assert_eq!(
        data1.nonce, data2.nonce,
        "nonce must be stable across calls"
    );
}

#[tokio::test]
async fn get_establish_cred_encryption_key_session_rejected() {
    use azihsm_ddi_mbor_types::*;

    ensure_io_part().await;

    // Submit with SQE session_ctrl=InSession — should get DDI error
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);

    let req_hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op: DdiOp::GetEstablishCredEncryptionKey,
        sess_id: None,
    };
    let req_len = DdiEncoder::encode_parts(
        req_hdr,
        DdiGetEstablishCredEncryptionKeyReq {},
        src.as_mut_slice(),
        false,
    )
    .expect("encode req");

    // Tamper SQE DW11: set ctrl=InSession (2) — mismatch with NoSession
    let mut sqe_data = sqe_with_dma(1104, &src.as_slice()[..req_len], dst.as_mut_slice());
    sqe_data[11] = 2; // ctrl=InSession

    let c = HSM.io(sqe_data, IO_PID, 0, 0).await.expect("io");

    assert_eq!(cqe_status(&c), 0, "expected CQE Success for session error");

    let resp_len = (c[0] & 0xFFFF) as usize;
    assert!(resp_len > 0, "expected DDI error response body");

    let mut decoder = DdiDecoder::new(&dst.as_slice()[..resp_len], false);
    let resp_hdr: DdiRespHdr = decoder.decode_hdr().expect("decode hdr");
    assert_eq!(
        resp_hdr.status,
        DdiStatus::InvalidArg,
        "expected InvalidArg for session ctrl mismatch"
    );
}

#[tokio::test]
async fn get_establish_cred_encryption_key_verify_signature() {
    use azihsm_crypto::*;
    use azihsm_ddi_mbor_types::*;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    ensure_io_part().await;

    // 1. Get the partition leaf cert (index 3)
    let leaf_der = get_cert_der(3).await;
    let leaf = X509Certificate::from_der(&leaf_der).expect("parse leaf cert");
    let leaf_pub_key_der = leaf
        .get_public_key_der()
        .expect("get pub key DER from leaf cert");

    // 2. Parse the leaf cert's public key
    let verifier_key =
        EccPublicKey::from_bytes(&leaf_pub_key_der).expect("parse leaf pub key as EccPublicKey");

    // 3. Get the establish-cred encryption key
    let (c, resp_bytes) = submit_get_establish_cred_enc_key(IO_PID, 1105, None).await;
    assert_eq!(cqe_status(&c), 0, "expected Success");

    let mut decoder = DdiDecoder::new(&resp_bytes, false);
    let _: DdiRespHdr = decoder.decode_hdr().expect("hdr");
    let data: DdiGetEstablishCredEncryptionKeyResp = decoder.decode_data().expect("data");

    let pub_key_raw = data.pub_key.der.as_slice();
    let signature_raw = data.pub_key_signature.as_slice();

    // 4. Hash the public key with SHA-384.  Fw hashed the same
    // wire-LE coordinate bytes (raw output of pub_key.der without
    // post-decode), so we hash the same bytes the test reads.
    let digest = Hasher::hash_vec(&mut HashAlgo::sha384(), pub_key_raw).expect("sha384");

    // 5. Convert the wire-LE signature (r_le || s_le, P-384 → 48 +
    // 48) into OpenSSL's BE `r || s`.  The DDI decoder is invoked
    // with `post_decode = false`, so we re-do the LE→BE flip
    // (equivalent of `ecc_signature_post_decode`) inline here.
    assert_eq!(signature_raw.len(), 96, "P-384 wire signature length");
    let mut signature_be = [0u8; 96];
    for (dst, src) in signature_be[..48]
        .iter_mut()
        .zip(signature_raw[..48].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in signature_be[48..96]
        .iter_mut()
        .zip(signature_raw[48..96].iter().rev())
    {
        *dst = *src;
    }

    // 6. Verify signature: raw EC verify (digest, signature) with leaf key.
    let result = Verifier::verify(
        &mut EccAlgo::default(),
        &verifier_key,
        &digest,
        &signature_be,
    );
    assert!(
        result.is_ok(),
        "signature verification failed: {:?}",
        result
    );
    assert!(result.unwrap(), "signature over public key is invalid");
}

#[tokio::test]
async fn get_establish_cred_encryption_key_changes_after_reenable() {
    use azihsm_ddi_mbor_types::*;

    // Use a dedicated partition for this test to avoid interfering with others
    let pid: u8 = 15;
    HSM.part_alloc(pid, 1u128 << pid)
        .await
        .expect("alloc pid 15");
    HSM.part_enable(pid).await.expect("enable pid 15");

    // Get the key before
    let (c1, resp_bytes1) = submit_get_establish_cred_enc_key(pid, 1106, None).await;
    assert_eq!(cqe_status(&c1), 0, "expected Success");

    let mut dec1 = DdiDecoder::new(&resp_bytes1, false);
    let _: DdiRespHdr = dec1.decode_hdr().expect("hdr1");
    let data1: DdiGetEstablishCredEncryptionKeyResp = dec1.decode_data().expect("data1");
    let old_pub_key = data1.pub_key.der.data().to_vec();
    let old_nonce = data1.nonce;

    // Disable and re-enable the partition
    HSM.part_disable(pid).await.expect("disable pid 15");
    HSM.part_enable(pid).await.expect("re-enable pid 15");

    // Get the key after
    let (c2, resp_bytes2) = submit_get_establish_cred_enc_key(pid, 1107, None).await;
    assert_eq!(cqe_status(&c2), 0, "expected Success");

    let mut dec2 = DdiDecoder::new(&resp_bytes2, false);
    let _: DdiRespHdr = dec2.decode_hdr().expect("hdr2");
    let data2: DdiGetEstablishCredEncryptionKeyResp = dec2.decode_data().expect("data2");

    assert_ne!(
        old_pub_key,
        data2.pub_key.der.data(),
        "public key must change after re-enable"
    );
    assert_ne!(old_nonce, data2.nonce, "nonce must change after re-enable");

    // Cleanup
    HSM.part_free(pid).await.expect("free pid 15");
}

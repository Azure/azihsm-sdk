// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmGdmaController`] implementation for the std PAL.
//!
//! Delegates to [`StdGdma`](crate::drivers::gdma::StdGdma) for all
//! GDMA operations.

use azihsm_fw_hsm_pal_traits::*;

use crate::StdHsmPal;

impl HsmGdmaController for StdHsmPal {
    /// Copy data between HSM-local buffers.
    async fn copy_mem(&self, _io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()> {
        self.gdma.copy_mem(src, dst);
        Ok(())
    }

    /// Zero an HSM-local buffer (software volatile wipe on the std
    /// platform). [`DmaBuf::zeroize`] guarantees the writes are not
    /// optimized away so key material is actually scrubbed.
    async fn zeroize_mem(&self, _io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()> {
        dst.zeroize();
        Ok(())
    }

    /// Copy from host memory into an HSM buffer.
    ///
    /// Interprets the PRP address as a raw host pointer.
    async fn copy_mem_from_host(
        &self,
        _io: &impl HsmIo,
        src: HsmDmaAddr,
        dst: &mut DmaBuf,
        _prp: bool,
    ) -> HsmResult<()> {
        // SAFETY: In the std platform, PRP addresses are raw host-process
        // pointers set up by the caller (test harness or integration test).
        // The caller is responsible for ensuring the address is valid and
        // the buffer remains alive for the duration of the copy.
        unsafe { self.gdma.copy_mem_from_host(src, dst) };
        Ok(())
    }

    /// Copy from host memory into an HSM buffer, sourced from a raw
    /// 16-byte NVMe SGL Data Block descriptor (first dword = host
    /// pointer, `length` field = transfer size).
    async fn copy_mem_from_host_raw(
        &self,
        _io: &impl HsmIo,
        desc: &[u8; 16],
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        // Only inline SGL Data Block descriptors are supported here.
        if prp {
            return Err(HsmError::UnsupportedCmd);
        }
        // The std PAL dereferences the descriptor's source address as a
        // raw host-process pointer (unlike the uno PAL, where the GDMA
        // hardware consumes the descriptor and interprets its SGL format),
        // so validate the length + source address before the copy.
        crate::drivers::gdma::validate_raw_src(desc, dst.len())?;
        // SAFETY: see `copy_mem_from_host` — std PRP addresses are raw
        // host-process pointers the caller guarantees valid and alive;
        // `validate_raw_src` rejects a null source for `len > 0`, and the
        // descriptor length equals `dst.len()`.
        unsafe { self.gdma.copy_mem_from_host_raw(desc, dst) };
        Ok(())
    }

    /// Copy from an HSM buffer to host memory.
    ///
    /// Interprets the PRP address as a raw host pointer.
    async fn copy_mem_to_host(
        &self,
        _io: &impl HsmIo,
        src: &DmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        _prp: bool,
    ) -> HsmResult<()> {
        // Split exactly as uno does, via the same shared rule. Nothing here
        // needs it -- host memory is flat and a single memcpy would work --
        // but the emulator is where this gets exercised, and it can only
        // catch a boundary mistake if it performs the same two copies into
        // the same two independent pages.
        let (head_len, tail_len) = host_resp_split(src.len()).ok_or(HsmError::InvalidArg)?;
        let (head, tail) = src.split_at(head_len);

        // SAFETY: In the std platform, PRP addresses are raw host-process
        // pointers set up by the caller (test harness or integration test).
        // The caller is responsible for ensuring the address is valid and
        // the buffer remains alive for the duration of the copy.
        unsafe { self.gdma.copy_mem_to_host(head, dst) };

        if tail_len == 0 {
            return Ok(());
        }

        if dst2.is_null() {
            return Err(HsmError::InvalidArg);
        }

        // SAFETY: as above; `tail` is the remaining `tail_len` bytes.
        unsafe { self.gdma.copy_mem_to_host(tail, dst2) };
        Ok(())
    }
}

#[cfg(test)]
mod resp_page_tests {
    use azihsm_fw_hsm_pal_traits::HOST_RESP_PAGE_LEN;
    use tokio::runtime::Handle;

    use super::*;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// Writes `len` bytes of a position-dependent pattern through
    /// `copy_mem_to_host` into two **separately allocated** host pages, and
    /// returns them.
    ///
    /// Separate allocations are the point. A single 8 KiB buffer would hide
    /// exactly the bug this guards against -- writing straight past the end
    /// of the first page instead of starting again at the second -- because
    /// the two would happen to be adjacent.
    async fn split_write(len: usize) -> (Vec<u8>, Vec<u8>, HsmResult<()>) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        let src = pal.dma_alloc(&io, len).unwrap();
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let mut page1 = vec![0u8; HOST_RESP_PAGE_LEN];
        let mut page2 = vec![0u8; HOST_RESP_PAGE_LEN];
        let a1 = ptr_to_addr(page1.as_mut_ptr());
        let a2 = ptr_to_addr(page2.as_mut_ptr());

        let r = pal.copy_mem_to_host(&io, src, a1, a2, true).await;
        (page1, page2, r)
    }

    fn ptr_to_addr(p: *mut u8) -> HsmDmaAddr {
        let v = p as usize as u64;
        HsmDmaAddr {
            lo: v as u32,
            hi: (v >> 32) as u32,
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn response_within_one_page_leaves_the_second_untouched() {
        let (p1, p2, r) = split_write(1000).await;
        assert!(r.is_ok());
        assert_eq!(&p1[..1000], &pattern(1000)[..]);
        assert!(p2.iter().all(|&b| b == 0), "second page must not be used");
    }

    #[tokio::test]
    async fn ml_dsa_87_signature_spans_both_pages_in_order() {
        // 4,627 bytes: the response this whole mechanism exists to carry.
        const LEN: usize = 4627;
        let (p1, p2, r) = split_write(LEN).await;
        assert!(r.is_ok());

        let want = pattern(LEN);
        assert_eq!(&p1[..], &want[..HOST_RESP_PAGE_LEN], "first page");
        assert_eq!(
            &p2[..LEN - HOST_RESP_PAGE_LEN],
            &want[HOST_RESP_PAGE_LEN..],
            "second page continues where the first stopped"
        );
        // Nothing beyond the response may be written.
        assert!(p2[LEN - HOST_RESP_PAGE_LEN..].iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn exactly_two_full_pages_is_the_limit_and_is_delivered_whole() {
        const LEN: usize = 2 * HOST_RESP_PAGE_LEN;
        let (p1, p2, r) = split_write(LEN).await;
        assert!(r.is_ok());
        let want = pattern(LEN);
        assert_eq!(&p1[..], &want[..HOST_RESP_PAGE_LEN]);
        assert_eq!(&p2[..], &want[HOST_RESP_PAGE_LEN..]);
    }

    // A response larger than both pages cannot be built here: the std PAL's
    // DMA arena refuses an allocation over 8 KiB, so the case is unreachable
    // through this entry point. `host_resp_split` covers it directly.

    #[tokio::test]
    async fn a_split_response_with_no_second_page_is_refused() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        let src = pal.dma_alloc(&io, 4627).unwrap();
        let mut page1 = vec![0u8; HOST_RESP_PAGE_LEN];
        let a1 = ptr_to_addr(page1.as_mut_ptr());

        let r = pal
            .copy_mem_to_host(&io, src, a1, HsmDmaAddr { lo: 0, hi: 0 }, true)
            .await;
        assert!(
            matches!(r, Err(HsmError::InvalidArg)),
            "truncating would be worse than failing"
        );
    }
}

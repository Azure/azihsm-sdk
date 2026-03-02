// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency device — wraps any [`DdiDev`] implementation with fault injection.

use azihsm_ddi_interface::*;
use azihsm_ddi_types::DdiAesOp;
use azihsm_ddi_types::DdiOpReq;

use crate::fault;

/// A DDI device that delegates to an inner [`DdiDev`] but can inject
/// faults into `exec_op` calls based on globally configured rules.
///
/// See [`crate::inject_fault`] and [`crate::clear_faults`] for the
/// fault injection API.
#[derive(Debug, Clone)]
pub struct DdiResTestDev<D: DdiDev> {
    inner: D,
    device_kind: Option<azihsm_ddi_types::DdiDeviceKind>,
}

impl<D: DdiDev> DdiResTestDev<D> {
    /// Wraps an existing [`DdiDev`] implementation.
    pub(crate) fn new(inner: D) -> Self {
        Self {
            inner,
            device_kind: None,
        }
    }

    /// Returns the device kind, as set by [`DdiDev::set_device_kind`].
    pub fn device_kind(&self) -> Option<azihsm_ddi_types::DdiDeviceKind> {
        self.device_kind
    }
}

impl<D: DdiDev> DdiDev for DdiResTestDev<D> {
    fn set_device_kind(&mut self, kind: azihsm_ddi_types::DdiDeviceKind) {
        self.device_kind = Some(kind);
        self.inner.set_device_kind(kind);
    }

    fn exec_op<T: DdiOpReq>(
        &self,
        req: &T,
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        // Check fault rules before delegating.
        match fault::check_faults(req.get_opcode()) {
            Some(fault::FaultAction::ReturnError(err)) => return Err(err.into_ddi_error()),
            Some(fault::FaultAction::TriggerReset) => {
                // Trigger device reset — wipes credentials, then let the op proceed
                // so it fails naturally with CredentialsNotEstablished.
                self.inner.simulate_nssr_after_lm()?;
                // Allow time for the HSM to finish processing the
                // NSSR internally after the IOCTL returns.
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            None => {}
        }
        self.inner.exec_op(req, cookie)
    }

    fn exec_op_fp_gcm_slice(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        tag: &mut Option<[u8; 16]>,
        iv: &mut Option<[u8; 12]>,
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        self.inner
            .exec_op_fp_gcm_slice(mode, gcm_params, src_buf, dst_buf, tag, iv, fips_approved)
    }

    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        self.inner.exec_op_fp_gcm(mode, gcm_params, src_buf)
    }

    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        self.inner.exec_op_fp_xts(mode, xts_params, src_buf)
    }

    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        self.inner
            .exec_op_fp_xts_slice(mode, xts_params, src_buf, dst_buf, fips_approved)
    }

    fn simulate_nssr_after_lm(&self) -> Result<(), DdiError> {
        self.inner.simulate_nssr_after_lm()
    }
}

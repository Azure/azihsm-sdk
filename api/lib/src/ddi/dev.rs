// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device Discovery Interface (DDI) device management.
//!
//! This module provides functionality for discovering and opening HSM devices
//! through the DDI layer. It manages device enumeration, device handle wrapping,
//! and device access operations.

use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::LazyLock;

use super::*;
use crate::resiliency::HsmDdi;

/// Type alias for the Azihsm DDI device type.
pub(in crate::ddi) type AzishmDev = <HsmDdi as Ddi>::Dev;

/// Global DDI instance for device operations.
///
/// Lazily initialized singleton providing access to the DDI implementation.
static DDI: LazyLock<HsmDdi> = LazyLock::new(HsmDdi::default);

/// Retrieves the API revision range supported by the HSM device.
///
/// Queries the device for its supported API revision range, returning both
/// the minimum and maximum API revisions. This information can be used to
/// determine API compatibility and feature availability.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
///
/// # Returns
///
/// Returns a tuple containing (minimum API revision, maximum API revision).
///
/// # Errors
///
/// Returns an error if:
/// - The device communication fails
/// - The DDI operation returns an error
/// - The device is not responding
pub(crate) fn get_api_rev(dev: &HsmDev) -> HsmResult<(HsmApiRev, HsmApiRev)> {
    let req = DdiGetApiRevCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetApiRev, None, None),
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let resp: DdiGetApiRevCmdResp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

    Ok((resp.data.min.into(), resp.data.max.into()))
}

/// Converts a DDI API revision to an HSM API revision.
impl From<DdiApiRev> for HsmApiRev {
    fn from(ddi_rev: DdiApiRev) -> Self {
        HsmApiRev {
            major: ddi_rev.major,
            minor: ddi_rev.minor,
        }
    }
}

/// Converts an HSM API revision to a DDI API revision.
impl From<HsmApiRev> for DdiApiRev {
    fn from(hsm_rev: HsmApiRev) -> Self {
        DdiApiRev {
            major: hsm_rev.major,
            minor: hsm_rev.minor,
        }
    }
}

/// HSM device handle wrapper.
///
/// Wraps the underlying DDI device handle, providing a typed interface
/// for HSM device operations while maintaining deref access to the
/// underlying device.
#[derive(Debug)]
pub(crate) struct HsmDev(AzishmDev);

impl Deref for HsmDev {
    type Target = AzishmDev;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HsmDev {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Retrieves the paths of all available HSM devices.
///
/// Queries the DDI layer for a list of all discoverable HSM devices
/// and returns their device paths.
///
/// # Returns
///
/// A vector of device path strings.
#[tracing::instrument(skip_all)]
pub(crate) fn dev_paths() -> Vec<String> {
    DDI.dev_info_list()
        .iter()
        .map(|info| {
            tracing::debug!(path = ?info.path, "Found device");
            info.path.clone()
        })
        .collect()
}

impl HsmDev {
    /// Returns the device kind (Virtual or Physical).
    pub(crate) fn device_kind(&self) -> DdiDeviceKind {
        self.0.device_kind()
    }
}

/// Retrieves device information for a specific device path.
///
/// # Arguments
///
/// * `path` - The device path string
///
/// # Returns
///
/// Returns `DevInfo` for the specified path.
///
/// # Errors
///
/// Returns an error if the path is not found.
#[tracing::instrument(skip_all, fields(path = path))]
pub(crate) fn dev_info_by_path(path: &str) -> HsmResult<DevInfo> {
    DDI.dev_info_list()
        .into_iter()
        .find(|info| info.path == path)
        .ok_or(HsmError::InvalidArgument)
}

/// Opens an HSM device at the specified path.
///
/// Attempts to open an HSM device using the DDI layer and wraps
/// the resulting device handle in an `HsmDev` structure.
///
/// # Arguments
///
/// * `path` - The device path string identifying the HSM device to open
///
/// # Returns
///
/// Returns an `HsmDev` handle on success.
///
/// # Errors
///
/// Returns an error if:
/// - The device path is invalid or does not exist
/// - The device is already open or in use
/// - The device cannot be accessed due to permissions
/// - The underlying DDI operation fails
#[tracing::instrument(skip_all, fields(path = path))]
pub(crate) fn open_dev(path: &str) -> HsmResult<HsmDev> {
    let dev = DDI.open_dev(path).map(HsmDev).map_err(HsmError::from)?;

    // Probe the device with GetApiRev + GetDeviceInfo at open time so
    // that transient IO faults surface here (where the resiliency
    // retry machinery owns them) rather than at the first downstream
    // operation. The result is discarded — `device_kind()` is now a
    // hardcoded property of the backend, so we don't need the data;
    // the side-effect of the round-trip is what matters.
    probe_device(&dev)?;

    Ok(dev)
}

/// Round-trips two DDI ops (`GetApiRev` then `GetDeviceInfo`) against
/// the device to confirm it is reachable. Used by [`open_dev`] to
/// surface transient errors during retry-eligible operations.
fn probe_device(dev: &HsmDev) -> HsmResult<()> {
    let (_, max_rev) = get_api_rev(dev)?;

    let req = DdiGetDeviceInfoCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetDeviceInfo, Some(max_rev), None),
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };

    dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

    Ok(())
}

/// Converts a DDI device kind to an HSM partition type.
impl From<DdiDeviceKind> for HsmPartType {
    fn from(kind: DdiDeviceKind) -> Self {
        match kind {
            DdiDeviceKind::Virtual => HsmPartType::Virtual,
            DdiDeviceKind::Physical => HsmPartType::Physical,
            _ => unreachable!(),
        }
    }
}

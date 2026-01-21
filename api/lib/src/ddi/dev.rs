// Copyright (C) Microsoft Corporation. All rights reserved.

//! Device Discovery Interface (DDI) device management.
//!
//! This module provides functionality for discovering and opening HSM devices
//! through the DDI layer. It manages device enumeration, device handle wrapping,
//! and device access operations.

use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::LazyLock;

use super::*;

/// Type alias for the Azihsm DDI device type.
pub(in crate::ddi) type AzishmDev = <AzihsmDdi as Ddi>::Dev;

/// Global DDI instance for device operations.
///
/// Lazily initialized singleton providing access to the DDI implementation.
static DDI: LazyLock<AzihsmDdi> = LazyLock::new(AzihsmDdi::default);

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

    let resp: DdiGetApiRevCmdResp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;

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
    let mut dev = DDI
        .open_dev(path)
        .map(HsmDev)
        .map_hsm_err(HsmError::DdiCmdFailure)?;

    // Retrieve and set the device kind for the opened device.
    let dev_kind = get_device_kind(&dev)?;
    dev.set_device_kind(dev_kind);

    Ok(dev)
}

/// Retrieves the device kind/type from the HSM device.
///
/// Queries the device for its kind identifier, which indicates the specific
/// type or model of the HSM device.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
///
/// # Returns
///
/// Returns the device kind identifier.
///
/// # Errors
///
/// Returns an error if:
/// - API revision retrieval fails
/// - Device communication fails
/// - The DDI operation returns an error
/// - The device is not responding
fn get_device_kind(dev: &HsmDev) -> HsmResult<DdiDeviceKind> {
    let (_, max_rev) = get_api_rev(dev)?;

    let req = DdiGetDeviceInfoCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetDeviceInfo, Some(max_rev), None),
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };

    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;

    Ok(resp.data.kind)
}

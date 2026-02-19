// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency mock DDI — wraps [`DdiMock`] with fault injection.

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;
use azihsm_ddi_mock::DdiMock;

use crate::dev::DdiResiliencyMockDev;

/// DDI implementation that delegates to [`DdiMock`] but wraps
/// returned devices in [`DdiResiliencyMockDev`] for fault injection.
#[derive(Default, Debug)]
pub struct DdiResiliencyMock {
    inner: DdiMock,
}

impl Ddi for DdiResiliencyMock {
    type Dev = DdiResiliencyMockDev;

    fn dev_info_list(&self) -> Vec<DevInfo> {
        self.inner.dev_info_list()
    }

    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        let inner_dev = self.inner.open_dev(path)?;
        Ok(DdiResiliencyMockDev::new(inner_dev))
    }
}

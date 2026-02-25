// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency DDI — wraps any [`Ddi`] implementation with fault injection.

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;

use crate::dev::DdiResiliencyDev;

/// DDI implementation that delegates to an inner [`Ddi`] but wraps
/// returned devices in [`DdiResiliencyDev`] for fault injection.
#[derive(Default, Debug)]
pub struct DdiResiliency<I: Ddi + Default> {
    inner: I,
}

impl<I: Ddi + Default> Ddi for DdiResiliency<I> {
    type Dev = DdiResiliencyDev<I::Dev>;

    fn dev_info_list(&self) -> Vec<DevInfo> {
        self.inner.dev_info_list()
    }

    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        let inner_dev = self.inner.open_dev(path)?;
        Ok(DdiResiliencyDev::new(inner_dev))
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency DDI — wraps any [`Ddi`] implementation with fault injection.

use azihsm_ddi_interface::*;

use crate::dev::DdiResTestDev;

/// DDI implementation that delegates to an inner [`Ddi`] but wraps
/// returned devices in [`DdiResTestDev`] for fault injection.
#[derive(Default, Debug)]
pub struct DdiResTest<I: Ddi + Default> {
    inner: I,
}

impl<I: Ddi + Default> Ddi for DdiResTest<I> {
    type Dev = DdiResTestDev<I::Dev>;

    fn dev_info_list(&self) -> Vec<DevInfo> {
        self.inner.dev_info_list()
    }

    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        let inner_dev = self.inner.open_dev(path)?;
        Ok(DdiResTestDev::new(inner_dev))
    }
}

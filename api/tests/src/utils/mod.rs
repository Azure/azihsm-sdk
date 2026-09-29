// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(not(feature = "session-ex-tests"))]
pub(crate) mod aes_xts;
pub(crate) mod api;
pub(crate) mod partition;
#[cfg(all(feature = "session-ex-tests", not(feature = "mock")))]
pub(crate) mod partition_ex_helpers;
#[cfg(not(feature = "session-ex-tests"))]
pub(crate) mod resiliency;
#[cfg(all(feature = "session-ex-tests", not(feature = "mock")))]
pub(crate) mod sd_provision;
pub(crate) mod session;

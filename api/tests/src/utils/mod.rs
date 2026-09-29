// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(not(feature = "session-ex-tests"))]
pub(crate) mod aes_xts;
pub(crate) mod api;
pub(crate) mod partition;
#[cfg(not(feature = "mock"))]
pub(crate) mod partition_ex_helpers;
#[cfg(not(feature = "session-ex-tests"))]
pub(crate) mod resiliency;
#[cfg(not(feature = "mock"))]
// The default suite retains this module for pre-existing direct TBOR tests,
// while the full helper surface is exercised only by the session-ex suite.
#[cfg_attr(not(feature = "session-ex-tests"), allow(dead_code))]
pub(crate) mod sd_provision;
pub(crate) mod session;

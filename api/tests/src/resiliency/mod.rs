// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests.
//!
//! Each sub-module targets a specific API surface and uses the
//! resiliency DDI device to inject transient faults, verifying
//! that the retry-with-backoff machinery recovers correctly.

mod open_part;

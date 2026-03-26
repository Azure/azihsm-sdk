// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Multi-threaded stress tests for key-operation resiliency.
//!
//! These tests use `partition.reset()` to trigger real simulated
//! resets while worker threads perform key operations concurrently.
//! They do NOT depend on the fault-injection device (`azihsm_res_test_dev`).

mod tests;

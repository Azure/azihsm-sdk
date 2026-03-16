// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! AZIHSM Simulator Service
//!
//! This crate provides both the sim-service binary and the shared wire protocol
//! used by clients to communicate with the service over a Unix Domain Socket.

pub mod protocol;

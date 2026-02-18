// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tracing and logging initialization utilities for API tests.
//!
//! This module provides functionality to initialize the tracing subscriber
//! with a hierarchical output format for test execution. It ensures that
//! tracing is initialized only once across all tests and configures
//! appropriate log levels for different components.

use azihsm_api_tests_macro::*;
use tracing::*;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;
use tracing_subscriber::*;
use tracing_tree::*;

/// Initializes the tracing subscriber for test execution.
///
/// This function sets up a global tracing subscriber with a hierarchical
/// layer for formatted output. It is designed to be called multiple times
/// safely, as the actual initialization occurs only once using a static
/// `Once` guard.
///
/// The subscriber is configured with:
/// - Debug level logging by default
/// - Info level for `azihsm_ddi_mock`
/// - Disabled logging for `azihsm_ddi_sim` and `azihsm_ddi_mock`
/// - Thread names and IDs in output
/// - Indented hierarchical output format
/// - Target information in log messages
///
/// # Panics
///
/// Panics if:
/// - The log filter string cannot be parsed
/// - The global subscriber cannot be set (should never happen due to `Once` guard)
#[allow(unused)]
#[allow(clippy::expect_used)]
pub fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let rust_log = "debug";
    let filter: Targets = rust_log.parse().expect("failed to parse the log");
    ONCE.call_once(|| {
        let layer = HierarchicalLayer::default()
            .with_writer(std::io::stdout)
            .with_indent_lines(true)
            .with_indent_amount(2)
            .with_thread_names(true)
            .with_thread_ids(true)
            .with_verbose_exit(false)
            .with_verbose_entry(false)
            .with_targets(true);
        let subscriber = Registry::default().with(filter).with(layer);
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

#[api_test]
fn test_trace_info() {
    info!("This is a info message.");
}

#[api_test]
fn test_trace_error() {
    error!("This is an error message.");
}

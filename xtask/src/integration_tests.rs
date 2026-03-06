// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;

use crate::nextest;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run integration tests
#[derive(Parser)]
#[clap(about = "Run Integration Tests")]
pub struct IntegrationTest {}

impl Xtask for IntegrationTest {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("start testing");

        let nextest = nextest::Nextest {
            features: Some("integration".to_string()),
            package: Some("integration-tests".to_string()),
            no_default_features: false,
            filterset: None,
            profile: Some("ci-provider-integration".to_string()),
            exclude: vec![],
        };
        nextest.run(ctx)
    }
}

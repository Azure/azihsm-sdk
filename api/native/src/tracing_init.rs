// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::Once;

use tracing_subscriber::prelude::*;

const DEFAULT_KEYWORD: u64 = 1;
const PROVIDER_NAME: &str = "Microsoft.Azure.IHSM";

static INIT: Once = Once::new();

/// Registers the ETW (Windows) / user_events (Linux) tracing subscriber.
///
/// Safe to call multiple times — only the first call has effect.
/// Subsequent calls are a no-op with negligible overhead.
pub(crate) fn ensure_init() {
    INIT.call_once(|| {
        if let Ok(layer) = tracing_etw::LayerBuilder::new(PROVIDER_NAME)
            .with_default_keyword(DEFAULT_KEYWORD)
            .build()
        {
            if tracing_subscriber::registry()
                .with(layer)
                .try_init()
                .is_ok()
            {
                tracing::info!(
                    provider_name = PROVIDER_NAME,
                    keyword = DEFAULT_KEYWORD,
                    "AZIHSM native tracing initialized"
                );

                emit_sample_traces();
            }
        }
    });
}

fn emit_sample_traces() {
    tracing::error!(
        sample = true,
        provider_name = PROVIDER_NAME,
        keyword = DEFAULT_KEYWORD,
        "AZIHSM sample error event"
    );
    tracing::warn!(
        sample = true,
        provider_name = PROVIDER_NAME,
        keyword = DEFAULT_KEYWORD,
        "AZIHSM sample warning event"
    );
    tracing::info!(
        sample = true,
        provider_name = PROVIDER_NAME,
        keyword = DEFAULT_KEYWORD,
        "AZIHSM sample info event"
    );
    tracing::info!(
        sample = true,
        provider_name = PROVIDER_NAME,
        keyword = DEFAULT_KEYWORD,
        operation = "azihsm_part_get_list",
        request_id = 42_u64,
        partition_count = 2_u32,
        duration_ms = 7_u64,
        success = true,
        "AZIHSM sample parameterized event"
    );
    tracing::debug!(
        sample = true,
        provider_name = PROVIDER_NAME,
        keyword = DEFAULT_KEYWORD,
        "AZIHSM sample debug event"
    );
    tracing::trace!(
        sample = true,
        provider_name = PROVIDER_NAME,
        keyword = DEFAULT_KEYWORD,
        "AZIHSM sample trace event"
    );
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::retry_with_backoff;

pub struct HsmError;
pub type HsmResult<T> = Result<T, HsmError>;

pub mod resiliency {
    pub const MAX_RETRIES: u32 = 3;
    pub const BACKOFF_BASE_MS: u64 = 10;
    pub const BACKOFF_JITTER_MS: u64 = 1;

    pub fn is_io_abort_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }
}

struct RetryTarget;

impl RetryTarget {
    #[retry_with_backoff(predicate = crate::resiliency::is_io_abort_error)]
    fn by_value_self(self) -> HsmResult<()> {
        Ok(())
    }
}

fn main() {}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::resiliency_key_gen;

pub struct HsmError;
pub type HsmResult<T> = Result<T, HsmError>;

pub mod resiliency {
    pub const MAX_RETRIES: u32 = 3;
    pub const BACKOFF_BASE_MS: u64 = 10;

    pub fn execute_key_gen_with_retry<T, F>(
        mut operation: F,
        _session: &crate::HsmSession,
        _partition: &crate::HsmPartition,
        _max_retries: u32,
        _backoff_base_ms: u64,
    ) -> crate::HsmResult<T>
    where
        F: FnMut() -> crate::HsmResult<T>,
    {
        operation()
    }
}

pub struct HsmPartition;

impl HsmPartition {
    fn resiliency_enabled(&self) -> bool {
        true
    }
}

pub struct HsmSession;

impl HsmSession {
    fn partition(&self) -> HsmPartition {
        HsmPartition
    }
}

#[resiliency_key_gen(session = "session")]
fn non_ident_pattern(session: &HsmSession, _: u8, (left, right): (u8, u8)) -> HsmResult<u8> {
    let _ = session;
    Ok(left + right)
}

fn main() {}
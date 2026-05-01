// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::resiliency_key_op;

pub struct HsmError;
pub type HsmResult<T> = Result<T, HsmError>;

#[resiliency_key_op(max_retries = 2)]
fn missing_required_arg() -> HsmResult<()> {
    Ok(())
}

fn main() {}

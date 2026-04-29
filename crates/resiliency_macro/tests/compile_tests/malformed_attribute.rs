// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::resiliency_key_gen;

pub struct HsmError;
pub type HsmResult<T> = Result<T, HsmError>;

#[resiliency_key_gen(session =)]
fn malformed_attribute() -> HsmResult<()> {
    Ok(())
}

fn main() {}
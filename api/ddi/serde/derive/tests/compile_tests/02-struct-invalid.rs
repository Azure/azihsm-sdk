// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;
use mcr_ddi_mbor::*;

#[derive(Ddi)]
#[ddi(map)]
struct Version {
    major: u32,
}

#[derive(Ddi)]
#[ddi(map)]
struct Empty;

#[derive(Ddi)]
#[ddi(map)]
struct StructWithInvalidType1 {
    #[ddi(id = 0)]
    field: [u8],
}

#[derive(Ddi)]
#[ddi(map)]
struct StructWithInvalidType2 {
    #[ddi(id = 0)]
    field: [u32; 10],
}

#[derive(Ddi)]
#[ddi(map)]
struct StructWithInvalidType12 {
    #[ddi(id = 0)]
    field0: u32,

    #[ddi(id = 2)]
    field1: u32,
}

#[derive(Ddi)]
#[ddi(map)]
struct New {
    #[ddi(id = 0)]
    opt: Option<u32>,
}

#[derive(Ddi)]
#[ddi(map)]
struct TupleStruct(u32);

#[derive(Ddi)]
#[ddi(map)]
struct StructWithInvalidOptType {
    #[ddi(id = 0)]
    field: Option<[u32; 10]>,
}

#[derive(Ddi)]
#[ddi(map)]
struct StructWithSlice<'a> {
    #[ddi(id = 0)]
    field: &'a [u8],
}

#[derive(Ddi)]
#[ddi(map)]
pub struct ValidStruct {
    #[ddi(id = 1)]
    pub field1: u32,
}

fn main() {}

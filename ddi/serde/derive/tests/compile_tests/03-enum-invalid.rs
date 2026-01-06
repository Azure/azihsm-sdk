// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;
use open_enum::open_enum;

#[derive(Ddi)]
enum InvalidEnum2 {
    True = 0,
}

#[derive(Ddi)]
#[ddi(enumeration)]
struct DoubleTupleStruct(u32, u32);

#[derive(Ddi)]
#[ddi(enumeration)]
struct IncorrectEnumDataType(u16);

#[open_enum]
#[derive(Ddi)]
#[repr(u64)]
#[ddi(enumeration)]
pub enum InvalidOpenEnumDataType {
    EnumVal1 = 1001,
}

#[open_enum]
#[derive(Ddi)]
#[repr(u32)]
pub enum InvalidEnumMissingEnumerationTag {
    EnumVal1 = 1001,
}

#[open_enum]
#[derive(Ddi)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum ValidOpenEnum {
    EnumVal1 = 1001,
}

fn main() {}

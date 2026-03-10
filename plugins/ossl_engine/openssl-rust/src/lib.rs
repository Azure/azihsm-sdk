// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

pub mod safeapi;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

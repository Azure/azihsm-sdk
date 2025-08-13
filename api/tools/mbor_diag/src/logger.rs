// Copyright (C) Microsoft Corporation. All rights reserved.

use std::fmt::Arguments;

pub trait Logger {
    fn println(&mut self, value: Arguments<'_>);
}

pub struct StdoutLogger;

impl Logger for StdoutLogger {
    fn println(&mut self, value: Arguments<'_>) {
        println!("{}", value);
    }
}

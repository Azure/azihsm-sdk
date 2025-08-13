// Copyright (C) Microsoft Corporation. All rights reserved.

mod cli;
mod logger;
mod print;
mod sanitize;

use core::panic;
use std::io::*;

use crate::cli::*;
use crate::logger::*;
use crate::print::*;
use crate::sanitize::*;

use clap::*;

fn main() {
    let cli_args = CliArgs::parse();

    let mut input = stdin();
    let mut input_data = vec![];

    println!("Convert from: {:?} to {:?}", cli_args.from, cli_args.to);

    println!("Provide input data and press CTRL+D when done with data...");
    let result = input.read_to_end(&mut input_data);

    if result.is_err() {
        panic!("Error reading input: {}", result.unwrap_err());
    }
    if input_data.is_empty() {
        panic!("No input data provided.");
    }
    let input_data = String::from_utf8(input_data).unwrap();

    // Sanitize the input data
    let sanitized_input = sanitize_input(cli_args.from, &input_data);

    print_converted_data(&mut StdoutLogger, cli_args.to, &sanitized_input);
}

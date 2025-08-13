// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::cli::*;

pub fn sanitize_input(from: From, input: &str) -> Vec<u8> {
    // Replace all newline characters with spaces
    let mut sanitized = input.replace('\n', " ");
    sanitized = sanitized.replace('\r', " ");

    // Replace any big brackets with spaces
    sanitized = sanitized.replace('[', " ");
    sanitized = sanitized.replace(']', " ");

    // Replace all 0x with spaces
    if from == From::Hex {
        sanitized = sanitized.replace("0x", " ");
    }

    // Replace all commas with spaces
    sanitized = sanitized.replace(',', " ");

    // Replace all semicolons with spaces
    sanitized = sanitized.replace(';', " ");

    // Replace all colons with spaces
    sanitized = sanitized.replace(':', " ");

    sanitized
        .split_whitespace()
        .map(|s| {
            // If hex then convert to u8
            if from == From::Hex {
                let hex = s.trim_start_matches("0x");
                if let Ok(num) = u8::from_str_radix(hex, 16) {
                    num
                } else {
                    panic!("Invalid hex value: {}", s);
                }
            } else {
                // If bytes then convert to u8
                if let Ok(num) = s.parse::<u8>() {
                    num
                } else {
                    panic!("Invalid byte value: {}", s);
                }
            }
        })
        .collect::<Vec<u8>>()
}

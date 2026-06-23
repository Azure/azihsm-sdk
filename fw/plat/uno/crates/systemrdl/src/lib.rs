// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! General-purpose parser for systemrdl files.

pub mod ast;
mod bits;
mod file_source;
mod lexer;
mod parser;
mod string_arena;
mod token;
mod token_iter;

pub use bits::Bits;
pub use file_source::FileSource;
pub use file_source::FsFileSource;
pub use parser::parse;
pub use token::*;

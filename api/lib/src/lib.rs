// Copyright (C) Microsoft Corporation. All rights reserved.

mod algo;
mod ddi;
mod error;
mod op;
mod partition;
mod session;
mod shared_types;
pub mod traits;

pub use algo::*;
pub use error::*;
pub use op::*;
pub use partition::*;
pub use session::*;
pub use shared_types::*;
pub use traits::*;

pub type HsmResult<T> = Result<T, HsmError>;

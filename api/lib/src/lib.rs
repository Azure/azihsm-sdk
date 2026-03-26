// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Debug print macro for resiliency instrumentation.
/// Enabled by the `res-debug` feature; compiles to nothing otherwise.
/// Output goes through `tracing::warn!` so it lands in log files.
macro_rules! res_dbg {
    ($($arg:tt)*) => {
        {
            #[cfg(feature = "res-debug")]
            tracing::warn!("{}", format_args!($($arg)*));
        }
    };
}

mod algo;
mod ddi;
mod error;
mod op;
mod partition;
mod resiliency;
mod session;
mod shared_types;
pub mod traits;

pub use algo::*;
pub use error::*;
pub use op::*;
pub use partition::*;
pub use resiliency::*;
pub use session::*;
pub use shared_types::*;
pub use traits::*;

pub type HsmResult<T> = Result<T, HsmError>;

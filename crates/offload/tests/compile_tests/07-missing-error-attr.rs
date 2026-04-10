// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use offload::offload;

#[derive(Debug)]
enum MyError {
    WorkerShutdown,
}

#[offload(shutdown_error = MyError::WorkerShutdown)]
impl MyWorker {
    pub fn good() -> Result<u32, MyError> {
        Ok(42)
    }
}

fn main() {}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use offload::offload;

#[derive(Debug)]
enum MyError {
    WorkerShutdown,
}

#[offload(error = MyError, shutdown_error = MyError::WorkerShutdown)]
impl MyWorker {
    pub async fn bad() -> Result<u32, MyError> {
        Ok(42)
    }
}

fn main() {}

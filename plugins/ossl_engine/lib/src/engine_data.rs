// Copyright (C) Microsoft Corporation. All rights reserved.

use tracing::dispatcher::DefaultGuard;

pub struct EngineData {
    // Stored but not read, when the engine data is dropped this will be dropped also
    _guard: DefaultGuard,
}

impl EngineData {
    pub fn new(guard: DefaultGuard) -> Self {
        Self { _guard: guard }
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared test fixtures.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Per-test scratch directory under the system temp dir. Removed on drop.
pub(crate) struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir =
            std::env::temp_dir().join(format!("azihsm_ossl_engine_resiliency-{tag}-{pid}-{n}"));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

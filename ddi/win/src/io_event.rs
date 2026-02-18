// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - MCR Windows Device - I/O Event Module

#![allow(unsafe_code)]

use std::ptr;

use azihsm_ddi_interface::*;
use winapi::shared::ntdef::HANDLE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::CreateEventW;

pub(crate) struct IoEvent(HANDLE);

impl IoEvent {
    pub(crate) fn new() -> DdiResult<Self> {
        let manual_reset = 1;
        let initial_state = 0;

        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let event =
            unsafe { CreateEventW(ptr::null_mut(), manual_reset, initial_state, ptr::null()) };

        if event.is_null() {
            let last_error = std::io::Error::last_os_error();
            Err(DdiError::IoError(last_error))?;
        }

        Ok(Self(event))
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for IoEvent {
    fn drop(&mut self) {
        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        unsafe { CloseHandle(self.0) };
    }
}

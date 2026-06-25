// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Embassy trace hook symbols — delegates to [`crate::profile`] helpers.

use crate::profile;

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_task_exec_begin(_executor_id: u32, task_id: u32) {
    profile::set_current_task_id(task_id);
    profile::task_begin(task_id);
}

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_task_exec_end(_executor_id: u32, _task_id: u32) {
    profile::set_current_task_id(0);
    profile::task_end();
}

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_task_new(_executor_id: u32, _task_id: u32) {
    profile::task_new();
}

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_task_end(_executor_id: u32, _task_id: u32) {
    profile::task_complete();
}

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_task_ready_begin(_executor_id: u32, _task_id: u32) {}

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_poll_start(_executor_id: u32) {}

#[unsafe(no_mangle)]
#[link_section = ".text.embassy_hooks"]
fn _embassy_trace_executor_idle(_executor_id: u32) {
    profile::set_current_task_id(0);
    profile::idle();
}

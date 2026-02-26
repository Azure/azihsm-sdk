// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fault injection types and global state for resiliency testing.
//!
//! Tests configure faults before calling the API under test.
//! Every `exec_op` call on [`super::DdiResTestDev`] checks
//! the global fault list. If a rule matches the current opcode, the
//! configured error is returned instead of delegating to the inner mock.
//!
//! # Per-op call tracking
//!
//! Each [`DdiOp`] has its own call counter (1-based). This lets tests
//! target a specific occurrence of an op — e.g., "fail the 2nd
//! `GetApiRev` call with `IoAborted`".
//!

use std::collections::HashMap;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DriverError;
use azihsm_ddi_types::DdiOp;
use parking_lot::Mutex;

/// Per-op call counters — keyed by the `DdiOp` inner `u32` value.
static OP_COUNTERS: Mutex<Option<HashMap<u32, u32>>> = Mutex::new(None);

/// Global fault rules.
static FAULTS: Mutex<Vec<FaultRule>> = Mutex::new(Vec::new());

/// Describes *when* a fault should fire for its target op.
#[derive(Debug, Clone)]
pub enum FaultTrigger {
    /// Fail the next `n` calls to the target op.
    /// Decremented on each match; removed when exhausted.
    NextNCalls(u32),

    /// Fail exactly on the *n*-th call (1-based) to the target op.
    /// One-shot — removed after it fires.
    OnNthCall(u32),
}

/// A single fault injection rule.
///
/// Each rule targets a specific [`DdiOp`], specifies *when* to fire
/// via [`FaultTrigger`], and which [`DriverError`] to return.
#[derive(Debug, Clone)]
pub struct FaultRule {
    /// The DDI opcode this rule applies to.
    pub op: DdiOp,
    /// When the fault fires.
    pub trigger: FaultTrigger,
    /// Which driver error to return.
    pub error: DriverError,
}

impl FaultRule {
    /// Fail the next `n` calls to `op` with the given error.
    pub fn fail_next(op: DdiOp, n: u32, error: DriverError) -> Self {
        assert!(n > 0, "fail_next: n must be > 0");
        Self {
            op,
            trigger: FaultTrigger::NextNCalls(n),
            error,
        }
    }

    /// Fail exactly the *n*-th call (1-based) to `op` with the given error.
    pub fn fail_nth(op: DdiOp, n: u32, error: DriverError) -> Self {
        assert!(n > 0, "fail_nth: n must be > 0 (counters are 1-based)");
        Self {
            op,
            trigger: FaultTrigger::OnNthCall(n),
            error,
        }
    }
}

/// Adds a fault rule to the global list.
pub fn inject_fault(rule: FaultRule) {
    FAULTS.lock().push(rule);
}

/// Removes all fault rules and resets per-op call counters.
///
/// Locks are acquired and released independently to maintain a
/// consistent lock order with [`check_faults`] (which locks
/// `OP_COUNTERS` then `FAULTS`).
pub fn clear_faults() {
    {
        let mut counters = OP_COUNTERS.lock();
        if let Some(map) = counters.as_mut() {
            map.clear();
        }
    }
    FAULTS.lock().clear();
}

/// Returns the call count for a specific [`DdiOp`].
pub fn op_call_count(op: DdiOp) -> u32 {
    OP_COUNTERS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&op.0).copied())
        .unwrap_or(0)
}

/// Increments the per-op counter and checks fault rules.
///
/// Returns `Some(DdiError)` if a rule matched, `None` otherwise.
/// Matched rules with counters are decremented; exhausted rules are
/// removed.
pub(crate) fn check_faults(opcode: DdiOp) -> Option<DdiError> {
    // Increment per-op counter (1-based).
    let op_count = {
        let mut counters = OP_COUNTERS.lock();
        let map = counters.get_or_insert_with(HashMap::new);
        let count = map.entry(opcode.0).or_insert(0);
        *count += 1;
        *count
    };

    let mut faults = FAULTS.lock();
    let mut matched_error = None;

    faults.retain_mut(|rule| {
        // Only match the first applicable rule.
        if matched_error.is_some() {
            return true;
        }

        // Skip rules not targeting this op.
        if rule.op != opcode {
            return true;
        }

        match &mut rule.trigger {
            FaultTrigger::NextNCalls(ref mut remaining) => {
                if *remaining > 0 {
                    *remaining -= 1;
                    matched_error = Some(DdiError::DriverError(rule.error));
                    // Keep the rule if it still has remaining count.
                    *remaining > 0
                } else {
                    // Exhausted — remove.
                    false
                }
            }
            FaultTrigger::OnNthCall(target) => {
                if op_count == *target {
                    matched_error = Some(DdiError::DriverError(rule.error));
                    // One-shot — remove after match.
                    false
                } else {
                    true
                }
            }
        }
    });

    if let Some(ref err) = matched_error {
        tracing::warn!(op_count, ?opcode, ?err, "Fault injected by resiliency mock");
    }

    matched_error
}

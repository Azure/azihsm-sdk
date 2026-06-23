// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::task::Context;

use embassy_sync::waitqueue::WakerRegistration;

use crate::EngineId;
use crate::EngineState;
use crate::QueueSlotState;
use crate::RequestId;

const LEGACY_REQUEST_ID: RequestId = RequestId::new(0);

/// Tracks waiter state for one hardware PKA engine.
pub(crate) struct EngineSlot {
    /// Waker for the task waiting on this engine's completion.
    pub(crate) waker: WakerRegistration,

    /// Raw status bits captured when the engine completes a command.
    pub(crate) status: u8,

    /// Explicit lifecycle state of this engine.
    pub(crate) state: EngineState,

    /// Indicates whether the engine should produce a completion wake-up.
    pub(crate) completion_armed: bool,
}

impl EngineSlot {
    pub(crate) fn clear(&mut self) {
        self.status = 0;
        self.state = EngineState::Idle;
        self.completion_armed = false;
    }

    pub(crate) fn mark_in_use(&mut self, awaiting_completion: bool) {
        self.state = EngineState::Running {
            req: LEGACY_REQUEST_ID,
        };
        self.completion_armed = awaiting_completion;
        self.status = 0;
    }

    pub(crate) fn take_completion_status(&mut self) -> Option<u8> {
        if self.status == 0 {
            return None;
        }

        let status = self.status;
        self.status = 0;
        self.completion_armed = false;
        Some(status)
    }

    pub(crate) fn register_waiter(&mut self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }

    pub(crate) fn arm_completion_wait(&mut self) {
        self.status = 0;
        self.completion_armed = true;
        if self.state == EngineState::Idle {
            self.state = EngineState::Running {
                req: LEGACY_REQUEST_ID,
            };
        }
    }

    pub(crate) fn is_in_use(&self) -> bool {
        self.state != EngineState::Idle
    }

    pub(crate) fn is_completion_armed(&self) -> bool {
        self.completion_armed
    }

    pub(crate) fn has_completion_status(&self) -> bool {
        self.status != 0
    }

    pub(crate) fn capture_completion_status(&mut self, status: u8) {
        self.status = status;
    }

    pub(crate) fn wake_waiter(&mut self) {
        self.waker.wake();
    }
}

/// Tracks a waiter that requested a specific engine.
pub(crate) struct SpecificWaiter {
    /// Waker for the task waiting on a specific engine ID.
    pub(crate) waker: WakerRegistration,

    /// Indicates whether a task is currently waiting on this engine ID.
    pub(crate) waiting: bool,

    /// Indicates whether the engine has been assigned to the waiter.
    pub(crate) assigned: bool,
}

impl SpecificWaiter {
    pub(crate) fn register_waiter(&mut self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

/// Tracks one entry in the shared engine-acquisition queue.
pub(crate) struct QueueSlot {
    /// Waker for the task associated with this queue entry.
    pub(crate) waker: WakerRegistration,

    /// Explicit lifecycle state for this queue slot.
    pub(crate) state: QueueSlotState,
}

impl QueueSlot {
    pub(crate) fn occupy(&mut self, pre_staged: bool) {
        self.state = QueueSlotState::Pending {
            req: LEGACY_REQUEST_ID,
            pre_staged,
        };
    }

    pub(crate) fn clear(&mut self) {
        self.state = QueueSlotState::Free;
    }

    pub(crate) fn assign_engine(&mut self, id: u8) {
        self.state = match self.state {
            QueueSlotState::Pending { req, pre_staged } => QueueSlotState::Assigned {
                req,
                engine: EngineId::new(id),
                pre_staged,
            },
            QueueSlotState::Assigned {
                req,
                engine: _,
                pre_staged,
            } => QueueSlotState::Assigned {
                req,
                engine: EngineId::new(id),
                pre_staged,
            },
            QueueSlotState::Completing { req, .. } => QueueSlotState::Completing {
                req,
                engine: EngineId::new(id),
            },
            QueueSlotState::Free => QueueSlotState::Assigned {
                req: LEGACY_REQUEST_ID,
                engine: EngineId::new(id),
                pre_staged: false,
            },
        };
    }

    pub(crate) fn assigned_engine(&self) -> Option<u8> {
        match self.state {
            QueueSlotState::Assigned { engine, .. } => Some(engine.raw()),
            QueueSlotState::Completing { engine, .. } => Some(engine.raw()),
            QueueSlotState::Free | QueueSlotState::Pending { .. } => None,
        }
    }

    pub(crate) fn is_unassigned_waiter(&self) -> bool {
        matches!(self.state, QueueSlotState::Pending { .. })
    }

    pub(crate) fn is_occupied(&self) -> bool {
        !matches!(self.state, QueueSlotState::Free)
    }

    pub(crate) fn pre_staged(&self) -> bool {
        match self.state {
            QueueSlotState::Pending { pre_staged, .. }
            | QueueSlotState::Assigned { pre_staged, .. } => pre_staged,
            QueueSlotState::Completing { .. } | QueueSlotState::Free => false,
        }
    }

    pub(crate) fn register_waiter(&mut self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

/// Shared mutable state for the async PKA engine pool.
pub(crate) struct UpkaState<const DEPTH: usize, const ENGINES: usize> {
    /// Bitmask of currently free engines.
    pub(crate) free_mask: u16,

    /// Per-engine completion state and wakers.
    pub(crate) engine_slots: [EngineSlot; ENGINES],

    /// Waiters blocked on a specific engine ID.
    pub(crate) specific_waiters: [SpecificWaiter; ENGINES],

    /// FIFO queue of tasks waiting for any engine.
    pub(crate) queue_slots: [QueueSlot; DEPTH],

    /// Monotonic head index of the waiter queue.
    pub(crate) queue_head: u8,

    /// Monotonic tail index of the waiter queue.
    pub(crate) queue_tail: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueDispatchAction {
    pub(crate) queue_slot: u8,
    pub(crate) pre_staged: bool,
}

impl<const DEPTH: usize, const ENGINES: usize> UpkaState<DEPTH, ENGINES> {
    /// Return the ring-buffer index for a monotonic queue cursor.
    pub(crate) fn queue_index(cursor: u8) -> usize {
        (cursor & ((DEPTH - 1) as u8)) as usize
    }

    /// Return whether the waiter queue has reached capacity.
    pub(crate) fn queue_is_full(&self) -> bool {
        self.queue_tail.wrapping_sub(self.queue_head) as usize >= DEPTH
    }

    /// Return whether the queue contains any waiter still awaiting engine assignment.
    pub(crate) fn has_any_waiters(&self) -> bool {
        let mut cursor = self.queue_head;
        while cursor != self.queue_tail {
            let idx = Self::queue_index(cursor);
            let slot = &self.queue_slots[idx];
            if slot.is_unassigned_waiter() {
                return true;
            }
            cursor = cursor.wrapping_add(1);
        }
        false
    }

    pub(crate) fn try_claim_free_engine(&mut self, awaiting_completion: bool) -> Option<u8> {
        if self.free_mask == 0 {
            return None;
        }

        let id = self.free_mask.trailing_zeros() as u8;
        self.free_mask &= !(1u16 << id);
        self.engine_slots[id as usize].mark_in_use(awaiting_completion);
        Some(id)
    }

    pub(crate) fn reserve_queue_slot(&mut self, pre_staged: bool) -> Option<u8> {
        if self.queue_is_full() {
            return None;
        }

        let q = Self::queue_index(self.queue_tail) as u8;
        self.queue_slots[q as usize].occupy(pre_staged);
        self.queue_tail = self.queue_tail.wrapping_add(1);
        Some(q)
    }

    pub(crate) fn wait_for_assigned_engine(&mut self, q: u8, cx: &Context<'_>) -> Option<u8> {
        let slot = &mut self.queue_slots[q as usize];
        if let Some(id) = slot.assigned_engine() {
            Some(id)
        } else {
            slot.register_waiter(cx);
            None
        }
    }

    pub(crate) fn clear_queue_entry(&mut self, q: u8) {
        self.queue_slots[q as usize].clear();
        while self.queue_head != self.queue_tail {
            let idx = Self::queue_index(self.queue_head);
            if self.queue_slots[idx].is_occupied() {
                break;
            }
            self.queue_head = self.queue_head.wrapping_add(1);
        }
    }

    pub(crate) fn release_engine_and_dispatch(&mut self, id: u8) -> Option<QueueDispatchAction> {
        self.engine_slots[id as usize].clear();

        if self.specific_waiters[id as usize].waiting {
            self.specific_waiters[id as usize].waiting = false;
            self.specific_waiters[id as usize].assigned = true;
            self.engine_slots[id as usize].mark_in_use(false);
            self.specific_waiters[id as usize].waker.wake();
            return None;
        }

        self.free_mask |= 1u16 << id;

        let mut cursor = self.queue_head;
        while cursor != self.queue_tail {
            let idx = Self::queue_index(cursor);
            if self.queue_slots[idx].is_unassigned_waiter() {
                let pre_staged = self.queue_slots[idx].pre_staged();
                self.free_mask &= !(1u16 << id);
                self.engine_slots[id as usize].mark_in_use(pre_staged);
                self.queue_slots[idx].assign_engine(id);
                self.queue_slots[idx].waker.wake();
                return Some(QueueDispatchAction {
                    queue_slot: idx as u8,
                    pre_staged,
                });
            }
            cursor = cursor.wrapping_add(1);
        }

        None
    }
}

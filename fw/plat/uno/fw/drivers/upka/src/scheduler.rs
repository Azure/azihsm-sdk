// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_uno_drivers_nvic::Nvic;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_pac::Interrupt;

use crate::api::UpkaDriver;
use crate::engine::UpkaEngine;
use crate::executor::EngineExecutor;
use crate::pool::UpkaState;
use crate::UpkaError;

/// Schedules queue/engine assignment and completion handling for UPKA commands.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scheduler<'a, const DEPTH: usize, const ENGINES: usize> {
    driver: &'a UpkaDriver<DEPTH, ENGINES>,
}

impl<'a, const DEPTH: usize, const ENGINES: usize> Scheduler<'a, DEPTH, ENGINES> {
    /// Create a scheduler view over a driver instance.
    pub(crate) const fn new(driver: &'a UpkaDriver<DEPTH, ENGINES>) -> Self {
        Self { driver }
    }

    fn make_engine(&self, id: u8) -> UpkaEngine<'a, DEPTH, ENGINES> {
        UpkaEngine {
            driver: self.driver,
            id,
            released: false,
        }
    }

    fn assign_engine(state: &mut UpkaState<DEPTH, ENGINES>, id: u8, awaiting_completion: bool) {
        state.free_mask &= !(1u16 << id);
        state.engine_slots[id as usize].mark_in_use(awaiting_completion);
    }

    fn claim_free_engine(state: &mut UpkaState<DEPTH, ENGINES>) -> Option<u8> {
        state.try_claim_free_engine(false)
    }

    /// Acquire any free engine.
    pub(crate) async fn acquire_any(&self) -> HsmResult<UpkaEngine<'a, DEPTH, ENGINES>> {
        let mut queue_idx: Option<u8> = None;

        poll_fn(move |cx| {
            self.driver.state.with(|s| {
                if let Some(idx) = queue_idx {
                    let assigned = {
                        if let Some(id) = s.wait_for_assigned_engine(idx, cx) {
                            s.clear_queue_entry(idx);
                            Some(id)
                        } else {
                            None
                        }
                    };

                    if let Some(id) = assigned {
                        return Poll::Ready(Ok(self.make_engine(id)));
                    }

                    return Poll::Pending;
                }

                if !s.has_any_waiters() {
                    if let Some(id) = Self::claim_free_engine(s) {
                        return Poll::Ready(Ok(self.make_engine(id)));
                    }
                }

                if s.queue_is_full() {
                    return Poll::Ready(Err(UpkaError::QUEUE_FULL));
                }

                let Some(idx) = s.reserve_queue_slot(false) else {
                    return Poll::Ready(Err(UpkaError::QUEUE_FULL));
                };
                s.queue_slots[idx as usize].register_waiter(cx);
                queue_idx = Some(idx);
                Poll::Pending
            })
        })
        .await
    }

    /// Acquire a specific engine by ID.
    pub(crate) async fn acquire_engine(
        &self,
        target: u8,
    ) -> HsmResult<UpkaEngine<'a, DEPTH, ENGINES>> {
        if usize::from(target) >= ENGINES {
            return Err(UpkaError::CMD_ERROR);
        }

        let mut registered = false;

        poll_fn(move |cx| {
            self.driver.state.with(|s| {
                let waiter = &mut s.specific_waiters[target as usize];
                if waiter.assigned {
                    waiter.assigned = false;
                    registered = false;
                    return Poll::Ready(Ok(self.make_engine(target)));
                }

                let bit = 1u16 << target;
                if s.free_mask & bit != 0 {
                    Self::assign_engine(s, target, false);
                    return Poll::Ready(Ok(self.make_engine(target)));
                }

                if !registered {
                    if waiter.waiting {
                        return Poll::Ready(Err(UpkaError::QUEUE_FULL));
                    }
                    waiter.waiting = true;
                    registered = true;
                }

                waiter.register_waiter(cx);
                Poll::Pending
            })
        })
        .await
    }

    /// Poll one engine and wake waiters if completed.
    pub(crate) fn wake_engine(&self, id: u8) {
        self.driver.state.with(|s| {
            Self::wake_engine_inner(s, id as usize);
        });
    }

    fn wake_engine_inner(s: &mut UpkaState<DEPTH, ENGINES>, id: usize) {
        let slot = &mut s.engine_slots[id];
        if !slot.is_in_use() || !slot.is_completion_armed() || slot.has_completion_status() {
            return;
        }
        let flags = EngineExecutor::completion_flags(id as u8);
        if flags != 0 {
            slot.capture_completion_status(flags as u8);
            Nvic::unpend_raw(Interrupt::UPKA_0_DONE as u16 + id as u16);
            Nvic::unpend_raw(Interrupt::UPKA_0_ERROR as u16 + id as u16);
            slot.wake_waiter();
        }
    }

    /// Release an engine and dispatch next queued waiter if available.
    pub(crate) fn release_engine(&self, id: u8) {
        self.driver.state.with(|s| {
            let _ = s.release_engine_and_dispatch(id);
        });
    }
}

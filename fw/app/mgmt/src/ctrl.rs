// Copyright (C) Microsoft Corporation. All rights reserved.

use std::task::Poll;

use azihsm_fw_pal_mgmt::MgmtQueueCtrlEvent;
use embassy_sync::waitqueue::WakerRegistration;
use futures::future::poll_fn;
use parking_lot::Mutex;

use super::*;

struct State {
    waker: WakerRegistration,
}

pub(crate) struct QueueCtrl {
    state: Mutex<State>,
}

impl QueueCtrl {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                waker: WakerRegistration::new(),
            }),
        }
    }

    pub fn wait_for_event(&self) -> impl Future<Output = MgmtQueueCtrlEvent> {
        poll_fn(|cx| {
            let mut state = self.state.lock();
            let Some(event) = mgmt_plat_poll_ctrl_event() else {
                state.waker.register(cx.waker());
                return Poll::Pending;
            };

            match event {
                MgmtQueueCtrlEvent::Enable { ctrl_id } => {
                    mgmt_plat_enable_ctrl(ctrl_id);
                }
                MgmtQueueCtrlEvent::Disable { ctrl_id } => {
                    mgmt_plat_disable_ctrl(ctrl_id);
                }
            }

            Poll::Ready(event)
        })
    }

    pub fn on_ctrl_event(&self) {
        let state = &mut *self.state.lock();
        state.waker.wake();
    }
}

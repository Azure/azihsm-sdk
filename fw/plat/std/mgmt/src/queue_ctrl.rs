// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_fw_pal_mgmt::*;
use bitvec::prelude::*;
use parking_lot::Mutex;

use crate::mgmt_app_on_ctrl_event;

struct State {
    ready: BitArray<[u64; 2], Lsb0>,
    curr: BitArray<[u64; 2], Lsb0>,
}

/// Queue Controller
pub(crate) struct QueueController {
    state: Mutex<State>,
}

impl QueueController {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                curr: bitarr![u64, Lsb0; 0; 65],
                ready: bitarr![u64, Lsb0; 0; 65],
            }),
        }
    }

    pub fn poll_ctrl_event(&self) -> Option<MgmtQueueCtrlEvent> {
        let state = &mut *self.state.lock();

        let changed = state.ready ^ state.curr;
        // println!("Curr bitset: {:?}", state.curr);
        // println!("Ready bitset: {:?}", state.ready);
        let Some(ctrl_id) = changed.first_one() else {
            return None;
        };

        // println!("Found changed ctrl_id {}", ctrl_id);

        match (state.ready[ctrl_id], state.curr[ctrl_id]) {
            (false, true) => Some(MgmtQueueCtrlEvent::Enable {
                ctrl_id: ctrl_id as u16,
            }),
            (true, false) => Some(MgmtQueueCtrlEvent::Disable {
                ctrl_id: ctrl_id as u16,
            }),
            _ => {
                debug_assert!(false, "Inconsistent state in QueueController {ctrl_id}");
                None
            }
        }
    }

    pub fn enable_ctrl(&self, ctrl_id: MgmtCtrlId) {
        // tracing::info!("XXXX QueueController enabling ctrl_id {}", ctrl_id);
        let state = &mut *self.state.lock();
        state.ready.set(ctrl_id as usize, true);
    }

    pub fn disable_ctrl(&self, ctrl_id: MgmtCtrlId) {
        // tracing::info!("YYYY QueueController disabling ctrl_id {}", ctrl_id);
        let state = &mut *self.state.lock();
        state.ready.set(ctrl_id as usize, false);
    }

    pub fn on_enable_ctrl(&self, ctrl_id: u16) {
        {
            let mut state = self.state.lock();

            // println!("MMMMMMM Enabling ctrl_id {} in curr bitset", ctrl_id);
            state.curr.set(ctrl_id as usize, true);
            // println!("Curr bitset after enabling: {:?}", state.curr);
        }

        mgmt_app_on_ctrl_event();
    }

    pub fn on_disable_ctrl(&self, ctrl_id: u16) {
        {
            let mut state = self.state.lock();
            // println!("NNNNNN Disabling ctrl_id {} in curr bitset", ctrl_id);

            state.curr.set(ctrl_id as usize, false);

            // println!("Curr bitset after disabling: {:?}", state.curr);
        }

        mgmt_app_on_ctrl_event();
    }

    pub fn ctrl_ready(&self, ctrl_id: MgmtCtrlId) -> bool {
        let state = &*self.state.lock();
        state.ready[ctrl_id as usize]
    }
}

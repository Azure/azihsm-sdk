// Copyright (C) Microsoft Corporation. All rights reserved.
pub type MgmtCtrlId = u16;

#[derive(Debug, Clone, Copy)]
pub enum MgmtQueueCtrlEvent {
    Enable { ctrl_id: MgmtCtrlId },
    Disable { ctrl_id: MgmtCtrlId },
}

pub trait MgmtPlat {
    fn poll_ctrl_event(&self) -> Option<MgmtQueueCtrlEvent>;

    fn enable_ctrl(&self, ctrl_id: MgmtCtrlId);

    fn disable_ctrl(&self, ctrl_id: MgmtCtrlId);
}

#[macro_export]
macro_rules! mgmt_plat_impl {
    ($vis:vis static $name:ident : $ty:ty = $init:expr;) => {
        $vis static $name: $ty = $init;

        #[inline]
        #[unsafe(no_mangle)]
        pub unsafe extern "Rust" fn _mgmt_plat_poll_ctrl_event()
        -> Option<$crate::MgmtQueueCtrlEvent> {
            <$ty as $crate::MgmtPlat>::poll_ctrl_event(&$name)
        }

        #[inline]
        #[unsafe(no_mangle)]
        pub unsafe extern "Rust" fn _mgmt_plat_enable_ctrl(ctrl_id: MgmtCtrlId) {
            <$ty as $crate::MgmtPlat>::enable_ctrl(&$name, ctrl_id);
        }

        #[inline]
        #[unsafe(no_mangle)]
        pub unsafe extern "Rust" fn _mgmt_plat_disable_ctrl(ctrl_id: MgmtCtrlId) {
            <$ty as $crate::MgmtPlat>::disable_ctrl(&$name, ctrl_id);
        }
    };
}

#[macro_export]
macro_rules! mgmt_plat_imports {
    () => {
        #[allow(unsafe_code)]
        unsafe extern "Rust" {
            fn _mgmt_plat_poll_ctrl_event() -> Option<$crate::MgmtQueueCtrlEvent>;

            fn _mgmt_plat_enable_ctrl(ctrl_id: $crate::MgmtCtrlId);

            fn _mgmt_plat_disable_ctrl(ctrl_id: $crate::MgmtCtrlId);
        }

        #[inline]
        #[allow(unsafe_code)]
        pub fn mgmt_plat_poll_ctrl_event() -> Option<$crate::MgmtQueueCtrlEvent> {
            unsafe { _mgmt_plat_poll_ctrl_event() }
        }

        #[inline]
        #[allow(unsafe_code)]
        pub fn mgmt_plat_enable_ctrl(ctrl_id: $crate::MgmtCtrlId) {
            unsafe { _mgmt_plat_enable_ctrl(ctrl_id) };
        }

        #[inline]
        #[allow(unsafe_code)]
        pub fn mgmt_plat_disable_ctrl(ctrl_id: $crate::MgmtCtrlId) {
            unsafe { _mgmt_plat_disable_ctrl(ctrl_id) };
        }
    };
}

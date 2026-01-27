// Copyright (C) Microsoft Corporation. All rights reserved.

/// Management application trait.
pub trait MgmtApp: Send + Sync + 'static {
    /// Starts the management application
    ///
    /// # Arguments
    ///
    /// * `spawner` - The embassy executor spawner to use for scheduling async tasks.
    fn start(&self, spawner: embassy_executor::Spawner);

    /// Stops the management application and cleans up its resources.
    fn stop(&self);
}

// #[allow(unsafe_code)]
// unsafe extern "Rust" {
//     /// Starts the management application.
//     ///
//     /// # Arguments
//     ///
//     /// * `spawner` - The embassy executor spawner to use for scheduling async tasks.
//     unsafe fn _mgmt_app_start(spawner: embassy_executor::Spawner);

//     /// Stops the management application.
//     unsafe fn _mgmt_app_stop();
// }

#[macro_export]
macro_rules! mgmt_app_impl {
    (static $name:ident: $ty:ty = $init:expr;) => {
        static $name: $ty = $init;

        /// Starts the management application.
        #[inline]
        #[unsafe(no_mangle)]
        pub unsafe extern "Rust" fn _mgmt_app_start(spawner: embassy_executor::Spawner) {
            <$ty as $crate::MgmtApp>::start(&$name, spawner);
        }

        /// Stops the management application.
        #[inline]
        #[unsafe(no_mangle)]
        pub unsafe extern "Rust" fn _mgmt_app_stop() {
            <$ty as $crate::MgmtApp>::stop(&$name);
        }
    };
}

#[macro_export]
macro_rules! mgmt_app_imports {
    () => {
        #[allow(unsafe_code)]
        unsafe extern "Rust" {
            /// Starts the management application.
            ///
            /// # Arguments
            ///
            /// * `spawner` - The embassy executor spawner to use for scheduling async tasks.
            unsafe fn _mgmt_app_start(spawner: embassy_executor::Spawner);

            /// Stops the management application.
            unsafe fn _mgmt_app_stop();
        }

        /// Starts the management application.
        ///
        /// # Arguments
        ///
        /// * `spawner` - The embassy executor spawner to use for scheduling async tasks.
        #[inline]
        pub(crate) fn mgmt_app_start(spawner: embassy_executor::Spawner) {
            unsafe { _mgmt_app_start(spawner) }
        }

        /// Stops the management application.
        #[inline]
        pub(crate) fn mgmt_app_stop() {
            unsafe { _mgmt_app_stop() }
        }
    };
}

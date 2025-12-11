// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_extension_support_virtual() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let dev_info = get_device_info(ddi, path);

            if dev_info.kind == DdiDeviceKind::Virtual {
                let resp = helper_get_api_rev_ext(dev, None, None);

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

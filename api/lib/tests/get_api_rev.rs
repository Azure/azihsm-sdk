// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_get_api_rev() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let api_rev_range = device.get_api_revision_range();

        assert!(api_rev_range.min.major <= api_rev_range.max.major);

        if api_rev_range.min.major == api_rev_range.max.major {
            assert!(api_rev_range.min.minor <= api_rev_range.max.minor);
        }

        assert_eq!(api_rev_range.min.major, 1);
        assert_eq!(api_rev_range.min.minor, 0);
        assert_eq!(api_rev_range.max.major, 1);
        assert_eq!(api_rev_range.max.minor, 0);
    });
}

#[test]
fn test_api_rev_comparison() {
    api_test(common_setup, common_cleanup, |_device, _path| {
        let api_rev_1_0 = HsmApiRevision { major: 1, minor: 0 };

        let api_rev_1_1 = HsmApiRevision { major: 1, minor: 1 };

        let api_rev_2_0 = HsmApiRevision { major: 2, minor: 0 };

        let api_rev_2_1 = HsmApiRevision { major: 2, minor: 1 };

        assert!(api_rev_1_0 < api_rev_1_1);
        assert!(api_rev_1_0 < api_rev_2_0);
        assert!(api_rev_1_0 < api_rev_2_1);

        assert!(api_rev_1_1 < api_rev_2_0);
        assert!(api_rev_1_1 < api_rev_2_1);

        assert!(api_rev_2_0 < api_rev_2_1);

        assert!(api_rev_1_0 == api_rev_1_0);
    });
}

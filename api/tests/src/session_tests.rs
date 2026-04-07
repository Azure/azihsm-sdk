// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[partition_test]
fn test_open_session(part: HsmPartition, creds: HsmCredentials) {
    let rev = part.api_rev();
    let _session = part
        .open_session(rev, &creds, None)
        .expect("Failed to open session");
}

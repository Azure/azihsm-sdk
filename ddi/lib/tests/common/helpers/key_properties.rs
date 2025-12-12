// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_key_properties_with_label(
    key_usage: DdiKeyUsage,
    key_availability: DdiKeyAvailability,
    key_label: MborByteArray<DDI_MAX_KEY_LABEL_LENGTH>,
) -> DdiKeyProperties {
    DdiKeyProperties {
        key_usage,
        key_availability,
        key_label,
    }
}

pub fn helper_key_properties(
    key_usage: DdiKeyUsage,
    key_availability: DdiKeyAvailability,
) -> DdiKeyProperties {
    helper_key_properties_with_label(
        key_usage,
        key_availability,
        MborByteArray::from_slice(&[]).expect("Failed to create empty byte array for key label"),
    )
}

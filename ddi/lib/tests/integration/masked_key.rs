// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_malformed_ddi() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_get_api_rev_op(
                dev,
                DdiOp::UnmaskKey,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::DdiDecodeFailed)
            ));
        },
    );
}

#[test]
fn test_masked_key_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let masked_key = resp.data.masked_key;

            let resp = helper_unmask_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_masked_key_malformed_mask_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            const FORMAT_OFFSET: usize = 2;
            const ALGORITHM_OFFSET: usize = FORMAT_OFFSET + 2;
            const IV_LEN_OFFSET: usize = ALGORITHM_OFFSET + 2;
            const IV_PADDING_OFFSET: usize = IV_LEN_OFFSET + 2;
            const METADATA_LEN_OFFSET: usize = IV_PADDING_OFFSET + 2;
            const METADATA_PADDING_OFFSET: usize = METADATA_LEN_OFFSET + 2;
            const ENCRYPTED_KEY_LEN_OFFSET: usize = METADATA_PADDING_OFFSET + 2;
            const ENCRYPTED_KEY_PADDING_OFFSET: usize = ENCRYPTED_KEY_LEN_OFFSET + 2;
            const TAG_LEN_OFFSET: usize = ENCRYPTED_KEY_PADDING_OFFSET + 2;
            const RESERVED_OFFSET: usize = TAG_LEN_OFFSET + 34;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let masked_key = resp.data.masked_key;

            let iv_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[ALGORITHM_OFFSET..IV_LEN_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();
            let iv_padding_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[IV_LEN_OFFSET..IV_PADDING_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();
            let metadata_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[IV_PADDING_OFFSET..METADATA_LEN_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();
            let metadata_padding_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[METADATA_LEN_OFFSET..METADATA_PADDING_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();
            let encrypted_key_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[METADATA_PADDING_OFFSET..ENCRYPTED_KEY_LEN_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();
            let encrypted_key_padding_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[ENCRYPTED_KEY_LEN_OFFSET..ENCRYPTED_KEY_PADDING_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();
            let tag_len: usize = u16::from_le_bytes(
                masked_key.as_slice()[ENCRYPTED_KEY_PADDING_OFFSET..TAG_LEN_OFFSET]
                    .try_into()
                    .unwrap(),
            )
            .into();

            {
                // Malformed generic header
                let mut malformed_masked_key = masked_key;
                malformed_masked_key.as_mut_slice()[..ALGORITHM_OFFSET].fill(0xff);
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    malformed_masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }

            {
                // Malformed AES header
                let mut malformed_masked_key = masked_key;
                malformed_masked_key.as_mut_slice()[ALGORITHM_OFFSET..RESERVED_OFFSET].fill(0xff);
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    malformed_masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }

            {
                // Malformed IV
                let mut malformed_masked_key = masked_key;
                malformed_masked_key.as_mut_slice()[RESERVED_OFFSET..RESERVED_OFFSET + iv_len]
                    .fill(0xff);
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    malformed_masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }

            {
                // Malformed metadata
                let mut malformed_masked_key = masked_key;
                let metadata_offset = RESERVED_OFFSET + iv_len + iv_padding_len;
                malformed_masked_key.as_mut_slice()
                    [metadata_offset..metadata_offset + metadata_len]
                    .fill(0xff);
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    malformed_masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }

            {
                // Malformed encrypted key data
                let mut malformed_masked_key = masked_key;
                let encrypted_data_offset =
                    RESERVED_OFFSET + iv_len + iv_padding_len + metadata_len + metadata_padding_len;
                malformed_masked_key.as_mut_slice()
                    [encrypted_data_offset..encrypted_data_offset + encrypted_key_len]
                    .fill(0xff);
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    malformed_masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }

            {
                // Malformed integrity tag
                let mut malformed_masked_key = masked_key;
                let tag_offset = RESERVED_OFFSET
                    + iv_len
                    + iv_padding_len
                    + metadata_len
                    + metadata_padding_len
                    + encrypted_key_len
                    + encrypted_key_padding_len;
                malformed_masked_key.as_mut_slice()[tag_offset..tag_offset + tag_len].fill(0xff);
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    malformed_masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }
        },
    );
}

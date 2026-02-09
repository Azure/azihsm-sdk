// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Get Param Encryption Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialReq {
    /// Encrypted credential
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedEstablishCredential,

    /// Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,

    /// Masked BK3
    #[ddi(id = 3)]
    pub masked_bk3: MborByteArray<1024>,

    /// Backed up Masked Key, if available
    #[ddi(id = 4)]
    pub bmk: MborByteArray<1024>,

    /// Masked unwrapping key, if available
    #[ddi(id = 5)]
    pub masked_unwrapping_key: MborByteArray<1024>,

    /// Partition ID signed by the TPM/Caller/Ephemeral key
    #[ddi(id = 6)]
    #[ddi(pre_encode_fn = "signature_pre_encode")]
    pub signed_pid: MborByteArray<1024>,

    /// TPM/Caller/Ephemeral Partition ID Endorsement Public Key
    #[ddi(id = 7)]
    pub tpm_pub_key: DdiDerPublicKey,
}

impl DdiEstablishCredentialReq {
    #[cfg(feature = "pre_encode")]
    pub fn signature_pre_encode(
        &self,
        input_array: &MborByteArray<1024>,
    ) -> Result<MborByteArray<1024>, MborEncodeError> {
        let mut output_array = [0u8; 1024];

        // We need to split the array into two components,
        // then convert endianness for each component.

        // Validate length.
        if input_array.len() != 96 {
            Err(MborEncodeError::InvalidLen)?
        }

        let input_component_len = input_array.len() / 2;

        // Convert from big Endian to little Endian for first component.
        let data = input_array.data();
        reverse_copy(
            &mut output_array[..input_component_len],
            &data[..input_component_len],
        );

        // Convert from little Endian to big Endian for second component.
        reverse_copy(
            &mut output_array[input_component_len..input_array.len()],
            &data[input_component_len..input_array.len()],
        );

        Ok(MborByteArray::new(output_array, input_array.len())?)
    }
}

/// DDI Get Param Encryption Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialResp {
    /// Backed up Masked Key
    #[ddi(id = 1)]
    pub bmk: MborByteArray<1024>,
}

ddi_op_req_resp!(DdiEstablishCredential);

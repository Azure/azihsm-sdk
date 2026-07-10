// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain sealing key structures and generation.
//!
//! This module provides the sealing key type and its generation
//! algorithm for use with security-domain (V2) HSM sessions. It
//! implements the key generation operation that creates a
//! security-domain sealing key within the hardware security module via
//! the TBOR `SdSealingKeyGen` command.

use super::*;

// A sealing key stored in the HSM, used for security-domain
// sealing/unsealing (derivation) operations.
define_hsm_key!(pub HsmSealingKey);

/// `KeyScope::SecurityDomain` discriminant (mirror of the firmware
/// `HsmKeyScope`). Security-domain sealing keys are generated with this
/// scope.
const KEY_SCOPE_SECURITY_DOMAIN: u8 = 4;

impl HsmSealingKey {
    /// Validates that `props` describe a supported HSM sealing key: a
    /// `Sealing`-kind secret key permitted for derivation only.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        if props.class() != HsmKeyClass::Secret
            || !Self::check_key_kind(props)
            || !Self::check_key_usage(props)
        {
            return Err(HsmError::InvalidKeyProps);
        }
        Ok(())
    }

    fn check_key_kind(props: &HsmKeyProps) -> bool {
        let supported_flag = match props.kind() {
            HsmKeyKind::Sealing => HsmKeyFlags::DERIVE,
            _ => return false,
        };
        props.check_supported_flags(supported_flag)
    }

    fn check_key_usage(props: &HsmKeyProps) -> bool {
        //check if key usage flags are valid for the key kind
        match props.kind() {
            HsmKeyKind::Sealing => props.can_derive(),
            _ => false,
        }
    }
}

impl HsmSecretKey for HsmSealingKey {}

impl HsmDerivationKey for HsmSealingKey {}

#[derive(Default)]
pub struct HsmSealingKeyGenAlgo {}

impl HsmKeyGenOp for HsmSealingKeyGenAlgo {
    type Key = HsmSealingKey;
    type Error = HsmError;
    type Session = HsmSession;

    /// Generates a new security-domain sealing key in the session's
    /// partition vault via TBOR `SdSealingKeyGen` (opcode `0x09`).
    ///
    /// Only valid on a V2 (security-domain) session; a V1 session yields
    /// [`HsmError::InvalidSession`].
    fn generate_key(
        &mut self,
        session: &Self::Session,
        props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error> {
        // Validate key properties before generating the key.
        HsmSealingKey::validate_props(&props)?;

        let handle = ddi::sd_sealing_key_gen(session, KEY_SCOPE_SECURITY_DOMAIN)?;
        Ok(HsmSealingKey::new(session.clone(), props, handle))
    }
}

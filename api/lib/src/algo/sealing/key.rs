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

// A security-domain sealing key held as a masked (AEAD-GCM-256) blob.
// Non-resident: not stored on the device or in the vault; the masked
// blob is cached in props and unmasked on-use.
define_hsm_key!(pub HsmSealingKey, ddi::HsmNoKeyHandle);

/// Host mirror of the firmware `HsmKeyScope` — a key's lifecycle /
/// visibility domain. Carried on the wire as its raw `u8` discriminant
/// because this crate is firewalled from the firmware PAL types.
#[repr(u8)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum KeyScope {
    Unspecified = 0,
    Session = 1,
    Ephemeral = 2,
    Local = 3,
    SecurityDomain = 4,
    Internal = 5,
}

/// Bit length of a security-domain sealing key. `SdSealingKeyGen` always
/// produces an ECC P-384 keypair, so the props must be sized to match.
const SEALING_KEY_BITS: u32 = 384;

impl HsmSealingKey {
    /// No-op: non-resident, so there is no device handle to restore.
    /// Kept for `#[resiliency_key_op]` compatibility.
    #[allow(unused)]
    pub(crate) fn restore_from_masked(&self) -> HsmResult<()> {
        Ok(())
    }

    /// Validates that `props` describe a supported HSM sealing key: a
    /// `Sealing`-kind secret key, P-384 sized, permitted for derivation
    /// only.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        if props.class() != HsmKeyClass::Secret
            || props.bits() != SEALING_KEY_BITS
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
        // Derivation is the only usage permitted for a sealing key.
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

    /// Generates a new security-domain sealing key via TBOR
    /// `SdSealingKeyGen` (opcode `0x09`). The key is returned as a
    /// non-resident masked blob cached in `props`, not stored in the
    /// partition vault.
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

        // Cache the masked blob and public key in props. The key is
        // non-resident (`HsmNoKeyHandle`) until unmasked on-use. Masked
        // under the partition-local masking key so the blob survives
        // across launches for unmask-on-use.
        let (masked_key, pub_key_der) = ddi::sd_sealing_key_gen(session, KeyScope::Local as u8)?;
        let mut props = props;
        props.set_masked_key(&masked_key);
        props.set_pub_key_der(&pub_key_der);
        Ok(HsmSealingKey::new(
            session.clone(),
            props,
            ddi::HsmNoKeyHandle,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-formed sealing key props: a `Sealing`-kind secret key
    /// permitted for derivation.
    fn sealing_props() -> HsmKeyProps {
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Sealing)
            .bits(384)
            .can_derive(true)
            .build()
            .expect("build sealing props")
    }

    #[test]
    fn validate_props_accepts_sealing_secret_derive() {
        assert!(HsmSealingKey::validate_props(&sealing_props()).is_ok());
    }

    #[test]
    fn validate_props_rejects_wrong_kind() {
        // A secret derive key of a non-`Sealing` kind must be rejected.
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(256)
            .can_derive(true)
            .build()
            .expect("build props");
        assert_eq!(
            HsmSealingKey::validate_props(&props),
            Err(HsmError::InvalidKeyProps),
        );
    }

    #[test]
    fn validate_props_rejects_wrong_bits() {
        // A `Sealing` secret derive key that isn't P-384 must be rejected.
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Sealing)
            .bits(256)
            .can_derive(true)
            .build()
            .expect("build props");
        assert_eq!(
            HsmSealingKey::validate_props(&props),
            Err(HsmError::InvalidKeyProps),
        );
    }

    #[test]
    fn validate_props_rejects_missing_derive() {
        // A `Sealing` secret key without derive usage must be rejected.
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Sealing)
            .bits(384)
            .build()
            .expect("build props");
        assert_eq!(
            HsmSealingKey::validate_props(&props),
            Err(HsmError::InvalidKeyProps),
        );
    }
}

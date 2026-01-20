// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_void;
use std::slice;

use azihsm_api::*;
use zerocopy::IntoBytes;

use super::*;

/// Key property identifier enumeration.
///
/// This enum defines the various properties that can be associated with cryptographic keys
/// in the HSM. Each property has a unique identifier that is used to query or set specific
/// attributes of a key object.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AzihsmKeyPropId {
    /// Key class property (e.g., Private, Public, Secret).
    // Corresponds to AZIHSM_KEY_PROP_ID_CLASS
    Class = 1,

    /// Key kind property (e.g., RSA, ECC, AES).
    // Corresponds to AZIHSM_KEY_PROP_ID_KIND
    Kind = 2,

    /// Bit length of the key.
    // Corresponds to AZIHSM_KEY_PROP_ID_BIT_LEN
    BitLen = 3,

    /// Human-readable label for the key.
    // Corresponds to AZIHSM_KEY_PROP_ID_LABEL
    Label = 4,

    /// Public key information associated with the key.
    // Corresponds to AZIHSM_KEY_PROP_PUB_KEY_INFO
    PubKeyInfo = 5,

    /// Elliptic curve identifier for ECC keys.
    // Corresponds to AZIHSM_KEY_PROP_ID_EC_CURVE
    EcCurve = 6,

    /// Whether the key is masked (protected by hardware).
    // Corresponds to AZIHSM_KEY_PROP_ID_MASKED_KEY
    MaskedKey = 7,

    /// Session handle associated with the key.
    // Corresponds to AZIHSM_KEY_PROP_ID_SESSION
    Session = 8,

    /// Whether the key was generated locally in the HSM.
    // Corresponds to AZIHSM_KEY_PROP_ID_LOCAL
    Local = 9,

    /// Whether the key is sensitive (cannot be revealed in plaintext).
    // Corresponds to AZIHSM_KEY_PROP_ID_SENSITIVE
    Sensitive = 10,

    /// Whether the key can be extracted from the HSM.
    // Corresponds to AZIHSM_KEY_PROP_ID_EXTRACTABLE
    Extractable = 11,

    /// Whether the key can be used for encryption operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_ENCRYPT
    Encrypt = 12,

    /// Whether the key can be used for decryption operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_DECRYPT
    Decrypt = 13,

    /// Whether the key can be used for signing operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_SIGN
    Sign = 14,

    /// Whether the key can be used for verification operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_VERIFY
    Verify = 15,

    /// Whether the key can be used for key wrapping operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_WRAP
    Wrap = 16,

    /// Whether the key can be used for key unwrapping operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_UNWRAP
    Unwrap = 17,

    /// Whether the key can be used for key derivation operations.
    // Corresponds to AZIHSM_KEY_PROP_ID_DERIVE
    Derive = 18,
}

/// C FFI structure for a single key property
///
/// # Safety
/// When using this struct from C code:
/// - `val` must point to valid memory for `len` bytes
/// - `val` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
///
#[repr(C)]
pub struct AzihsmKeyProp {
    /// Property identifier
    pub id: AzihsmKeyPropId,

    /// Pointer to the property value
    pub val: *mut c_void,

    /// Length of the property value in bytes
    pub len: u32,
}

/// C FFI structure for a list of key properties
///
/// # Safety
/// When using this struct from C code:
/// - `props` must point to valid memory for `count` elements
/// - Each element's `val` must point to valid memory for `len` bytes
/// - The lifetimes of `props` and its elements must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
///
#[repr(C)]
pub struct AzihsmKeyPropList {
    /// Pointer to an array of key properties
    pub props: *mut AzihsmKeyProp,

    /// Number of key properties in the array
    pub count: u32,
}

/// Extract a boolean value from a key property
impl TryFrom<&AzihsmKeyProp> for bool {
    type Error = AzihsmStatus;

    /// Converts a key property to a boolean.
    ///
    /// # Safety
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing a u8 value.
    #[allow(unsafe_code)]
    fn try_from(prop: &AzihsmKeyProp) -> Result<Self, Self::Error> {
        if prop.val.is_null() || prop.len != 1 {
            Err(AzihsmStatus::InvalidArgument)?;
        }
        let val_ptr = prop.val as *const u8;
        // SAFETY: Caller ensures prop.val is valid pointer to u8
        let bool_val = unsafe { *val_ptr != 0 };
        Ok(bool_val)
    }
}

/// Extract a u32 value from a key property
impl TryFrom<&AzihsmKeyProp> for u32 {
    type Error = AzihsmStatus;

    /// Converts a key property to a u32.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing a u32 value.
    #[allow(unsafe_code)]
    fn try_from(prop: &AzihsmKeyProp) -> Result<Self, Self::Error> {
        if prop.val.is_null() || prop.len != std::mem::size_of::<u32>() as u32 {
            Err(AzihsmStatus::InvalidArgument)?;
        }
        let val_ptr = prop.val as *const u32;
        Ok(
            // SAFETY: Caller ensures prop.val is valid pointer to u32
            unsafe { *val_ptr },
        )
    }
}

/// Extract an ECC curve value from a key property
impl TryFrom<&AzihsmKeyProp> for HsmEccCurve {
    type Error = AzihsmStatus;

    /// Converts a key property to an ECC curve.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing a u32 value.
    #[allow(unsafe_code)]
    fn try_from(prop: &AzihsmKeyProp) -> Result<Self, Self::Error> {
        let value = u32::try_from(prop)?;
        Ok(AzihsmEccCurve::try_from(value)?.into())
    }
}

/// Extract a key kind value from a key property
impl TryFrom<&AzihsmKeyProp> for HsmKeyKind {
    type Error = AzihsmStatus;

    /// Converts a key property to a key type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing a u32 value.
    #[allow(unsafe_code)]
    fn try_from(prop: &AzihsmKeyProp) -> Result<Self, Self::Error> {
        let value = u32::try_from(prop)?;
        Ok(AzihsmKeyKind::try_from(value)?.into())
    }
}

/// Extract a key class value from a key property
impl TryFrom<&AzihsmKeyProp> for HsmKeyClass {
    type Error = AzihsmStatus;
    /// Converts a key property to a key class.
    /// # Safety
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing a u32 value.
    #[allow(unsafe_code)]
    fn try_from(prop: &AzihsmKeyProp) -> Result<Self, Self::Error> {
        let value = u32::try_from(prop)?;
        Ok(AzihsmKeyClass::try_from(value)?.into())
    }
}

/// Extract a byte slice from a key property
impl TryFrom<&AzihsmKeyProp> for &[u8] {
    type Error = AzihsmStatus;

    /// Converts a key property to a byte vector.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing at least `prop.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(prop: &AzihsmKeyProp) -> Result<Self, Self::Error> {
        validate_ptr(prop.val)?;

        // SAFETY: Pointer has been validated as non-null above
        let slice = unsafe { slice::from_raw_parts(prop.val as *const u8, prop.len as usize) };
        Ok(slice)
    }
}

/// Extract key properties from C FFI key property list into HsmKeyProps
impl TryFrom<&AzihsmKeyPropList> for HsmKeyProps {
    type Error = AzihsmStatus;

    /// Extract key properties from C FFI key property list into a builder.
    ///
    /// # Safety
    ///
    /// This implementation is unsafe because it dereferences raw pointers from C.
    /// The caller must ensure that:
    /// - The pointer is a valid pointer to `AzihsmKeyPropList`
    /// - The `props` array contains `count` valid elements
    /// - Each property's `val` pointer is valid and points to data of `len` bytes
    /// - The memory remains valid for the duration of this function call
    #[allow(unsafe_code)]
    fn try_from(key_props_list: &AzihsmKeyPropList) -> Result<Self, Self::Error> {
        if key_props_list.props.is_null() || key_props_list.count == 0 {
            Err(AzihsmStatus::InvalidArgument)?;
        }

        let mut builder = HsmKeyPropsBuilder::default();

        // SAFETY: the function ensures that the pointer is valid
        let prop_slice =
            unsafe { slice::from_raw_parts(key_props_list.props, key_props_list.count as usize) };

        for prop in prop_slice {
            if prop.val.is_null() {
                Err(AzihsmStatus::InvalidArgument)?;
            }

            builder = match prop.id {
                AzihsmKeyPropId::Session => builder.is_session(prop.try_into()?),

                AzihsmKeyPropId::Encrypt => builder.can_encrypt(prop.try_into()?),

                AzihsmKeyPropId::Decrypt => builder.can_decrypt(prop.try_into()?),

                AzihsmKeyPropId::Sign => builder.can_sign(prop.try_into()?),

                AzihsmKeyPropId::Verify => builder.can_verify(prop.try_into()?),

                AzihsmKeyPropId::Wrap => builder.can_wrap(prop.try_into()?),

                AzihsmKeyPropId::Unwrap => builder.can_unwrap(prop.try_into()?),

                AzihsmKeyPropId::Derive => builder.can_derive(prop.try_into()?),

                AzihsmKeyPropId::BitLen => builder.bits(prop.try_into()?),

                AzihsmKeyPropId::EcCurve => builder.ecc_curve(prop.try_into()?),

                AzihsmKeyPropId::Kind => builder.key_kind(prop.try_into()?),

                AzihsmKeyPropId::Label => builder.label(prop.try_into()?),

                AzihsmKeyPropId::Class => builder.class(prop.try_into()?),

                // These properties are not settable by the user
                AzihsmKeyPropId::Local
                | AzihsmKeyPropId::Sensitive
                | AzihsmKeyPropId::Extractable => Err(AzihsmStatus::InvalidArgument)?,

                // Ignore unknown properties
                _ => builder,
            };
        }

        Ok(builder.build()?)
    }
}

/// Get a property of a key
///
/// @param[in] key Handle to the key
/// @param[in/out] key_prop Pointer to key property structure. On input, specifies which property to get. On output, contains the property value.
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_get_prop(
    key_handle: AzihsmHandle,
    key_prop: *mut AzihsmKeyProp,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(key_prop)?;

        let prop = deref_mut_ptr(key_prop)?;
        let key_type = HandleType::try_from(key_handle)?;

        match key_type {
            HandleType::EccPubKey => {
                let key = HsmEccPublicKey::try_from(key_handle)?;
                get_key_prop(key, prop)
            }
            HandleType::EccPrivKey => {
                let key = HsmEccPrivateKey::try_from(key_handle)?;
                get_key_prop(key, prop)
            }
            HandleType::AesKey => {
                let key = HsmAesKey::try_from(key_handle)?;
                get_key_prop(key, prop)
            }
            HandleType::RsaPubKey => {
                let key = HsmRsaPublicKey::try_from(key_handle)?;
                get_key_prop(key, prop)
            }
            HandleType::RsaPrivKey => {
                let key = HsmRsaPrivateKey::try_from(key_handle)?;
                get_key_prop(key, prop)
            }
            _ => Err(AzihsmStatus::InvalidHandle),
        }
    })
}

/// Helper function to get a key property
fn get_key_prop(
    key: impl HsmKeyCommonProps,
    key_prop: &mut AzihsmKeyProp,
) -> Result<(), AzihsmStatus> {
    match key_prop.id {
        AzihsmKeyPropId::Class => copy_to_key_prop(key_prop, key.class().as_bytes()),
        AzihsmKeyPropId::Kind => copy_to_key_prop(key_prop, key.kind().as_bytes()),
        AzihsmKeyPropId::BitLen => copy_to_key_prop(key_prop, &key.bits().to_le_bytes()),
        AzihsmKeyPropId::Label => copy_to_key_prop(key_prop, &key.label()),
        AzihsmKeyPropId::PubKeyInfo => copy_to_key_prop(key_prop, &key.pub_key_der_vec()?),
        AzihsmKeyPropId::EcCurve => {
            let Some(curve) = key.ecc_curve() else {
                Err(AzihsmStatus::KeyPropertyNotPresent)?
            };
            copy_to_key_prop(key_prop, curve.as_bytes())
        }
        AzihsmKeyPropId::MaskedKey => copy_to_key_prop(key_prop, &key.masked_key_vec()?),
        AzihsmKeyPropId::Session => copy_to_key_prop(key_prop, key.is_session().as_bytes()),
        AzihsmKeyPropId::Local => copy_to_key_prop(key_prop, key.is_local().as_bytes()),
        AzihsmKeyPropId::Sensitive => copy_to_key_prop(key_prop, key.is_sensitive().as_bytes()),
        AzihsmKeyPropId::Extractable => copy_to_key_prop(key_prop, key.is_extractable().as_bytes()),
        AzihsmKeyPropId::Encrypt => copy_to_key_prop(key_prop, key.can_encrypt().as_bytes()),
        AzihsmKeyPropId::Decrypt => copy_to_key_prop(key_prop, key.can_decrypt().as_bytes()),
        AzihsmKeyPropId::Sign => copy_to_key_prop(key_prop, key.can_sign().as_bytes()),
        AzihsmKeyPropId::Verify => copy_to_key_prop(key_prop, key.can_verify().as_bytes()),
        AzihsmKeyPropId::Wrap => copy_to_key_prop(key_prop, key.can_wrap().as_bytes()),
        AzihsmKeyPropId::Unwrap => copy_to_key_prop(key_prop, key.can_unwrap().as_bytes()),
        AzihsmKeyPropId::Derive => copy_to_key_prop(key_prop, key.can_derive().as_bytes()),
    }
}

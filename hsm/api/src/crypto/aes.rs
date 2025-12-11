// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_ddi_types::DdiAesKeySize;
use mcr_ddi_types::DdiAesOp;
use mcr_ddi_types::DdiKeyProperties;
use parking_lot::RwLock;

use crate::crypto::utils::pkcs7;
use crate::crypto::Algo;
use crate::crypto::DecryptOp;
use crate::crypto::EncryptOp;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyGenOp;
use crate::crypto::KeyId;
use crate::crypto::SafeInnerAccess;
use crate::crypto::Stage;
use crate::crypto::StreamingDecryptOp;
use crate::crypto::StreamingEncDecAlgo;
use crate::crypto::StreamingEncryptOp;
use crate::ddi;
use crate::ddi::aes_xts_enc_dec;
use crate::types::AzihsmKeyClass;
use crate::types::AzihsmKeyPropId;
use crate::types::InnerKeyPropsOps;
use crate::types::KeyKind;
use crate::types::KeyPropValue;
use crate::types::KeyProps;
use crate::types::KeyPropsOps;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_AES_DECRYPT_FAILED;
use crate::AZIHSM_AES_ENCRYPT_FAILED;
use crate::AZIHSM_AES_KEYGEN_FAILED;
use crate::AZIHSM_AES_UNSUPPORTED_DATA_UNIT_LENGTH;
use crate::AZIHSM_DELETE_KEY_FAILED;
use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
use crate::AZIHSM_KEY_ALREADY_EXISTS;
use crate::AZIHSM_KEY_NOT_INITIALIZED;
use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;
use crate::AZIHSM_OPERATION_NOT_SUPPORTED;
use crate::AZIHSM_UNSUPPORTED_KEY_SIZE;

/// AES block size and IV length in bytes
pub(crate) const AES_CBC_BLOCK_IV_LENGTH: usize = 16;
pub(crate) const AES_XTS_SECTOR_NUM_LEN: usize = 16;

/// Shared function for processing AES CBC blocks in both encrypt and decrypt operations
fn process_aes_cbc_blocks(
    key_id: KeyId,
    current_iv: &mut [u8; AES_CBC_BLOCK_IV_LENGTH],
    session: &Session,
    data: &[u8],
    output: &mut [u8],
    operation: DdiAesOp,
) -> Result<usize, AzihsmError> {
    if data.is_empty() {
        return Ok(0);
    }

    // Check if output buffer is sufficient
    if output.len() < data.len() {
        Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
    }

    let error_code = match operation {
        DdiAesOp::Encrypt => AZIHSM_AES_ENCRYPT_FAILED,
        DdiAesOp::Decrypt => AZIHSM_AES_DECRYPT_FAILED,
        _ => unreachable!(),
    };

    let resp = ddi::aes_enc_dec(
        &session.partition().read().partition,
        Some(session.session_id()),
        Some(session.api_rev().into()),
        key_id.0,
        operation,
        data,
        current_iv,
    )
    .map_err(|_| error_code)?;

    let response_len = resp.data.msg.len();
    if response_len > output.len() {
        Err(error_code)?;
    }

    output[..response_len].copy_from_slice(&resp.data.msg.data()[..response_len]);
    current_iv.copy_from_slice(&resp.data.iv.data()[..AES_CBC_BLOCK_IV_LENGTH]);
    Ok(response_len)
}

impl TryFrom<&KeyProps> for DdiAesKeySize {
    type Error = AzihsmError;

    fn try_from(props: &KeyProps) -> Result<DdiAesKeySize, Self::Error> {
        let key_len_bits = props.bit_len().ok_or(AZIHSM_KEY_PROPERTY_NOT_PRESENT)?;

        match key_len_bits {
            128 => Ok(DdiAesKeySize::Aes128),
            192 => Ok(DdiAesKeySize::Aes192),
            256 => Ok(DdiAesKeySize::Aes256),
            512 => Ok(DdiAesKeySize::AesXtsBulk256),
            _ => Err(AZIHSM_UNSUPPORTED_KEY_SIZE),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AesCbcKey(Arc<RwLock<AesCbcKeyInner>>);

#[derive(Debug)]
struct AesCbcKeyInner {
    id: Option<KeyId>,
    props: KeyProps,
    _masked_key: Option<Vec<u8>>,
}

impl AesCbcKey {
    pub fn new(props: KeyProps) -> Self {
        AesCbcKey(Arc::new(RwLock::new(AesCbcKeyInner {
            id: None,
            props,
            _masked_key: None,
        })))
    }
    pub(crate) fn new_with_id(props: KeyProps, key_id: KeyId) -> Self {
        AesCbcKey(Arc::new(RwLock::new(AesCbcKeyInner {
            id: Some(key_id),
            props,
            _masked_key: None,
        })))
    }

    fn with_inner<R>(&self, f: impl FnOnce(&AesCbcKeyInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut AesCbcKeyInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    pub fn id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.id)
    }
}

impl Key for AesCbcKey {}

/// Implement Key Property Ops for AesCbcKey
impl KeyPropsOps for AesCbcKey {
    // AES is a symmetric key, supports get and set property only
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.with_inner(|inner| inner.get_property(id))
    }

    //set property
    fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| inner.set_property(id, value))
    }
}

impl InnerKeyPropsOps for AesCbcKeyInner {
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.props.get_property(id)
    }

    fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        // Validate KeyKind for AES CBC keys
        if id == AzihsmKeyPropId::Kind {
            if let KeyPropValue::KeyType(kind) = &value {
                if *kind != KeyKind::Aes {
                    Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
                }
            }
        }
        self.props.set_property(id, value)
    }
    fn apply_defaults(&mut self) -> Result<(), AzihsmError> {
        // Set operation defaults only if user hasn't specified any operations
        // Check if user has specified any operation flags
        let has_any_operation = self.props.encrypt().is_some()
            || self.props.decrypt().is_some()
            || self.props.wrap().is_some()
            || self.props.unwrap().is_some()
            || self.props.derive().is_some();

        if !has_any_operation {
            // Default to both encrypt and decrypt for AES symmetric keys
            self.props.set_encrypt(true);
            self.props.set_decrypt(true);
        }

        // Set the key kind if not already set
        if self.props.kind().is_none() {
            self.props.set_kind(KeyKind::Aes);
        }

        // Apply HSM-managed defaults for AES keys
        // AES keys are always locally generated (for now)
        self.props.apply_hsm_defaults(
            AzihsmKeyClass::Secret,
            true, // is_local: true for generated keys
        );
        Ok(())
    }
}

impl KeyDeleteOp for AesCbcKey {
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        let key_id = inner.id.ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        ddi::delete_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.0,
        )
        .map_err(|_| AZIHSM_DELETE_KEY_FAILED)?;

        // Clear the key ID to indicate it's deleted
        inner.id = None;

        Ok(())
    }
}

impl KeyGenOp for AesCbcKey {
    fn generate_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        // Check if already generated
        if inner.id.is_some() {
            Err(AZIHSM_KEY_ALREADY_EXISTS)?;
        }

        // Apply key-specific defaults before generation
        inner.apply_defaults()?;

        // Validate operation exclusivity after defaults are applied
        inner.props.validate_operation_exclusivity()?;

        // Get DDI key size and properties
        let ddi_key_size = DdiAesKeySize::try_from(&inner.props)?;
        let ddi_key_props = DdiKeyProperties::try_from(&inner.props)?;

        let resp = ddi::aes_generate_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            ddi_key_size,
            None,
            ddi_key_props,
        )
        .map_err(|_| AZIHSM_AES_KEYGEN_FAILED)?;

        inner.id = Some(KeyId(resp.data.key_id));

        Ok(())
    }

    fn generate_key_pair(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        // AES is a symmetric algorithm - it doesn't support key pairs
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

/// Streaming encryption context for AES CBC
pub struct AesCbcEncryptStreamOp<'a> {
    /// Session reference for crypto operations
    session: &'a Session,
    /// Current IV for the next block operation
    current_iv: [u8; AES_CBC_BLOCK_IV_LENGTH],
    /// Buffer for partial blocks during streaming
    buffer: Vec<u8>,
    /// Key ID being used for this streaming session
    key_id: KeyId,
    /// Whether PKCS#7 padding is enabled
    pub(crate) pkcs7_pad: bool,
}

impl<'a> AesCbcEncryptStreamOp<'a> {
    fn new(
        session: &'a Session,
        iv: [u8; AES_CBC_BLOCK_IV_LENGTH],
        key_id: KeyId,
        pkcs7_pad: bool,
    ) -> Self {
        Self {
            session,
            current_iv: iv,
            buffer: Vec::with_capacity(AES_CBC_BLOCK_IV_LENGTH), // Pre-allocate one block
            key_id,
            pkcs7_pad,
        }
    }

    fn process_complete_blocks(
        key_id: KeyId,
        current_iv: &mut [u8; AES_CBC_BLOCK_IV_LENGTH],
        session: &Session,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        process_aes_cbc_blocks(key_id, current_iv, session, data, output, DdiAesOp::Encrypt)
    }
}

impl<'a> StreamingEncryptOp for AesCbcEncryptStreamOp<'a> {
    /// Calculate the required output buffer size
    ///
    /// # Arguments
    /// * `input_len` - Additional input data length (0 for finalize)
    /// * `stage` - Stage of the operation (Update or Finalize)
    fn required_output_len(&self, input_len: usize, stage: Stage) -> usize {
        let total_data = self.buffer.len() + input_len;

        match stage {
            Stage::Update => {
                // Only complete blocks are output during update
                let num_complete_blocks = total_data / AES_CBC_BLOCK_IV_LENGTH;
                num_complete_blocks * AES_CBC_BLOCK_IV_LENGTH
            }
            Stage::Finalize => {
                if self.pkcs7_pad {
                    // With PKCS#7 padding, round up to next block boundary
                    let blocks_needed = (total_data / AES_CBC_BLOCK_IV_LENGTH) + 1;
                    blocks_needed * AES_CBC_BLOCK_IV_LENGTH
                } else {
                    // Without padding: no output in finalize.
                    0
                }
            }
        }
    }

    fn update(&mut self, pt: &[u8], ct: &mut [u8]) -> Result<usize, AzihsmError> {
        // Calculate required output size BEFORE modifying buffer
        let bytes_to_process = self.required_output_len(pt.len(), Stage::Update);

        // Check if output buffer is sufficient
        if ct.len() < bytes_to_process {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Add new data to buffer
        self.buffer.extend_from_slice(pt);

        if bytes_to_process == 0 {
            return Ok(0); // No complete blocks to process
        }

        let bytes_written = Self::process_complete_blocks(
            self.key_id,
            &mut self.current_iv,
            self.session,
            &self.buffer[..bytes_to_process],
            ct,
        )?;

        // Keep remaining partial block in buffer
        self.buffer.drain(..bytes_to_process);

        Ok(bytes_written)
    }

    fn finalize(mut self, ct: &mut [u8]) -> Result<usize, AzihsmError> {
        let mut final_data = self.buffer;

        if self.pkcs7_pad {
            // Apply PKCS#7 padding to remaining data
            let mut padded_data = Vec::new();
            pkcs7::apply(&final_data, &mut padded_data, AES_CBC_BLOCK_IV_LENGTH);
            final_data = padded_data;
        } else if !final_data.is_empty() {
            // In non-padded mode, we should not have partial blocks at finalization
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        if final_data.is_empty() {
            return Ok(0);
        }

        // Validate output buffer size
        if ct.len() < final_data.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        Self::process_complete_blocks(
            self.key_id,
            &mut self.current_iv,
            self.session,
            &final_data,
            ct,
        )
    }
}

/// Streaming decryption context for AES CBC
pub struct AesCbcDecryptStreamOp<'a> {
    /// Session reference for crypto operations
    session: &'a Session,
    /// Current IV for the next block operation
    current_iv: [u8; AES_CBC_BLOCK_IV_LENGTH],
    /// Buffer for partial blocks during streaming
    buffer: Vec<u8>,
    /// Key ID being used for this streaming session
    key_id: KeyId,
    /// Whether PKCS#7 padding is enabled
    pub(crate) pkcs7_pad: bool,
}

impl<'a> AesCbcDecryptStreamOp<'a> {
    fn new(
        session: &'a Session,
        iv: [u8; AES_CBC_BLOCK_IV_LENGTH],
        key_id: KeyId,
        pkcs7_pad: bool,
    ) -> Self {
        Self {
            session,
            current_iv: iv,
            buffer: Vec::with_capacity(AES_CBC_BLOCK_IV_LENGTH), // Pre-allocate one block
            key_id,
            pkcs7_pad,
        }
    }

    /// Process complete blocks for streaming operations
    fn process_complete_blocks(
        key_id: KeyId,
        current_iv: &mut [u8; AES_CBC_BLOCK_IV_LENGTH],
        session: &Session,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        process_aes_cbc_blocks(key_id, current_iv, session, data, output, DdiAesOp::Decrypt)
    }
}

impl<'a> StreamingDecryptOp for AesCbcDecryptStreamOp<'a> {
    fn required_output_len(&self, input_len: usize, stage: Stage) -> usize {
        let total_data = self.buffer.len() + input_len;

        match stage {
            Stage::Update => {
                // For decryption, we need to keep at least one block for final processing (padding removal)
                let available_blocks = total_data / AES_CBC_BLOCK_IV_LENGTH;
                let blocks_to_process = if self.pkcs7_pad && available_blocks > 0 {
                    available_blocks - 1 // Keep last block for finalize
                } else {
                    available_blocks
                };
                blocks_to_process * AES_CBC_BLOCK_IV_LENGTH
            }
            Stage::Finalize => {
                if self.pkcs7_pad {
                    // Upper bound - actual may be smaller after padding removal
                    AES_CBC_BLOCK_IV_LENGTH
                } else {
                    // Unpadded: no output in finalize (errors if buffer non-empty)
                    0
                }
            }
        }
    }

    fn update(&mut self, ct: &[u8], pt: &mut [u8]) -> Result<usize, AzihsmError> {
        // Calculate required output size BEFORE modifying buffer
        let bytes_to_process = self.required_output_len(ct.len(), Stage::Update);

        // Check if output buffer is sufficient
        if pt.len() < bytes_to_process {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Add new data to buffer
        self.buffer.extend_from_slice(ct);

        if bytes_to_process == 0 {
            return Ok(0); // No blocks to process yet
        }

        let bytes_written = Self::process_complete_blocks(
            self.key_id,
            &mut self.current_iv,
            self.session,
            &self.buffer[..bytes_to_process],
            pt,
        )?;

        // Remove processed blocks from buffer
        self.buffer.drain(..bytes_to_process);

        Ok(bytes_written)
    }

    fn finalize(mut self, pt: &mut [u8]) -> Result<usize, AzihsmError> {
        if self.buffer.is_empty() {
            return Ok(0);
        }

        // For decryption with PKCS7 padding, the buffer should contain exactly one block
        if self.pkcs7_pad && self.buffer.len() != AES_CBC_BLOCK_IV_LENGTH {
            Err(AZIHSM_AES_DECRYPT_FAILED)?;
        }

        let mut temp_buffer = vec![0u8; self.buffer.len()];
        let bytes_written = Self::process_complete_blocks(
            self.key_id,
            &mut self.current_iv,
            self.session,
            &self.buffer,
            &mut temp_buffer,
        )?;

        if bytes_written != self.buffer.len() {
            Err(AZIHSM_AES_DECRYPT_FAILED)?;
        }

        self.buffer.clear();

        // Apply padding removal if needed
        if self.pkcs7_pad {
            pkcs7::remove(
                &mut temp_buffer,
                AES_CBC_BLOCK_IV_LENGTH,
                AZIHSM_AES_DECRYPT_FAILED,
            )?;
        }

        // After padding removal, temp_buffer.len() is the actual plaintext length
        let final_length = temp_buffer.len();

        if final_length > pt.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        pt[..final_length].copy_from_slice(&temp_buffer);
        Ok(final_length)
    }
}

pub struct AesCbcAlgo {
    pub iv: [u8; AES_CBC_BLOCK_IV_LENGTH],
    pub pkcs7_pad: bool,
}

impl AesCbcAlgo {
    /// Create a new AES CBC algorithm instance
    pub fn new(iv: [u8; AES_CBC_BLOCK_IV_LENGTH], pkcs7_pad: bool) -> Self {
        Self { iv, pkcs7_pad }
    }

    /// Calculate the output length for encryption with optional padding
    fn calculate_encrypt_len(&self, input_len: usize) -> usize {
        if self.pkcs7_pad {
            // With PKCS#7 padding, we always add at least 1 byte of padding
            // Round up to next block boundary
            let blocks = (input_len / AES_CBC_BLOCK_IV_LENGTH) + 1;
            blocks * AES_CBC_BLOCK_IV_LENGTH
        } else {
            // No padding - input must already be block-aligned
            input_len
        }
    }
}

impl Algo for AesCbcAlgo {}

impl<'a> StreamingEncDecAlgo<'a, AesCbcKey> for AesCbcAlgo {
    type EncryptStream = AesCbcEncryptStreamOp<'a>;
    type DecryptStream = AesCbcDecryptStreamOp<'a>;

    fn encrypt_init(
        &self,
        session: &'a Session,
        key: &AesCbcKey,
    ) -> Result<Self::EncryptStream, AzihsmError> {
        Ok(AesCbcEncryptStreamOp::new(
            session,
            self.iv,
            key.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?,
            self.pkcs7_pad,
        ))
    }

    fn decrypt_init(
        &self,
        session: &'a Session,
        key: &AesCbcKey,
    ) -> Result<Self::DecryptStream, AzihsmError> {
        Ok(AesCbcDecryptStreamOp::new(
            session,
            self.iv,
            key.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?,
            self.pkcs7_pad,
        ))
    }
}

impl EncryptOp<AesCbcKey> for AesCbcAlgo {
    fn ciphertext_len(&self, pt_len: usize) -> usize {
        self.calculate_encrypt_len(pt_len)
    }

    fn encrypt(
        &mut self,
        session: &Session,
        key: &AesCbcKey,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        let key_id = key.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?.0;

        let mut input_data = Vec::new();

        if self.pkcs7_pad {
            // Apply PKCS#7 padding
            pkcs7::apply(pt, &mut input_data, AES_CBC_BLOCK_IV_LENGTH);
        } else {
            // No padding - input must be block-aligned
            if !pt.len().is_multiple_of(AES_CBC_BLOCK_IV_LENGTH) {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }

            input_data.extend_from_slice(pt);
        }

        if ct.len() < input_data.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        let resp = ddi::aes_enc_dec(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id,
            DdiAesOp::Encrypt,
            &input_data,
            &self.iv,
        )
        .map_err(|_| AZIHSM_AES_ENCRYPT_FAILED)?;

        let response_len = resp.data.msg.len();
        if response_len > ct.len() {
            Err(AZIHSM_AES_ENCRYPT_FAILED)?;
        }

        ct[..response_len].copy_from_slice(&resp.data.msg.data()[..response_len]);
        self.iv
            .copy_from_slice(&resp.data.iv.data()[..AES_CBC_BLOCK_IV_LENGTH]);

        Ok(response_len)
    }
}

impl DecryptOp<AesCbcKey> for AesCbcAlgo {
    fn plaintext_len(&self, ct_len: usize) -> usize {
        if self.pkcs7_pad {
            // With padding, plaintext will be smaller than ciphertext
            // Return the ciphertext length as upper bound
            ct_len
        } else {
            // Without padding, plaintext length equals ciphertext length
            ct_len
        }
    }

    fn decrypt(
        &mut self,
        session: &Session,
        key: &AesCbcKey,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        let key_id = key.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?.0;

        // Ciphertext must be block-aligned
        if !ct.len().is_multiple_of(AES_CBC_BLOCK_IV_LENGTH) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        // Buffer validation: for unpadded mode, pt must be at least ct length
        // For padded mode, we'll check after padding removal since pt can be smaller
        if !self.pkcs7_pad && pt.len() < ct.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        let resp = ddi::aes_enc_dec(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id,
            DdiAesOp::Decrypt,
            ct,
            &self.iv,
        )
        .map_err(|_| AZIHSM_AES_DECRYPT_FAILED)?;

        let mut decrypted_data = resp.data.msg.data()[..resp.data.msg.len()].to_vec();

        if self.pkcs7_pad {
            // Remove PKCS#7 padding
            pkcs7::remove(
                &mut decrypted_data,
                AES_CBC_BLOCK_IV_LENGTH,
                AZIHSM_AES_DECRYPT_FAILED,
            )?;
        }

        // Now check if the final decrypted data fits in the provided buffer
        if decrypted_data.len() > pt.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        pt[..decrypted_data.len()].copy_from_slice(&decrypted_data);
        self.iv
            .copy_from_slice(&resp.data.iv.data()[..AES_CBC_BLOCK_IV_LENGTH]);

        Ok(decrypted_data.len())
    }
}

#[derive(Clone, Debug)]
pub struct AesXtsKey(Arc<RwLock<AesXtsKeyInner>>);

#[derive(Debug)]
struct AesXtsKeyInner {
    id: Option<(KeyId, KeyId)>,
    props: KeyProps,
    _masked_key: Option<Vec<u8>>,
}

impl AesXtsKey {
    pub fn new(props: KeyProps) -> Self {
        AesXtsKey(Arc::new(RwLock::new(AesXtsKeyInner {
            id: None,
            props,
            _masked_key: None,
        })))
    }

    #[allow(unused)]
    fn with_inner<R>(&self, f: impl FnOnce(&AesXtsKeyInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut AesXtsKeyInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    #[allow(unused)]
    pub fn id(&self) -> Option<(KeyId, KeyId)> {
        self.with_inner(|inner| inner.id)
    }
}

impl Key for AesXtsKey {}

/// Implement Key Property Ops for AesXtsKey
impl KeyPropsOps for AesXtsKey {
    // AES XTS is a symmetric key, supports get and set property only
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.with_inner(|inner| inner.get_property(id))
    }

    //set property
    fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| inner.set_property(id, value))
    }
}

impl InnerKeyPropsOps for AesXtsKeyInner {
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.props.get_property(id)
    }

    fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        // Validate KeyKind for AES XTS keys
        if id == AzihsmKeyPropId::Kind {
            if let KeyPropValue::KeyType(kind) = &value {
                if *kind != KeyKind::AesXts {
                    Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
                }
            }
        }
        self.props.set_property(id, value)
    }
    fn apply_defaults(&mut self) -> Result<(), AzihsmError> {
        // Set operation defaults only if user hasn't specified any operations
        // Check if user has specified any operation flags
        let has_any_operation = self.props.encrypt().is_some()
            || self.props.decrypt().is_some()
            || self.props.wrap().is_some()
            || self.props.unwrap().is_some()
            || self.props.derive().is_some();

        if !has_any_operation {
            // Default to both encrypt and decrypt for AES XTS symmetric keys
            self.props.set_encrypt(true);
            self.props.set_decrypt(true);
        }

        // Set the key kind if not already set
        if self.props.kind().is_none() {
            self.props.set_kind(KeyKind::AesXts);
        }

        // Apply HSM-managed defaults for AES XTS keys
        // AES XTS keys are always locally generated (for now)
        self.props.apply_hsm_defaults(
            AzihsmKeyClass::Secret,
            true, // is_local: true for generated keys
        );
        Ok(())
    }
}

impl KeyDeleteOp for AesXtsKey {
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        let key_id = inner.id.ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        ddi::delete_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.0 .0,
        )
        .map_err(|_| AZIHSM_DELETE_KEY_FAILED)?;

        ddi::delete_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.1 .0,
        )
        .map_err(|_| AZIHSM_DELETE_KEY_FAILED)?;

        // Clear the key ID to indicate it's deleted
        inner.id = None;

        Ok(())
    }
}

impl KeyGenOp for AesXtsKey {
    fn generate_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        // Check if already generated
        if inner.id.is_some() {
            Err(AZIHSM_KEY_ALREADY_EXISTS)?;
        }

        // Apply key-specific defaults before generation
        inner.apply_defaults()?;

        // Validate operation exclusivity after defaults are applied
        inner.props.validate_operation_exclusivity()?;

        // Get DDI key size and properties
        let ddi_key_size = DdiAesKeySize::try_from(&inner.props)?;
        if ddi_key_size != DdiAesKeySize::AesXtsBulk256 {
            Err(AZIHSM_UNSUPPORTED_KEY_SIZE)?;
        }
        let ddi_key_props = DdiKeyProperties::try_from(&inner.props)?;

        // Generate key 1
        let resp = ddi::aes_generate_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            ddi_key_size,
            None,
            ddi_key_props,
        )
        .map_err(|_| AZIHSM_AES_KEYGEN_FAILED)?;

        // Generate key 2
        let resp2 = ddi::aes_generate_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            ddi_key_size,
            None,
            ddi_key_props,
        )
        .map_err(|_| AZIHSM_AES_KEYGEN_FAILED)?;

        inner.id = Some((KeyId(resp.data.key_id), KeyId(resp2.data.key_id)));

        Ok(())
    }
}

pub struct AesXtsAlgo {
    pub sector_num: [u8; AES_XTS_SECTOR_NUM_LEN],
    pub data_unit_len: Option<u32>,
}

impl AesXtsAlgo {
    fn xts_operation(
        &self,
        session: &Session,
        key: &AesXtsKey,
        input: &[u8],
        output: &mut [u8],
        operation: DdiAesOp,
    ) -> Result<usize, AzihsmError> {
        if output.len() < input.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?
        }

        let key_ids = key.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        // Validate data unit length
        let data_unit_len = self.data_unit_len.unwrap_or(input.len() as u32);
        if data_unit_len as usize != input.len() && !matches!(data_unit_len, 512 | 4096 | 8192) {
            Err(AZIHSM_AES_UNSUPPORTED_DATA_UNIT_LENGTH)?;
        }

        let error_code = match operation {
            DdiAesOp::Encrypt => AZIHSM_AES_ENCRYPT_FAILED,
            DdiAesOp::Decrypt => AZIHSM_AES_DECRYPT_FAILED,
            _ => unreachable!(),
        };

        let resp = aes_xts_enc_dec(
            &session.partition().read().partition,
            session.session_id(),
            0, // [TODO]
            key_ids.1 .0,
            key_ids.0 .0,
            operation,
            input,
            self.sector_num,
            data_unit_len,
        )
        .map_err(|_| error_code)?;

        if resp.data.len() > output.len() {
            Err(error_code)?
        }

        output[..resp.data.len()].copy_from_slice(&resp.data);

        Ok(resp.data.len())
    }
}

impl Algo for AesXtsAlgo {}

impl EncryptOp<AesXtsKey> for AesXtsAlgo {
    fn ciphertext_len(&self, pt_len: usize) -> usize {
        pt_len
    }

    fn encrypt(
        &mut self,
        session: &Session,
        key: &AesXtsKey,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        self.xts_operation(session, key, pt, ct, DdiAesOp::Encrypt)
    }
}

impl DecryptOp<AesXtsKey> for AesXtsAlgo {
    fn plaintext_len(&self, ct_len: usize) -> usize {
        ct_len
    }

    fn decrypt(
        &mut self,
        session: &Session,
        key: &AesXtsKey,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        self.xts_operation(session, key, ct, pt, DdiAesOp::Decrypt)
    }
}

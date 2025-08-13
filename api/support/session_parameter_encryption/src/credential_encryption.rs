// Copyright (C) Microsoft Corporation. All rights reserved.

use crypto::aes::*;
use crypto::ecc::*;
use crypto::sha::*;
use crypto::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;

#[derive(Debug)]
pub struct DeviceCredentialEncryptionKey {
    ecc_pub_key: EccPublicKey,
    nonce: [u8; 32],
}

impl DeviceCredentialEncryptionKey {
    pub fn new(pub_key_der: &DdiDerPublicKey, nonce: [u8; 32]) -> Result<Self, CryptoError> {
        let ecc_pub_key = EccPublicKey::from_der(
            &pub_key_der.der.data()[..pub_key_der.der.len()],
            Some(CryptoKeyKind::Ecc384Public),
        )?;
        Ok(Self { ecc_pub_key, nonce })
    }

    pub fn generate_ephemeral_encryption_key(
        &self,
    ) -> Result<(CredentialEncryptionKey, DdiDerPublicKey), CryptoError> {
        let (client_priv_key, _pub_key) = generate_ecc(CryptoEccCurve::P384)?;
        let client_priv_key_der = client_priv_key.to_der()?;
        self.create_credential_key_from_der(&client_priv_key_der)
    }

    pub fn create_credential_key_from_der(
        &self,
        priv_key_der: &[u8],
    ) -> Result<(CredentialEncryptionKey, DdiDerPublicKey), CryptoError> {
        let ecc_priv_key =
            EccPrivateKey::from_der(priv_key_der, Some(CryptoKeyKind::Ecc384Private))?;

        let credential_key =
            CredentialEncryptionKey::create(&self.ecc_pub_key, &ecc_priv_key, &self.nonce)?;

        let mut session_pub_key_der = [0u8; 768];
        let session_pub_key_vec = ecc_priv_key.extract_pub_key_der()?;
        session_pub_key_der[..session_pub_key_vec.len()].copy_from_slice(&session_pub_key_vec);
        let ddi_pub_key = DdiDerPublicKey {
            der: MborByteArray::new(session_pub_key_der, session_pub_key_vec.len())
                .map_err(|_| CryptoError::EccFromDerError)?,
            key_kind: DdiKeyType::Ecc384Public,
        };

        Ok((credential_key, ddi_pub_key))
    }
}

pub struct CredentialEncryptionKey {
    aes_key: [u8; 32],
    hmac_key: [u8; 48],
}

impl CredentialEncryptionKey {
    fn create(
        device_credential_key: &EccPublicKey,
        client_priv_key: &EccPrivateKey,
        nonce: &[u8],
    ) -> Result<Self, CryptoError> {
        // ECDH exchange
        let ecdh_bytes = client_priv_key.derive(device_credential_key)?;

        // HKDF
        let derived_bytes = hkdf_sha_384_derive(&ecdh_bytes, Some(nonce), 80)?;
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&derived_bytes[..32]);
        let mut hmac_key = [0u8; 48];
        hmac_key.copy_from_slice(&derived_bytes[32..]);

        Ok(CredentialEncryptionKey { aes_key, hmac_key })
    }

    pub fn encrypt(
        &self,
        id: [u8; 16],
        pin: [u8; 16],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedCredential, CryptoError> {
        let mut encrypted_id = [0; 16];
        let mut encrypted_pin = [0; 16];
        let mut iv = [0; 16];

        crypto::rand::rand_bytes(&mut iv)?;

        let aes_key = AesKey::from_bytes(&self.aes_key)?;

        let encrypted_id_vec = aes_key.encrypt(&id, AesAlgo::Cbc, Some(&iv))?.cipher_text;
        encrypted_id.copy_from_slice(&encrypted_id_vec);

        let encrypted_pin_vec = aes_key.encrypt(&pin, AesAlgo::Cbc, Some(&iv))?.cipher_text;
        encrypted_pin.copy_from_slice(&encrypted_pin_vec);

        let mut id_pin_iv_nonce = [0; 80];
        id_pin_iv_nonce[..16].copy_from_slice(&encrypted_id);
        id_pin_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
        id_pin_iv_nonce[32..48].copy_from_slice(&iv);
        id_pin_iv_nonce[48..].copy_from_slice(&nonce);

        let tag = hmac_sha_384(&self.hmac_key, &id_pin_iv_nonce)?;

        Ok(DdiEncryptedCredential {
            encrypted_id: MborByteArray::new(encrypted_id, 16)
                .map_err(|_| CryptoError::ByteArrayCreationError)?,
            encrypted_pin: MborByteArray::new(encrypted_pin, 16)
                .map_err(|_| CryptoError::ByteArrayCreationError)?,
            iv: MborByteArray::new(iv, 16).map_err(|_| CryptoError::ByteArrayCreationError)?,
            nonce,
            tag,
        })
    }

    pub fn encrypt_pin(
        &self,
        pin: [u8; 16],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedPin, CryptoError> {
        let mut encrypted_pin = [0; 16];
        let mut iv = [0; 16];

        crypto::rand::rand_bytes(&mut iv)?;

        let aes_key = AesKey::from_bytes(&self.aes_key)?;

        let encrypted_pin_vec = aes_key.encrypt(&pin, AesAlgo::Cbc, Some(&iv))?.cipher_text;
        encrypted_pin.copy_from_slice(&encrypted_pin_vec);

        let mut id_pin_iv_nonce = [0; 64];
        id_pin_iv_nonce[..16].copy_from_slice(&encrypted_pin);
        id_pin_iv_nonce[16..32].copy_from_slice(&iv);
        id_pin_iv_nonce[32..].copy_from_slice(&nonce);

        let tag = hmac_sha_384(&self.hmac_key, &id_pin_iv_nonce)?;

        Ok(DdiEncryptedPin {
            encrypted_pin: MborByteArray::new(encrypted_pin, 16)
                .map_err(|_| CryptoError::ByteArrayCreationError)?,
            iv: MborByteArray::new(iv, 16).map_err(|_| CryptoError::ByteArrayCreationError)?,
            nonce,
            tag,
        })
    }
}

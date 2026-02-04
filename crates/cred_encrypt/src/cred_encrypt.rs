// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[derive(Debug)]
pub struct DeviceCredKey {
    ecc_pub_key: EccPublicKey,
    nonce: [u8; 32],
}

impl DeviceCredKey {
    pub fn new(pub_key_der: &DdiDerPublicKey, nonce: [u8; 32]) -> Result<Self, CredEncErr> {
        let ecc_pub_key =
            EccPublicKey::from_bytes(&pub_key_der.der.data()[..pub_key_der.der.len()])
                .map_err(|_| CredEncErr::EccKeyImportError)?;
        Ok(Self { ecc_pub_key, nonce })
    }

    pub fn generate_ephemeral_encryption_key(
        &self,
    ) -> Result<(CredentialEncryptionKey, DdiDerPublicKey), CredEncErr> {
        let client_priv_key =
            EccPrivateKey::from_curve(EccCurve::P384).map_err(|_| CredEncErr::EccKeyGenError)?;
        let client_priv_key_der = client_priv_key
            .to_vec()
            .map_err(|_| CredEncErr::EccKeyExportError)?;
        self.create_credential_key_from_der(&client_priv_key_der)
    }

    pub fn create_credential_key_from_der(
        &self,
        priv_key_der: &[u8],
    ) -> Result<(CredentialEncryptionKey, DdiDerPublicKey), CredEncErr> {
        let ecc_priv_key =
            EccPrivateKey::from_bytes(priv_key_der).map_err(|_| CredEncErr::EccKeyImportError)?;

        let credential_key =
            CredentialEncryptionKey::create(&self.ecc_pub_key, &ecc_priv_key, &self.nonce)?;

        let session_pub_key = ecc_priv_key
            .public_key()
            .map_err(|_| CredEncErr::EccKeyExportError)?;
        let session_pub_key_vec = session_pub_key
            .to_vec()
            .map_err(|_| CredEncErr::EccKeyExportError)?;

        let ddi_pub_key = DdiDerPublicKey {
            der: MborByteArray::from_slice(&session_pub_key_vec)
                .map_err(|_| CredEncErr::SliceTooBig)?,
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
    ) -> Result<Self, CredEncErr> {
        // ECDH exchange
        let ecdh = EcdhAlgo::new(device_credential_key)
            .derive(client_priv_key, 48)
            .map_err(|_| CredEncErr::EcdhDeriveError)?;

        // HKDF
        let hash = HashAlgo::sha384();
        let hkdf = HkdfAlgo::new(HkdfMode::ExtractAndExpand, &hash, None, Some(nonce));
        let output = hkdf
            .derive(&ecdh, 80)
            .map_err(|_| CredEncErr::HkdfDeriveError)?;
        let derived_bytes = output.to_vec().map_err(|_| CredEncErr::SecretExportError)?;

        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&derived_bytes[..32]);
        let mut hmac_key = [0u8; 48];
        hmac_key.copy_from_slice(&derived_bytes[32..]);

        Ok(CredentialEncryptionKey { aes_key, hmac_key })
    }

    fn aes_cbc_encrypt(
        &self,
        algo: &mut AesCbcAlgo,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CredEncErr> {
        let key = AesKey::from_bytes(&self.aes_key).map_err(|_| CredEncErr::AesKeyImportError)?;
        let ciphertext = Encrypter::encrypt_vec(algo, &key, plaintext)
            .map_err(|_| CredEncErr::AesCbcEncryptError)?;
        Ok(ciphertext)
    }

    fn hmac_sha_384(&self, data: &[u8]) -> Result<[u8; 48], CredEncErr> {
        let mut tag = [0u8; 48];
        let hash = HashAlgo::sha384();
        let mut hmac = HmacAlgo::new(hash);
        let key =
            HmacKey::from_bytes(&self.hmac_key).map_err(|_| CredEncErr::HmacKeyImportError)?;
        Signer::sign(&mut hmac, &key, data, Some(&mut tag))
            .map_err(|_| CredEncErr::HmacSignError)?;
        Ok(tag)
    }

    pub fn encrypt_establish_credential(
        &self,
        id: [u8; 16],
        pin: [u8; 16],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedEstablishCredential, CredEncErr> {
        let mut iv = [0; 16];
        Rng::rand_bytes(&mut iv).map_err(|_| CredEncErr::RngError)?;

        let mut algo = AesCbcAlgo::with_no_padding(&iv);
        let encrypted_id = self.aes_cbc_encrypt(&mut algo, &id)?;
        let encrypted_pin = self.aes_cbc_encrypt(&mut algo, &pin)?;

        let mut id_pin_iv_nonce = [0; 80];
        id_pin_iv_nonce[..16].copy_from_slice(&encrypted_id);
        id_pin_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
        id_pin_iv_nonce[32..48].copy_from_slice(&iv);
        id_pin_iv_nonce[48..].copy_from_slice(&nonce);

        let tag = self.hmac_sha_384(&id_pin_iv_nonce)?;

        Ok(DdiEncryptedEstablishCredential {
            encrypted_id: MborByteArray::from_slice(&encrypted_id)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            encrypted_pin: MborByteArray::from_slice(&encrypted_pin)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            iv: MborByteArray::from_slice(&iv).map_err(|_| CredEncErr::SliceTooBig)?,
            nonce,
            tag,
        })
    }

    pub fn encrypt_session_credential(
        &self,
        id: [u8; 16],
        pin: [u8; 16],
        seed: [u8; 48],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedSessionCredential, CredEncErr> {
        let mut iv = [0; 16];
        Rng::rand_bytes(&mut iv).map_err(|_| CredEncErr::RngError)?;

        let mut algo = AesCbcAlgo::with_no_padding(&iv);
        let encrypted_id = self.aes_cbc_encrypt(&mut algo, &id)?;
        let encrypted_pin = self.aes_cbc_encrypt(&mut algo, &pin)?;
        let encrypted_seed = self.aes_cbc_encrypt(&mut algo, &seed)?;

        let mut id_pin_seed_iv_nonce = [0; 128];
        id_pin_seed_iv_nonce[..16].copy_from_slice(&encrypted_id);
        id_pin_seed_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
        id_pin_seed_iv_nonce[32..80].copy_from_slice(&encrypted_seed);
        id_pin_seed_iv_nonce[80..96].copy_from_slice(&iv);
        id_pin_seed_iv_nonce[96..].copy_from_slice(&nonce);

        let tag = self.hmac_sha_384(&id_pin_seed_iv_nonce)?;

        Ok(DdiEncryptedSessionCredential {
            encrypted_id: MborByteArray::from_slice(&encrypted_id)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            encrypted_pin: MborByteArray::from_slice(&encrypted_pin)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            encrypted_seed: MborByteArray::from_slice(&encrypted_seed)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            iv: MborByteArray::from_slice(&iv).map_err(|_| CredEncErr::SliceTooBig)?,
            nonce,
            tag,
        })
    }

    pub fn encrypt_pin(
        &self,
        pin: [u8; 16],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedPin, CredEncErr> {
        let mut iv = [0; 16];
        Rng::rand_bytes(&mut iv).map_err(|_| CredEncErr::RngError)?;

        let mut algo = AesCbcAlgo::with_no_padding(&iv);
        let encrypted_pin = self.aes_cbc_encrypt(&mut algo, &pin)?;

        let mut id_pin_iv_nonce = [0; 64];
        id_pin_iv_nonce[..16].copy_from_slice(&encrypted_pin);
        id_pin_iv_nonce[16..32].copy_from_slice(&iv);
        id_pin_iv_nonce[32..].copy_from_slice(&nonce);

        let tag = self.hmac_sha_384(&id_pin_iv_nonce)?;

        Ok(DdiEncryptedPin {
            encrypted_pin: MborByteArray::from_slice(&encrypted_pin)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            iv: MborByteArray::from_slice(&iv).map_err(|_| CredEncErr::SliceTooBig)?,
            nonce,
            tag,
        })
    }
}

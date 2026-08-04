// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

const BK3_TRANSPORT_INFO: &[u8] = b"BK3_TRANSPORT_ENC";

const BK3_KPIN_DOMAIN: u8 = 0x02;

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

    pub fn generate_ephemeral_bk3_key(
        &self,
    ) -> Result<(Bk3EncryptionKey, DdiDerPublicKey), CredEncErr> {
        let client_priv_key =
            EccPrivateKey::from_curve(EccCurve::P384).map_err(|_| CredEncErr::EccKeyGenError)?;
        let client_priv_key_der = client_priv_key
            .to_vec()
            .map_err(|_| CredEncErr::EccKeyExportError)?;
        self.create_bk3_key_from_der(&client_priv_key_der)
    }

    pub fn create_bk3_key_from_der(
        &self,
        priv_key_der: &[u8],
    ) -> Result<(Bk3EncryptionKey, DdiDerPublicKey), CredEncErr> {
        let ecc_priv_key =
            EccPrivateKey::from_bytes(priv_key_der).map_err(|_| CredEncErr::EccKeyImportError)?;

        let bk3_key = Bk3EncryptionKey::create(&self.ecc_pub_key, &ecc_priv_key)?;

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

        Ok((bk3_key, ddi_pub_key))
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
        let iv = Rng::rand_vec(16).map_err(|_| CredEncErr::RngError)?;

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
        let iv = Rng::rand_vec(16).map_err(|_| CredEncErr::RngError)?;

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
        let iv = Rng::rand_vec(16).map_err(|_| CredEncErr::RngError)?;

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

pub struct Bk3EncryptionKey {
    secret: [u8; 48],
}

impl Bk3EncryptionKey {
    fn create(
        device_credential_key: &EccPublicKey,
        client_priv_key: &EccPrivateKey,
    ) -> Result<Self, CredEncErr> {
        let ecdh = EcdhAlgo::new(device_credential_key)
            .derive(client_priv_key, 48)
            .map_err(|_| CredEncErr::EcdhDeriveError)?;
        let secret_bytes = ecdh.to_vec().map_err(|_| CredEncErr::SecretExportError)?;
        if secret_bytes.len() != 48 {
            return Err(CredEncErr::EcdhDeriveError);
        }
        let mut secret = [0u8; 48];
        secret.copy_from_slice(&secret_bytes);
        Ok(Self { secret })
    }

    fn hkdf_sha384(&self, info: &[u8], out_len: usize) -> Result<Vec<u8>, CredEncErr> {
        let ikm =
            GenericSecretKey::from_bytes(&self.secret).map_err(|_| CredEncErr::SecretExportError)?;
        let hash = HashAlgo::sha384();
        let hkdf = HkdfAlgo::new(HkdfMode::ExtractAndExpand, &hash, None, Some(info));
        let output = hkdf
            .derive(&ikm, out_len)
            .map_err(|_| CredEncErr::HkdfDeriveError)?;
        output.to_vec().map_err(|_| CredEncErr::SecretExportError)
    }

    fn derive_transport_keys(&self) -> Result<([u8; 32], [u8; 48]), CredEncErr> {
        let derived = self.hkdf_sha384(BK3_TRANSPORT_INFO, 80)?;
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&derived[..32]);
        let mut hmac_key = [0u8; 48];
        hmac_key.copy_from_slice(&derived[32..80]);
        Ok((aes_key, hmac_key))
    }

    fn derive_k_pin(&self, id: [u8; 16], pin: [u8; 16]) -> Result<[u8; 48], CredEncErr> {
        let mut info = [0u8; 33];
        info[..16].copy_from_slice(&pin);
        info[16..32].copy_from_slice(&id);
        info[32] = BK3_KPIN_DOMAIN;

        let result = self.hkdf_sha384(&info, 48);

        info.fill(0);

        let derived = result?;
        let mut k_pin = [0u8; 48];
        k_pin.copy_from_slice(&derived[..48]);
        Ok(k_pin)
    }

    fn aes_cbc_encrypt(
        aes_key: &[u8; 32],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CredEncErr> {
        let mut algo = AesCbcAlgo::with_no_padding(iv);
        let key = AesKey::from_bytes(aes_key).map_err(|_| CredEncErr::AesKeyImportError)?;
        Encrypter::encrypt_vec(&mut algo, &key, plaintext)
            .map_err(|_| CredEncErr::AesCbcEncryptError)
    }

    fn hmac_sha_384(hmac_key: &[u8], data: &[u8]) -> Result<[u8; 48], CredEncErr> {
        let mut tag = [0u8; 48];
        let hash = HashAlgo::sha384();
        let mut hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(hmac_key).map_err(|_| CredEncErr::HmacKeyImportError)?;
        Signer::sign(&mut hmac, &key, data, Some(&mut tag)).map_err(|_| CredEncErr::HmacSignError)?;
        Ok(tag)
    }

    pub fn encrypt_bk3(
        &self,
        bk3: &[u8; 48],
        id: [u8; 16],
        pin: [u8; 16],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedBk3, CredEncErr> {
        let iv = Rng::rand_vec(16).map_err(|_| CredEncErr::RngError)?;

        let (aes_key, transport_hmac_key) = self.derive_transport_keys()?;
        let k_pin = self.derive_k_pin(id, pin)?;

        let ct_bk3 = Self::aes_cbc_encrypt(&aes_key, &iv, bk3)?;

        let mut message = [0u8; 96];
        message[..16].copy_from_slice(&iv);
        message[16..64].copy_from_slice(&ct_bk3);
        message[64..96].copy_from_slice(&nonce);

        let tag_transport = Self::hmac_sha_384(&transport_hmac_key, &message)?;
        let tag_pin = Self::hmac_sha_384(&k_pin, &message)?;

        Ok(DdiEncryptedBk3 {
            encrypted_bk3: MborByteArray::from_slice(&ct_bk3)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            iv: MborByteArray::from_slice(&iv).map_err(|_| CredEncErr::SliceTooBig)?,
            nonce,
            tag_transport,
            tag_pin,
        })
    }
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use zeroize::Zeroize;
use zeroize::Zeroizing;

use super::*;

/// ECDH shared secret. The transport keys are used to encrypt and authenticate messages.
const BK3_TRANSPORT_INFO: &[u8] = b"BK3_TRANSPORT_ENC";

/// Domain byte for the PIN-bound HMAC key derivation. This is a fixed value
/// to ensure that the derived key is unique to the BK3 encryption scheme.
const BK3_KPIN_DOMAIN: u8 = 0x02;

/// AES-256 transport key length in bytes.
const AES_KEY_LEN: usize = 32;

/// HMAC-SHA-384 key length in bytes.
const HMAC_KEY_LEN: usize = 48;

/// HMAC-SHA-384 tag length in bytes.
const HMAC_TAG_LEN: usize = 48;

/// AES-CBC IV length in bytes.
const IV_LEN: usize = 16;

/// Credential ID length in bytes.
const ID_LEN: usize = 16;

/// PIN length in bytes.
const PIN_LEN: usize = 16;

/// Nonce length in bytes.
const NONCE_LEN: usize = 32;

/// BK3 backup-key length in bytes.
const BK3_LEN: usize = 48;

/// ECDH P-384 shared-secret length in bytes.
const ECDH_SECRET_LEN: usize = 48;

/// Transport key material = AES key || HMAC key.
const TRANSPORT_KEYMAT_LEN: usize = AES_KEY_LEN + HMAC_KEY_LEN;

/// K_pin HKDF `info` = PIN || ID || domain byte.
const KPIN_INFO_LEN: usize = PIN_LEN + ID_LEN + 1;

/// Authenticated BK3 message = IV || ct_bk3 || nonce.
const BK3_MSG_LEN: usize = IV_LEN + BK3_LEN + NONCE_LEN;

/// Encrypt `plaintext` with AES-256-CBC using `algo` (which carries the IV and
/// CBC chaining state). Shared by the credential and BK3 encryption schemes.
///
/// # Errors
///
/// Returns a [`CredEncErr`] if the key import or the AES-CBC encryption fails.
fn aes_cbc_encrypt(
    aes_key: &[u8; AES_KEY_LEN],
    algo: &mut AesCbcAlgo,
    plaintext: &[u8],
) -> Result<Vec<u8>, CredEncErr> {
    let key = AesKey::from_bytes(aes_key).map_err(|_| CredEncErr::AesKeyImportError)?;
    Encrypter::encrypt_vec(algo, &key, plaintext).map_err(|_| CredEncErr::AesCbcEncryptError)
}

/// Compute an HMAC-SHA-384 tag over `data` under `hmac_key`. Shared by the
/// credential and BK3 encryption schemes.
///
/// # Errors
///
/// Returns a [`CredEncErr`] if the key import or the HMAC signing fails.
fn hmac_sha_384(hmac_key: &[u8], data: &[u8]) -> Result<[u8; HMAC_TAG_LEN], CredEncErr> {
    let mut tag = [0u8; HMAC_TAG_LEN];
    let hash = HashAlgo::sha384();
    let mut hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(hmac_key).map_err(|_| CredEncErr::HmacKeyImportError)?;
    Signer::sign(&mut hmac, &key, data, Some(&mut tag)).map_err(|_| CredEncErr::HmacSignError)?;
    Ok(tag)
}

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

    /// Generate a fresh ephemeral P-384 key pair and derive a
    /// [`Bk3EncryptionKey`] from it.
    ///
    /// # Returns
    ///
    /// The derived [`Bk3EncryptionKey`] together with the ephemeral public key
    /// (DER) to send to the device.
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if key generation, export, or the ECDH
    /// derivation fails.
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

    /// Derive a [`Bk3EncryptionKey`] from a caller-supplied ephemeral private
    /// key. Primarily used to drive deterministic tests.
    ///
    /// # Arguments
    ///
    /// * `priv_key_der` - The ephemeral P-384 private key in DER form.
    ///
    /// # Returns
    ///
    /// The derived [`Bk3EncryptionKey`] together with the matching ephemeral
    /// public key (DER) to send to the device.
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if the private key cannot be imported, the
    /// public key cannot be exported, or the ECDH derivation fails.
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

impl Drop for CredentialEncryptionKey {
    fn drop(&mut self) {
        self.aes_key.zeroize();
        self.hmac_key.zeroize();
    }
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
        let derived_bytes =
            Zeroizing::new(output.to_vec().map_err(|_| CredEncErr::SecretExportError)?);

        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&derived_bytes[..32]);
        let mut hmac_key = [0u8; 48];
        hmac_key.copy_from_slice(&derived_bytes[32..]);

        Ok(CredentialEncryptionKey { aes_key, hmac_key })
    }

    pub fn encrypt_establish_credential(
        &self,
        id: [u8; 16],
        pin: [u8; 16],
        nonce: [u8; 32],
    ) -> Result<DdiEncryptedEstablishCredential, CredEncErr> {
        let iv = Rng::rand_vec(16).map_err(|_| CredEncErr::RngError)?;

        let mut algo = AesCbcAlgo::with_no_padding(&iv);
        let encrypted_id = aes_cbc_encrypt(&self.aes_key, &mut algo, &id)?;
        let encrypted_pin = aes_cbc_encrypt(&self.aes_key, &mut algo, &pin)?;

        let mut id_pin_iv_nonce = [0; 80];
        id_pin_iv_nonce[..16].copy_from_slice(&encrypted_id);
        id_pin_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
        id_pin_iv_nonce[32..48].copy_from_slice(&iv);
        id_pin_iv_nonce[48..].copy_from_slice(&nonce);

        let tag = hmac_sha_384(&self.hmac_key, &id_pin_iv_nonce)?;

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
        let encrypted_id = aes_cbc_encrypt(&self.aes_key, &mut algo, &id)?;
        let encrypted_pin = aes_cbc_encrypt(&self.aes_key, &mut algo, &pin)?;
        let encrypted_seed = aes_cbc_encrypt(&self.aes_key, &mut algo, &seed)?;

        let mut id_pin_seed_iv_nonce = [0; 128];
        id_pin_seed_iv_nonce[..16].copy_from_slice(&encrypted_id);
        id_pin_seed_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
        id_pin_seed_iv_nonce[32..80].copy_from_slice(&encrypted_seed);
        id_pin_seed_iv_nonce[80..96].copy_from_slice(&iv);
        id_pin_seed_iv_nonce[96..].copy_from_slice(&nonce);

        let tag = hmac_sha_384(&self.hmac_key, &id_pin_seed_iv_nonce)?;

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
        let encrypted_pin = aes_cbc_encrypt(&self.aes_key, &mut algo, &pin)?;

        let mut id_pin_iv_nonce = [0; 64];
        id_pin_iv_nonce[..16].copy_from_slice(&encrypted_pin);
        id_pin_iv_nonce[16..32].copy_from_slice(&iv);
        id_pin_iv_nonce[32..].copy_from_slice(&nonce);

        let tag = hmac_sha_384(&self.hmac_key, &id_pin_iv_nonce)?;

        Ok(DdiEncryptedPin {
            encrypted_pin: MborByteArray::from_slice(&encrypted_pin)
                .map_err(|_| CredEncErr::SliceTooBig)?,
            iv: MborByteArray::from_slice(&iv).map_err(|_| CredEncErr::SliceTooBig)?,
            nonce,
            tag,
        })
    }
}

/// Per-provisioning key material for BK3 encryption, derived from the ECDH
/// shared secret. Zeroized on drop.
pub struct Bk3EncryptionKey {
    secret: [u8; ECDH_SECRET_LEN],
}

impl Drop for Bk3EncryptionKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Bk3EncryptionKey {
    /// Perform ECDH between the device public key and the ephemeral private key
    /// to establish the shared `secret` this key material is derived from.
    ///
    /// # Arguments
    ///
    /// * `device_credential_key` - The device's ECC public key.
    /// * `client_priv_key` - The ephemeral ECC private key.
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if the ECDH derivation or secret export fails.
    fn create(
        device_credential_key: &EccPublicKey,
        client_priv_key: &EccPrivateKey,
    ) -> Result<Self, CredEncErr> {
        let ecdh = EcdhAlgo::new(device_credential_key)
            .derive(client_priv_key, ECDH_SECRET_LEN)
            .map_err(|_| CredEncErr::EcdhDeriveError)?;
        let secret_bytes =
            Zeroizing::new(ecdh.to_vec().map_err(|_| CredEncErr::SecretExportError)?);
        if secret_bytes.len() != ECDH_SECRET_LEN {
            return Err(CredEncErr::EcdhDeriveError);
        }
        let mut secret = [0u8; ECDH_SECRET_LEN];
        secret.copy_from_slice(&secret_bytes);
        Ok(Self { secret })
    }

    /// Expand the shared `secret` with HKDF-SHA-384 to derive key material.
    ///
    /// # Arguments
    ///
    /// * `info` - The HKDF context/`info` string binding the derivation.
    /// * `out_len` - The number of bytes of key material to derive.
    ///
    /// # Returns
    ///
    /// `out_len` bytes of derived key material, wrapped in [`Zeroizing`].
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if the HKDF derivation or secret export fails.
    fn hkdf_sha384(&self, info: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>, CredEncErr> {
        let ikm = GenericSecretKey::from_bytes(&self.secret)
            .map_err(|_| CredEncErr::SecretExportError)?;
        let hash = HashAlgo::sha384();
        let hkdf = HkdfAlgo::new(HkdfMode::ExtractAndExpand, &hash, None, Some(info));
        let output = hkdf
            .derive(&ikm, out_len)
            .map_err(|_| CredEncErr::HkdfDeriveError)?;
        output
            .to_vec()
            .map(Zeroizing::new)
            .map_err(|_| CredEncErr::SecretExportError)
    }

    /// Derive the BK3 transport keys from the shared secret via HKDF with the
    /// fixed `BK3_TRANSPORT_INFO` context.
    ///
    /// # Returns
    ///
    /// A tuple of the AES-CBC key and the HMAC key, each wrapped in
    /// [`Zeroizing`].
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if the HKDF derivation fails.
    fn derive_transport_keys(
        &self,
    ) -> Result<(Zeroizing<[u8; AES_KEY_LEN]>, Zeroizing<[u8; HMAC_KEY_LEN]>), CredEncErr> {
        let derived = self.hkdf_sha384(BK3_TRANSPORT_INFO, TRANSPORT_KEYMAT_LEN)?;
        let mut aes_key = Zeroizing::new([0u8; AES_KEY_LEN]);
        aes_key.copy_from_slice(&derived[..AES_KEY_LEN]);
        let mut hmac_key = Zeroizing::new([0u8; HMAC_KEY_LEN]);
        hmac_key.copy_from_slice(&derived[AES_KEY_LEN..TRANSPORT_KEYMAT_LEN]);
        Ok((aes_key, hmac_key))
    }

    /// Derive the PIN-bound HMAC key (`k_pin`) from the shared secret via HKDF,
    /// using `PIN || ID || domain` as the context so the tag binds the operator
    /// PIN and ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The credential ID to bind into the derivation.
    /// * `pin` - The operator PIN to bind into the derivation.
    ///
    /// # Returns
    ///
    /// The PIN-bound HMAC key, wrapped in [`Zeroizing`].
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if the HKDF derivation fails.
    fn derive_k_pin(
        &self,
        id: [u8; ID_LEN],
        pin: [u8; PIN_LEN],
    ) -> Result<Zeroizing<[u8; HMAC_KEY_LEN]>, CredEncErr> {
        // `info` carries the PIN and ID in the clear; wrap it in `Zeroizing`
        // so it is wiped on drop (all paths, including early return) instead
        // of a manual `fill(0)`.
        let mut info = Zeroizing::new([0u8; KPIN_INFO_LEN]);
        info[..PIN_LEN].copy_from_slice(&pin);
        info[PIN_LEN..PIN_LEN + ID_LEN].copy_from_slice(&id);
        info[PIN_LEN + ID_LEN] = BK3_KPIN_DOMAIN;

        let derived = self.hkdf_sha384(&info[..], HMAC_KEY_LEN)?;
        let mut k_pin = Zeroizing::new([0u8; HMAC_KEY_LEN]);
        k_pin.copy_from_slice(&derived[..HMAC_KEY_LEN]);
        Ok(k_pin)
    }

    /// Encrypt a BK3 backup key for secure provisioning.
    ///
    /// Encrypts `bk3` with AES-CBC under the derived transport key, then
    /// authenticates `IV || ct_bk3 || nonce` twice: once with the transport HMAC
    /// key (`tag_transport`) and once with the PIN-bound key (`tag_pin`).
    ///
    /// # Arguments
    ///
    /// * `bk3` - The BK3 backup key to encrypt.
    /// * `id` - The credential ID bound into the PIN tag.
    /// * `pin` - The operator PIN bound into the PIN tag.
    /// * `nonce` - The device-supplied nonce for replay protection.
    ///
    /// # Returns
    ///
    /// A [`DdiEncryptedBk3`] carrying the ciphertext, IV, nonce, and the two
    /// authentication tags.
    ///
    /// # Errors
    ///
    /// Returns a [`CredEncErr`] if RNG, key derivation, AES-CBC encryption, or
    /// HMAC signing fails, or if the ciphertext is not the expected length.
    pub fn encrypt_bk3(
        &self,
        bk3: &[u8; BK3_LEN],
        id: [u8; ID_LEN],
        pin: [u8; PIN_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<DdiEncryptedBk3, CredEncErr> {
        let iv = Rng::rand_vec(IV_LEN).map_err(|_| CredEncErr::RngError)?;

        let (aes_key, transport_hmac_key) = self.derive_transport_keys()?;
        let k_pin = self.derive_k_pin(id, pin)?;

        let mut algo = AesCbcAlgo::with_no_padding(&iv);
        let ct_bk3 = aes_cbc_encrypt(&aes_key, &mut algo, bk3)?;
        if ct_bk3.len() != BK3_LEN {
            return Err(CredEncErr::AesCbcEncryptError);
        }

        let mut message = [0u8; BK3_MSG_LEN];
        message[..IV_LEN].copy_from_slice(&iv);
        message[IV_LEN..IV_LEN + BK3_LEN].copy_from_slice(&ct_bk3);
        message[IV_LEN + BK3_LEN..].copy_from_slice(&nonce);

        let tag_transport = hmac_sha_384(&transport_hmac_key[..], &message)?;
        let tag_pin = hmac_sha_384(&k_pin[..], &message)?;

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

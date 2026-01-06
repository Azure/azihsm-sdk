// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key attestation module

use crate::crypto::ecc::EccCurve;
use crate::crypto::ecc::EccOp;
use crate::crypto::ecc::EccPrivateKey;
use crate::crypto::ecc::EccPrivateOp;
use crate::crypto::ecc::EccPublicKey;
use crate::crypto::ecc::EccPublicOp;
use crate::crypto::rsa::RsaOp;
use crate::crypto::rsa::RsaPrivateKey;
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::sha::sha;
use crate::crypto::sha::HashAlgorithm;
use crate::errors::ManticoreError;
use crate::report::*;

/// Support key attestation quote generation.
pub struct KeyAttester {
    protected_header: [u8; PROTECTED_HEADER_SIZE],
    unprotected_header: UnprotectedHeader,
    report: [u8; PAYLOAD_MAX_SIZE],
    report_size: usize,
    signature: [u8; SIGNATURE_SIZE],
}

impl KeyAttester {
    ///  Create and initialize a `KeyAttester` instance.
    ///
    /// # Returns
    /// * `KeyAttester` - An initialized `KeyAttester` instance.
    pub fn new() -> Self {
        let unprotected_header = UnprotectedHeader {};

        Self {
            protected_header: PROTECTED_HEADER,
            unprotected_header,
            report: [0u8; PAYLOAD_MAX_SIZE],
            report_size: 0,
            signature: [0u8; SIGNATURE_SIZE],
        }
    }

    ///  Create the report payload.
    ///
    /// # Arguments
    /// * `public_key` - The encoded public key using `CoseKey`.
    /// * `public_key_size` - The size of the encoded public key.
    /// * `flags` - The flags associated with the key.
    /// * `app_uuid` - The uuid of the vault application session.
    /// * `report_data` - Customized data to be included in the report.
    ///
    /// # Returns
    /// * `()` - If the creation succeeds.
    ///
    /// # Errors
    /// * `ManticoreError::CborEncodeError` - If CBOR encoding fails during creation.
    pub fn create_report_payload(
        &mut self,
        public_key: &[u8; PUBLIC_KEY_MAX_SIZE],
        public_key_size: u16,
        flags: KeyFlags,
        app_uuid: [u8; 16],
        report_data: &[u8; REPORT_DATA_SIZE],
        vm_launch_id: &[u8; VM_LAUNCH_ID_SIZE],
    ) -> Result<(), ManticoreError> {
        (self.report, self.report_size) = CoseSign1::create_payload(
            REPORT_VERSION,
            public_key,
            public_key_size,
            flags.into(),
            app_uuid,
            report_data,
            vm_launch_id,
        )?;

        Ok(())
    }

    ///  Sign the quote using EC384.
    ///
    /// # Arguments
    /// * `key` - The P-384 ECC private key for signing.
    ///
    /// # Returns
    /// * `([u8; COSE_SIGN1_OBJECT_MAX_SIZE], usize)` - The signed quote buffer and the length of the quote.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If key is not a P-384 ECC key.
    /// * `ManticoreError::CborEncodeError` - If CBOR encoding fails during creation.
    pub fn sign(
        &mut self,
        key: &EccPrivateKey,
    ) -> Result<([u8; TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE], usize), ManticoreError> {
        let payload = &self.report[..self.report_size];
        // Create the to-be-signed data blob.
        let (buffer, len) = CoseSign1::create_tbs(&self.protected_header, payload)?;

        // Sign the data blob.
        self.signature = CoseSign1::sign(key, &buffer[..len])?;

        let mut cose_sign1_object_buffer = [0u8; TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE];

        // Add an untagged COSE_Sign1 object after the tag
        let cose_sign1_object = CoseSign1Object {
            protected_header: self.protected_header,
            unprotected_header: self.unprotected_header,
            payload,
            signature: self.signature,
        };

        let cose_sign1_object_buffer_size =
            cose_sign1_object.encode(&mut cose_sign1_object_buffer)?;

        Ok((cose_sign1_object_buffer, cose_sign1_object_buffer_size))
    }

    ///  Parse the attestation report from a signed COSE_Sign1 object.
    pub fn parse(report: &[u8]) -> Result<Self, ManticoreError> {
        let cose_sign1_object = CoseSign1Object::decode(report)?;

        let report_size = cose_sign1_object.payload.len();
        if report_size > PAYLOAD_MAX_SIZE {
            return Err(ManticoreError::InvalidArgument);
        }

        let mut report = [0u8; PAYLOAD_MAX_SIZE];
        report[..report_size].copy_from_slice(cose_sign1_object.payload);

        Ok(KeyAttester {
            protected_header: cose_sign1_object.protected_header,
            unprotected_header: cose_sign1_object.unprotected_header,
            report,
            report_size,
            signature: cose_sign1_object.signature,
        })
    }

    ///  Verify the attestation report signature.
    pub fn verify(&self, key: &EccPublicKey) -> Result<(), ManticoreError> {
        let payload = &self.report[..self.report_size];
        // Create the to-be-signed data blob.
        let (buffer, len) = CoseSign1::create_tbs(&self.protected_header, payload)?;

        // Ensure the key uses P-384.
        let curve = key.curve()?;
        if curve != EccCurve::P384 {
            Err(ManticoreError::InvalidArgument)?
        }

        let hash = sha(HashAlgorithm::Sha384, &buffer[..len])?;

        key.verify(&hash, &self.signature).map_err(|_| {
            tracing::error!("Signature doesn't match");
            // This may indicate LM happened between getting report and cert chain
            ManticoreError::ReportSignatureMismatch
        })
    }
}

/// Support COSE Key Object encoding based on Section 7, <https://www.rfc-editor.org/rfc/rfc9052>.
#[derive(Debug)]
pub enum CoseKey {
    /// RSA Public Key
    RsaPublic {
        /// Modulus
        n: Vec<u8>,

        /// Exponent
        e: Vec<u8>,
    },

    /// ECC Public Key
    EccPublic {
        /// Curve
        crv: i8,

        /// X Coordinate
        x: Vec<u8>,

        /// Y Coordinate
        y: Vec<u8>,
    },
}

impl CoseKey {
    /// Encode the key.
    ///
    /// # Returns
    /// * `([u8; PUBLIC_KEY_MAX_SIZE], u16)` - The encoded key buffer and the size of the encoded key.
    ///
    /// # Errors
    /// * `ManticoreError::CborEncodeError` - If CBOR encoding fails.
    pub fn encode(&self) -> Result<([u8; PUBLIC_KEY_MAX_SIZE], u16), ManticoreError> {
        let mut buffer = [0u8; PUBLIC_KEY_MAX_SIZE];
        let len = match self {
            CoseKey::RsaPublic { n, e } => encode_rsa_public(n, e, &mut buffer),
            CoseKey::EccPublic { crv, x, y } => encode_ecc_public(*crv, x, y, &mut buffer),
        }?;

        Ok((buffer, len as u16))
    }
}

impl TryFrom<&EccPrivateKey> for CoseKey {
    type Error = ManticoreError;

    /// Create a `CoseKey` from an ECC private key.
    ///
    /// # Arguments
    /// * `key` - The ECC private key.
    ///
    /// # Returns
    /// * `CoseKey` - The corresponding `CoseKey`.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the key is not a supported ECC key.
    fn try_from(key: &EccPrivateKey) -> Result<Self, Self::Error> {
        let curve_name = key.curve()?;

        // Based on Table 18, https://www.rfc-editor.org/rfc/rfc9053.html
        let crv = match curve_name {
            EccCurve::P256 => 1,
            EccCurve::P384 => 2,
            EccCurve::P521 => 3,
        };

        let (x, y) = key.coordinates()?;

        Ok(Self::EccPublic { crv, x, y })
    }
}

impl TryFrom<&EccPublicKey> for CoseKey {
    type Error = ManticoreError;

    /// Create a `CoseKey` from an ECC public key.
    ///
    /// # Arguments
    /// * `key` - The ECC public key.
    ///
    /// # Returns
    /// * `CoseKey` - The corresponding `CoseKey`.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the key is not a supported ECC key.
    fn try_from(key: &EccPublicKey) -> Result<Self, Self::Error> {
        let curve_name = key.curve()?;

        // Based on Table 18, https://www.rfc-editor.org/rfc/rfc9053.html
        let crv = match curve_name {
            EccCurve::P256 => 1,
            EccCurve::P384 => 2,
            EccCurve::P521 => 3,
        };

        let (x, y) = key.coordinates()?;

        Ok(Self::EccPublic { crv, x, y })
    }
}

impl TryFrom<&RsaPrivateKey> for CoseKey {
    type Error = ManticoreError;

    /// Create a `CoseKey` from an RSA Private key.
    ///
    /// # Arguments
    /// * `key` - The RSA private key.
    ///
    /// # Returns
    /// * `CoseKey` - The corresponding `CoseKey`.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the key is not a supported RSA key.
    fn try_from(key: &RsaPrivateKey) -> Result<Self, Self::Error> {
        let n = key.modulus()?;
        let e = key.public_exponent()?;

        Ok(Self::RsaPublic { n, e })
    }
}

impl TryFrom<&RsaPublicKey> for CoseKey {
    type Error = ManticoreError;

    /// Create a `CoseKey` from an RSA Public key.
    ///
    /// # Arguments
    /// * `key` - The RSA public key.
    ///
    /// # Returns
    /// * `CoseKey` - The corresponding `CoseKey`.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the key is not a supported RSA key.
    fn try_from(key: &RsaPublicKey) -> Result<Self, Self::Error> {
        let n = key.modulus()?;
        let e = key.public_exponent()?;

        Ok(Self::RsaPublic { n, e })
    }
}

/// Support COSE_Sign1 object creation based on <https://www.rfc-editor.org/rfc/rfc9052>.
struct CoseSign1 {}

impl CoseSign1 {
    ///  Create the payload.
    ///
    /// # Arguments
    /// * `public_key` - The encoded public key using `CoseKey`.
    /// * `public_key_size` - The size of the encoded public key.
    /// * `flags` - The flags associated with the key.
    /// * `app_uuid` - The uuid of the vault application session.
    /// * `report_data` - Customized data to be included in the report.
    /// * `vm_launch_id` - The VM launch ID.
    ///
    /// # Returns
    /// * `([u8; REPORT_SIZE], usize)` - The payload buffer and the size of the payload.
    ///
    /// # Errors
    /// * `ManticoreError::CborEncodeError` - If CBOR encoding fails during creation.
    fn create_payload(
        version: u16,
        public_key: &[u8; PUBLIC_KEY_MAX_SIZE],
        public_key_size: u16,
        flags: u32,
        app_uuid: [u8; 16],
        report_data: &[u8; REPORT_DATA_SIZE],
        vm_launch_id: &[u8; VM_LAUNCH_ID_SIZE],
    ) -> Result<([u8; PAYLOAD_MAX_SIZE], usize), ManticoreError> {
        let mut buffer = [0u8; PAYLOAD_MAX_SIZE];
        let report = KeyAttestationReport {
            version,
            public_key: *public_key,
            public_key_size,
            flags,
            app_uuid,
            report_data: *report_data,
            vm_launch_id: *vm_launch_id,
        };
        let size = report.encode(&mut buffer)?;

        Ok((buffer, size))
    }

    /// Create the to-be-signed buffer based on Section 4.4, <https://www.rfc-editor.org/rfc/rfc9052>.
    ///
    /// # Arguments
    /// * `body_protected` - The `body_protected` parameter of the `Sig_structure`.
    /// * `payload` - The `payload` parameter of the `Sig_structure`.
    ///
    /// # Returns
    /// * `([u8; SIG_STRUCTURE_MAX_SIZE], usize)` - The payload buffer and the size of the payload.
    ///
    /// # Errors
    /// * `ManticoreError::CborEncodeError` - If CBOR encoding fails during creation.
    fn create_tbs(
        body_protected: &[u8],
        payload: &[u8],
    ) -> Result<([u8; SIG_STRUCTURE_MAX_SIZE], usize), ManticoreError> {
        let mut sig_struct_buffer = [0u8; SIG_STRUCTURE_MAX_SIZE];

        let sig_struct_size = encode_sig_struct(body_protected, payload, &mut sig_struct_buffer)?;

        Ok((sig_struct_buffer, sig_struct_size))
    }

    /// Sign with ES384 given the key and the to-be-signed buffer.
    ///
    /// # Arguments
    /// * `key` - The P-384 ECC private signing key.
    /// * `tbs` - The to-be-signed data blob generated by `create_tbs`.
    ///
    /// # Returns
    /// * `[u8; SIGNATURE_SIZE]` - The ECDSA signature.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If key is not a P-384 ECC key.
    /// * `ManticoreError::CborEncodeError` - If CBOR encoding fails during creation.
    /// * `ManticoreError::CoseSign1UnexpectedSignature` - If size of the signature is unexpected.
    fn sign(key: &EccPrivateKey, tbs: &[u8]) -> Result<[u8; SIGNATURE_SIZE], ManticoreError> {
        // Ensure the key uses P-384.
        let curve = key.curve()?;
        if curve != EccCurve::P384 {
            tracing::error!(?curve, "CoseSign1 only accepts P-384 ECC key for signing");
            Err(ManticoreError::InvalidArgument)?
        }

        let hash = sha(HashAlgorithm::Sha384, tbs)?;
        let signature = key.sign(&hash)?;

        if signature.len() != SIGNATURE_SIZE {
            tracing::error!(
                expect = SIGNATURE_SIZE,
                actual = signature.len(),
                "Unexpected signature size"
            );
            Err(ManticoreError::CoseSign1UnexpectedSignature)?
        }

        let mut signature_buffer = [0u8; SIGNATURE_SIZE];
        signature_buffer.copy_from_slice(&signature);

        Ok(signature_buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecc::generate_ecc;
    use crate::crypto::rsa::generate_rsa;

    #[test]
    fn test_rsa_cose_key() {
        const KEY_SIZE: usize = 512;

        // Generate the key
        let keypair = generate_rsa((KEY_SIZE * 8) as u32);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        let result_from_private = CoseKey::try_from(&rsa_private);
        assert!(result_from_private.is_ok());
        let result_from_private = result_from_private.unwrap();

        let result_from_public = CoseKey::try_from(&rsa_public);
        assert!(result_from_public.is_ok());
        let result_from_public = result_from_public.unwrap();

        let result_from_private = result_from_private.encode();
        assert!(result_from_private.is_ok());
        let (encode_from_private, encode_len_from_private) = result_from_private.unwrap();

        let result_from_public = result_from_public.encode();
        assert!(result_from_public.is_ok());
        let (encode_from_public, encode_len_from_public) = result_from_public.unwrap();

        assert_eq!(encode_len_from_private, encode_len_from_public);
        assert_eq!(encode_from_private, encode_from_public);

        // The size of the encoded 4k RSA public key should equal to `PUBLIC_KEY_MAX_SIZE` - 1.
        // The difference lines in the intended maximum exponent size is 4 while
        // the current RSA implementation uses the 3-byte exponent (0x010001) by default.
        assert_eq!(encode_len_from_private as usize, PUBLIC_KEY_MAX_SIZE - 1);
    }

    #[test]
    fn test_ecc_cose_key() {
        // Generate the key
        let keypair = generate_ecc(EccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();

        let result_from_private = CoseKey::try_from(&ecc_private);
        assert!(result_from_private.is_ok());
        let result_from_private = result_from_private.unwrap();

        let result_from_public = CoseKey::try_from(&ecc_public);
        assert!(result_from_public.is_ok());
        let result_from_public = result_from_public.unwrap();

        let result_from_private = result_from_private.encode();
        assert!(result_from_private.is_ok());
        let (encode_from_private, encode_len_from_private) = result_from_private.unwrap();

        let result_from_public = result_from_public.encode();
        assert!(result_from_public.is_ok());
        let (encode_from_public, encode_len_from_public) = result_from_public.unwrap();

        assert_eq!(encode_len_from_private, encode_len_from_public);
        assert_eq!(encode_from_private, encode_from_public);
    }

    #[test]
    fn test_cose_sign1() {
        let protected_header = PROTECTED_HEADER;
        let unprotected_header = UnprotectedHeader {};

        let result = generate_rsa(2048);
        assert!(result.is_ok());
        let (rsa_private, _) = result.unwrap();

        let result = CoseKey::try_from(&rsa_private);
        assert!(result.is_ok());
        let rsa_key = result.unwrap();

        let result = rsa_key.encode();
        assert!(result.is_ok());
        let (rsa, rsa_len) = result.unwrap();

        let result =
            CoseSign1::create_payload(1, &rsa, rsa_len, 4, [1u8; 16], &[2u8; 128], &[3u8; 16]);
        assert!(result.is_ok());
        let (report_buffer, report_buffer_size) = result.unwrap();

        let result = CoseSign1::create_tbs(&protected_header, &report_buffer[..report_buffer_size]);
        assert!(result.is_ok());
        let (buffer, len) = result.unwrap();

        let result = generate_ecc(EccCurve::P384);
        assert!(result.is_ok());
        let (ecc_private, _) = result.unwrap();

        let result = CoseSign1::sign(&ecc_private, &buffer[..len]);
        assert!(result.is_ok());
        let signature = result.unwrap();

        // Test with non P-384 ECC key.
        let result = generate_ecc(EccCurve::P256);
        assert!(result.is_ok());
        let (ecc_private, _) = result.unwrap();

        let result = CoseSign1::sign(&ecc_private, &buffer[..len]);
        assert_eq!(result, Err(ManticoreError::InvalidArgument));

        let mut cose_sign1_object_buffer = [0u8; TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE];
        let cose_sign1_object = CoseSign1Object {
            protected_header,
            unprotected_header,
            payload: &report_buffer,
            signature,
        };
        let result = cose_sign1_object.encode(&mut cose_sign1_object_buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_attester() {
        let mut attester = KeyAttester::new();

        const KEY_SIZE: usize = 256;

        let keypair = generate_rsa((KEY_SIZE * 8) as u32);
        assert!(keypair.is_ok());
        let (rsa_private, _) = keypair.unwrap();

        let rsa_key = CoseKey::try_from(&rsa_private).unwrap();
        let (rsa, rsa_len) = rsa_key.encode().unwrap();

        let flags = KeyFlags::new()
            .with_is_generated(true)
            .with_can_encrypt(true)
            .with_can_decrypt(true);

        let result = attester.create_report_payload(
            &rsa,
            rsa_len,
            flags,
            [1u8; 16],
            &[2u8; 128],
            &[3u8; 16],
        );
        assert!(result.is_ok());

        let result = generate_ecc(EccCurve::P384);
        assert!(result.is_ok());
        let (ecc_private_key, _) = result.unwrap();
        let result = attester.sign(&ecc_private_key);
        assert!(result.is_ok());
    }
}

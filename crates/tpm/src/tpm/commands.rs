// Copyright (C) Microsoft Corporation. All rights reserved.

use std::io;

use crate::tpm::device::RawTpm;
use crate::tpm::helpers::*;
use crate::tpm::types::command_prelude::*;
use crate::tpm::types::Tpm2b;
use crate::tpm::types::TpmsSensitiveCreate;

const TPM_RESPONSE_HEADER_SIZE: usize = 10;
const TPM_HANDLE_SIZE: usize = 4;

pub struct CreatedPrimary {
    pub handle: u32,
    pub public: Vec<u8>,
}

pub struct LoadedObject {
    pub handle: u32,
    pub name: Vec<u8>,
}

pub struct SealedObject {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub creation_data: Vec<u8>,
    pub creation_hash: Vec<u8>,
    pub creation_ticket: Vec<u8>,
}

/// TPM command extension methods built on any RawTpm implementation.
/// The extension only implements a minimal subset of TPM commands.
pub trait TpmCommandExt: RawTpm {
    fn create_primary(
        &self,
        hierarchy: Hierarchy,
        public_template: Tpm2bPublic,
        pcrs: &[u32],
    ) -> io::Result<CreatedPrimary>;

    fn load(
        &self,
        parent_handle: u32,
        parent_auth: &[u8],
        in_private: &[u8],
        in_public: &[u8],
    ) -> io::Result<LoadedObject>;

    fn unseal(&self, item_handle: u32, auth_value: &[u8]) -> io::Result<Vec<u8>>;

    fn seal(
        &self,
        parent_handle: u32,
        parent_auth: &[u8],
        data: &[u8],
        public_template: Tpm2bPublic,
        pcrs: &[u32],
    ) -> io::Result<SealedObject>;

    /// Flushes a transient or loaded object handle from the TPM.
    fn flush_context(&self, handle: u32) -> io::Result<()>;

    /// Create a primary ECC key in the specified hierarchy.
    fn create_primary_ecc(
        &self,
        hierarchy: Hierarchy,
        public_template: Tpm2bPublicEcc,
    ) -> io::Result<CreatedPrimary>;

    /// Sign a digest using the specified key handle. Returns the signature.
    fn sign(&self, key_handle: u32, digest: &[u8]) -> io::Result<TpmtSignature>;

    /// Verify a signature using the specified key handle. Returns Ok(()) if valid.
    fn verify_signature(
        &self,
        key_handle: u32,
        digest: &[u8],
        signature: &TpmtSignature,
    ) -> io::Result<()>;
}

impl<T: RawTpm> TpmCommandExt for T {
    /// Creates a primary key in the specified TPM hierarchy.
    ///
    /// A primary key is generated directly from the hierarchy seed and can be used as a
    /// parent for other keys. Primary keys are deterministic - the same template and PCR
    /// selections will always produce the same key handle and public area.
    ///
    /// # Arguments
    ///
    /// * `hierarchy` - The TPM hierarchy in which to create the primary key (Owner, Endorsement, or Null)
    /// * `public_template` - Template defining the key type, attributes, and parameters
    /// * `pcrs` - PCR indices to bind the key creation to (empty slice for no PCR binding)
    ///
    /// # Returns
    ///
    /// Returns a `CreatedPrimary` containing:
    /// - `handle` - TPM handle for the created primary key (transient, must be flushed)
    /// - `public` - Marshaled public area in TPM2B format
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM command fails or the response is malformed.
    fn create_primary(
        &self,
        hierarchy: Hierarchy,
        public_template: Tpm2bPublic,
        pcrs: &[u32],
    ) -> io::Result<CreatedPrimary> {
        let parameters = CreatePrimaryCommandParameters {
            in_sensitive: empty_sensitive_create(),
            in_public: public_template,
            outside_info: Tpm2bBytes(Vec::new()),
            creation_pcr: PcrSelectionList::from_pcrs(pcrs),
        };
        let cmd_body = CreatePrimaryCommand::new(hierarchy, parameters);
        let handle_values = cmd_body.handle_values();
        let cmd =
            build_command_pw_sessions(TpmCommandCode::CreatePrimary, &handle_values, &[&[]], |b| {
                cmd_body.parameters.marshal(b);
            });

        let resp = self.transmit_raw(&cmd)?;
        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::CreatePrimary)?;

        if resp.len() < 14 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "CreatePrimary short response",
            ));
        }
        // Response layout: header (10) + handle (4) + paramSize (4) + parameters.
        let parsed = CreatePrimaryResponse::from_bytes(&resp)?;
        let public_bytes = {
            // Re-marshal the returned out_public to return canonical TPM2B form
            let mut b = Vec::new();
            parsed.parameters.out_public.marshal(&mut b);
            b
        };
        Ok(CreatedPrimary {
            handle: parsed.handles.object_handle,
            public: public_bytes,
        })
    }

    /// Loads a previously created TPM object into the TPM.
    ///
    /// Takes marshaled private and public blobs (typically from a prior `seal` operation)
    /// and loads the object into TPM memory under the specified parent key.
    ///
    /// # Arguments
    ///
    /// * `parent_handle` - Handle of the parent key under which to load the object
    /// * `parent_auth` - Authorization value for the parent key (empty slice if none)
    /// * `in_private` - Marshaled TPM2B_PRIVATE blob containing the encrypted private portion
    /// * `in_public` - Marshaled TPM2B_PUBLIC blob containing the public portion
    ///
    /// # Returns
    ///
    /// Returns a `LoadedObject` containing:
    /// - `handle` - TPM handle for the loaded object (transient, must be flushed)
    /// - `name` - TPM name of the loaded object
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM command fails or the response is malformed.
    fn load(
        &self,
        parent_handle: u32,
        parent_auth: &[u8],
        in_private_blob: &[u8],
        in_public_blob: &[u8],
    ) -> io::Result<LoadedObject> {
        let mut priv_cursor = 0usize;
        let in_private = Tpm2bBytes::unmarshal(in_private_blob, &mut priv_cursor)?;
        if priv_cursor != in_private_blob.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TPM2B_PRIVATE blob has trailing bytes",
            ));
        }

        let mut pub_cursor = 0usize;
        let in_public = Tpm2bBytes::unmarshal(in_public_blob, &mut pub_cursor)?;
        if pub_cursor != in_public_blob.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "TPM2B_PUBLIC blob has {} trailing bytes",
                    in_public_blob.len() - pub_cursor
                ),
            ));
        }

        let parameters = LoadCommandParameters {
            in_private,
            in_public,
        };
        let cmd_body = LoadCommand::new(parent_handle, parameters);
        let handles = cmd_body.handle_values();
        let session_auths: [&[u8]; 1] = [parent_auth];
        let cmd = build_command_pw_sessions(TpmCommandCode::Load, &handles, &session_auths, |b| {
            cmd_body.parameters.marshal(b);
        });

        let resp = self.transmit_raw(&cmd)?;

        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::Load)?;
        if resp.len() < (TPM_RESPONSE_HEADER_SIZE + TPM_HANDLE_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Load short response",
            ));
        }

        let parsed = LoadResponse::from_bytes(&resp)?;

        Ok(LoadedObject {
            handle: parsed.handles.object_handle,
            name: parsed.parameters.name.0,
        })
    }

    /// Unseals data from a loaded TPM sealed object.
    ///
    /// Retrieves the sensitive data that was previously sealed using the `seal` command.
    /// The object must already be loaded into the TPM using `load`.
    ///
    /// # Arguments
    ///
    /// * `item_handle` - Handle of the loaded sealed object
    /// * `auth_value` - Authorization value for the sealed object (empty slice if none)
    ///
    /// # Returns
    ///
    /// Returns the unsealed data as a `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM command fails or the response is malformed.
    fn unseal(&self, item_handle: u32, auth_value: &[u8]) -> io::Result<Vec<u8>> {
        let cmd_body = UnsealCommand::new(item_handle);
        let handles = cmd_body.handle_values();
        let session_auths: [&[u8]; 1] = [auth_value];
        let cmd =
            build_command_pw_sessions(TpmCommandCode::Unseal, &handles, &session_auths, |b| {
                cmd_body.parameters.marshal(b);
            });

        let resp = self.transmit_raw(&cmd)?;
        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::Unseal)?;
        if resp.len() < 14 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unseal short response",
            ));
        }
        let parsed = UnsealResponse::from_bytes(&resp)?;

        Ok(parsed.parameters.out_data.0)
    }

    /// Seals data under a parent key in the TPM.
    ///
    /// Creates a sealed data object that can only be unsealed by the TPM. The sealed object
    /// is encrypted under the parent key and can optionally be bound to PCR values.
    /// Unlike `create_primary`, this does not load the object into TPM memory - it returns
    /// the encrypted blobs that can be stored externally and loaded later.
    ///
    /// # Arguments
    ///
    /// * `parent_handle` - Handle of the parent key under which to seal the data
    /// * `parent_auth` - Authorization value for the parent key (empty slice if none)
    /// * `data` - The sensitive data to seal (will be encrypted by the TPM)
    /// * `public_template` - Template defining the sealed object's attributes
    /// * `pcrs` - PCR indices to bind the sealed object to (empty slice for no PCR binding)
    ///
    /// # Returns
    ///
    /// Returns a `SealedObject` containing:
    /// - `private` - Marshaled TPM2B_PRIVATE blob (encrypted sensitive data)
    /// - `public` - Marshaled TPM2B_PUBLIC blob (public portion)
    /// - `creation_data` - Metadata about the object creation
    /// - `creation_hash` - Hash of creation data (32 bytes for SHA-256)
    /// - `creation_ticket` - TPM-signed ticket proving object was created by this TPM
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM command fails or the response is malformed.
    fn seal(
        &self,
        parent_handle: u32,
        parent_auth: &[u8],
        data: &[u8],
        public_template: Tpm2bPublic,
        pcrs: &[u32],
    ) -> io::Result<SealedObject> {
        let sensitive = Tpm2b::new(TpmsSensitiveCreate {
            user_auth: Tpm2bBytes(Vec::new()),
            data: Tpm2bBytes(data.to_vec()),
        });

        let parameters = CreateCommandParameters {
            in_sensitive: sensitive,
            in_public: public_template,
            outside_info: Tpm2bBytes(Vec::new()),
            creation_pcr: PcrSelectionList::from_pcrs(pcrs),
        };

        let cmd_body = CreateCommand::new(parent_handle, parameters);
        let handles = cmd_body.handle_values();
        let session_auths: [&[u8]; 1] = [parent_auth];
        let cmd =
            build_command_pw_sessions(TpmCommandCode::Create, &handles, &session_auths, |b| {
                cmd_body.parameters.marshal(b);
            });

        let resp = self.transmit_raw(&cmd)?;

        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::Create)?;

        if resp.len() < 14 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Create short response",
            ));
        }

        let parsed = CreateResponse::from_bytes(&resp)?;

        // Convert the response data to raw bytes for the SealedObject
        let mut private_bytes = Vec::new();
        parsed.parameters.out_private.marshal(&mut private_bytes);

        let mut public_bytes = Vec::new();
        parsed.parameters.out_public.marshal(&mut public_bytes);

        Ok(SealedObject {
            private: private_bytes,
            public: public_bytes,
            creation_data: parsed.parameters.creation_data.0,
            creation_hash: parsed.parameters.creation_hash.0,
            creation_ticket: parsed.parameters.creation_ticket,
        })
    }

    /// Flushes a transient or loaded object handle from the TPM.
    ///
    /// This should be called on any handles returned by `create_primary`, `load`, or other
    /// commands that create transient objects to avoid exhausting TPM handle slots.
    fn flush_context(&self, handle: u32) -> io::Result<()> {
        let cmd_body = FlushContextCommand::new(handle);
        let handles = cmd_body.handle_values();
        let cmd = build_command_no_sessions(TpmCommandCode::FlushContext, &handles, |b| {
            cmd_body.parameters.marshal(b);
        });

        let resp = self.transmit_raw(&cmd)?;
        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::FlushContext)?;
        Ok(())
    }

    fn create_primary_ecc(
        &self,
        hierarchy: Hierarchy,
        public_template: Tpm2bPublicEcc,
    ) -> io::Result<CreatedPrimary> {
        // ECC CreatePrimary: marshal the ECC public template
        let mut template_buf = Vec::new();
        public_template.marshal(&mut template_buf);

        // Build command with marshalled ECC template
        let mut params_buf = Vec::new();
        // in_sensitive (empty)
        empty_sensitive_create().marshal(&mut params_buf);
        // in_public (ECC template)
        params_buf.extend_from_slice(&template_buf);
        // outside_info (empty)
        Tpm2bBytes(Vec::new()).marshal(&mut params_buf);
        // creation_pcr (empty list)
        PcrSelectionList::from_pcrs(&[]).marshal(&mut params_buf);

        let handles = [hierarchy.handle()];
        let cmd = build_command_pw_sessions(TpmCommandCode::CreatePrimary, &handles, &[&[]], |b| {
            b.extend_from_slice(&params_buf);
        });

        let resp = self.transmit_raw(&cmd)?;
        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::CreatePrimary)?;

        if resp.len() < 14 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "CreatePrimary ECC short response",
            ));
        }

        // Parse response: header (10) + handle (4) + paramSize (4) + parameters
        let (header, mut cursor) = crate::tpm::types::TpmResponseHeader::parse(&resp)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "CreatePrimary ECC error 0x{:08x}",
                header.return_code
            )));
        }

        let object_handle = u32::from_be_bytes([
            resp[cursor],
            resp[cursor + 1],
            resp[cursor + 2],
            resp[cursor + 3],
        ]);
        cursor += 4;

        // Skip paramSize
        let _param_size = u32::from_be_bytes([
            resp[cursor],
            resp[cursor + 1],
            resp[cursor + 2],
            resp[cursor + 3],
        ]);
        cursor += 4;

        // Read the outPublic size-prefixed blob
        let out_public_size = u16::from_be_bytes([resp[cursor], resp[cursor + 1]]) as usize;
        let out_public = resp[cursor..cursor + 2 + out_public_size].to_vec();

        Ok(CreatedPrimary {
            handle: object_handle,
            public: out_public,
        })
    }

    fn sign(&self, key_handle: u32, digest: &[u8]) -> io::Result<TpmtSignature> {
        let parameters = SignCommandParameters {
            digest: Tpm2bBytes(digest.to_vec()),
            scheme: TpmtSigScheme::Null, // Use key's default scheme
            validation: TpmtTkHashcheck::null_ticket(),
        };
        let cmd_body = SignCommand::new(key_handle, parameters);
        let handles = cmd_body.handle_values();
        let cmd = build_command_pw_sessions(TpmCommandCode::Sign, &handles, &[&[]], |b| {
            cmd_body.parameters.marshal(b);
        });

        let resp = self.transmit_raw(&cmd)?;
        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::Sign)?;

        let parsed = SignResponse::from_bytes(&resp)?;
        Ok(parsed.parameters.signature)
    }

    fn verify_signature(
        &self,
        key_handle: u32,
        digest: &[u8],
        signature: &TpmtSignature,
    ) -> io::Result<()> {
        let parameters = VerifySignatureCommandParameters {
            digest: Tpm2bBytes(digest.to_vec()),
            signature: signature.clone(),
        };
        let cmd_body = VerifySignatureCommand::new(key_handle, parameters);
        let handles = cmd_body.handle_values();
        let cmd = build_command_no_sessions(TpmCommandCode::VerifySignature, &handles, |b| {
            cmd_body.parameters.marshal(b);
        });

        let resp = self.transmit_raw(&cmd)?;
        parse_tpm_rc_with_cmd(&resp, TpmCommandCode::VerifySignature)?;

        // If we get here without error, the signature is valid
        let _ = VerifySignatureResponse::from_bytes(&resp)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn vtpm_seal_unseal_basic() {
        #[cfg(feature = "vtpm-tests")]
        {
            use super::*;
            use crate::tpm::device::Tpm;

            let tpm = match Tpm::open_reference_for_tests() {
                Ok(t) => t,
                Err(_) => panic!(),
            };

            // Create a primary key to use as parent for sealing
            let auth_policy = [];
            let object_attributes = TpmaObjectBits::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_no_da(true)
                .with_restricted(true)
                .with_decrypt(true);
            let primary_pub = Tpm2b::new(TpmtPublic {
                type_alg: TpmAlgId::Rsa.into(),
                name_alg: TpmAlgId::Sha256.into(),
                object_attributes: object_attributes.into(),
                auth_policy: Tpm2bBytes(auth_policy.to_vec()),
                detail: TpmtPublicDetail::RsaDetail(RsaDetail {
                    symmetric: SymDefObject {
                        alg: TpmAlgId::Aes.into(),
                        key_bits: 128,
                        mode: TpmAlgId::Cfb.into(),
                    },
                    scheme: RsaScheme::Null,
                    key_bits: 2048,
                    exponent: 0,
                }),

                unique: Tpm2bBytes(Vec::new()),
            });
            let pcrs = [];

            let result = tpm.create_primary(Hierarchy::Null, primary_pub, &pcrs);
            assert!(result.is_ok());
            let created_primary = result.unwrap();

            // Test data to seal
            let test_data = b"This is secret data that should be sealed";

            // Create a simple data object template for sealing
            // Use a proper keyedHashObject template designed for sealing
            let object_attributes = TpmaObjectBits::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_user_with_auth(true)
                .with_no_da(true);
            let seal_template = Tpm2b::new(TpmtPublic {
                type_alg: TpmAlgId::KeyedHash.into(),
                name_alg: TpmAlgId::Sha256.into(),
                object_attributes: object_attributes.into(),
                auth_policy: Tpm2bBytes(auth_policy.to_vec()),
                detail: TpmtPublicDetail::KeyedHashDetail(KeyedHashDetail {
                    scheme: KeyedHashScheme::Null,
                    hash_alg: TpmAlgId::Null,
                }),
                unique: Tpm2bBytes(Vec::new()),
            });

            // Test seal operation
            let result = tpm.seal(
                created_primary.handle,
                &auth_policy,
                test_data,
                seal_template,
                &[],
            );
            assert!(result.is_ok());
            let sealed_object = result.unwrap();

            assert!(
                !sealed_object.private.is_empty(),
                "Sealed private data should not be empty"
            );
            assert!(
                !sealed_object.public.is_empty(),
                "Sealed public data should not be empty"
            );

            // Verify that creation_data, creation_hash, and creation_ticket are populated
            assert!(
                !sealed_object.creation_data.is_empty(),
                "Creation data should not be empty"
            );
            assert!(
                sealed_object.creation_hash.len() == 32,
                "Creation hash should be 32 bytes (SHA-256)"
            );
            assert!(
                !sealed_object.creation_ticket.is_empty(),
                "Creation ticket should not be empty"
            );

            // Test that we can load the sealed object and then unseal it
            let result = tpm.load(
                created_primary.handle,
                &auth_policy,
                &sealed_object.private,
                &sealed_object.public,
            );
            assert!(result.is_ok());
            let loaded_object = result.unwrap();

            // Now try to unseal the data
            let result = tpm.unseal(loaded_object.handle, &[]);
            assert!(result.is_ok());
            let unsealed_data = result.unwrap();

            assert_eq!(
                unsealed_data, test_data,
                "Unsealed data should match original test data"
            );
        }
    }
}

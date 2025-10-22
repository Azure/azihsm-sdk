// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Manticore API
//!
//! This crate provides the Manticore API for Rust.
//!

mod error;

use std::sync::Arc;

use attestation::attestation::KeyAttester;
use attestation::error::AttestationError;
use crypto::cert::der_to_pem;
use crypto::ecc::EccOp;
use crypto::ecc::EccPublicKey;
use crypto::ecc::EccPublicOp;
use crypto::rsa::RsaOp;
use crypto::rsa::RsaPublicKey;
use crypto::rsa::RsaPublicOp;
use crypto::sha::HashAlgorithm;
use crypto::CryptoError;
use crypto::CryptoHashAlgorithm;
use crypto::CryptoKeyKind;
use crypto::CryptoRsaCryptoPadding;
use crypto::CryptoRsaSignaturePadding;
pub use error::HsmError;
use mcr_ddi::Ddi;
use mcr_ddi::DdiAesGcmParams;
use mcr_ddi::DdiAesXtsParams;
use mcr_ddi::DdiDev;
use mcr_ddi::DevInfo;
// use mcr_ddi_serde::report::REPORT_DATA_SIZE;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use parking_lot::RwLock;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;
use session_parameter_encryption::DeviceCredentialEncryptionKey;
use tracing::instrument;
use uuid::uuid;
use uuid::Uuid;
use x509::X509Certificate;
use x509::X509CertificateOp;

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        type HsmDdi = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        type HsmDdi = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        type HsmDdi = mcr_ddi_win::DdiWin;
    }
}

/// HSM Result
pub type HsmResult<T> = Result<T, HsmError>;

/// HSM Device Information
pub type HsmDevInfo = DevInfo;

/// Default Vault ID
pub const DEFAULT_VAULT_ID: Uuid = uuid!("E01D5EA3-6451-439D-A55C-23DED856EFA3");

/// Size of BK3 in bytes
const BK3_SIZE: usize = 48;

/// Size limit of sealed BK3 in bytes
const SEALED_BK3_SIZE: usize = 512;

/// Size of the report data.
const REPORT_DATA_SIZE: usize = 128;

const ALLOWED_DIGEST_LENGTHS: [usize; 4] = [
    20, // SHA1
    32, // SHA256
    48, // SHA384
    64, // SHA512
];

/// HSM API Revision Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HsmApiRevision {
    /// Major version
    pub major: u32,

    /// Minor version
    pub minor: u32,
}

impl PartialOrd for HsmApiRevision {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.major == other.major {
            // If major versions are equal, compare minor versions
            self.minor.partial_cmp(&other.minor)
        } else {
            // Otherwise, compare major versions
            self.major.partial_cmp(&other.major)
        }
    }
}

/// HSM API Revision Range Structure
#[derive(Clone, Copy, Debug)]
pub struct HsmApiRevisionRange {
    /// Minimum Supported API Revision
    pub min: HsmApiRevision,

    /// Maximum Supported API Revision
    pub max: HsmApiRevision,
}

/// HSM Device Info Structure
#[derive(Clone, Copy, Debug)]
pub struct HsmDeviceInfo {
    /// Device Kind
    pub kind: DeviceKind,
    /// Number of tables assigned to the device
    pub tables: u8,
}

/// HSM Application Credentials
#[derive(Clone, Copy)]
pub struct HsmAppCredentials {
    /// Application ID
    pub id: Uuid,

    /// Application PIN
    pub pin: [u8; 16],
}

/// HSM Device
#[derive(Debug)]
pub struct HsmDevice {
    inner: Arc<RwLock<HsmDeviceInner>>,
}

impl HsmDevice {
    /// Returns the HSM device list
    ///
    /// # Returns
    /// * `Vec<HsmDevInfo>` - HSM device list
    pub fn get_devices() -> Vec<HsmDevInfo> {
        let ddi = HsmDdi::default();
        let devices = ddi.dev_info_list();

        tracing::debug!(?devices, "Got HsmDevice list");
        devices
    }

    /// Open HSM device
    ///
    /// # Arguments
    /// `path` - Device path
    ///
    /// # Returns
    /// `Self` - HSM Device Instance
    #[instrument]
    pub fn open(path: &str) -> HsmResult<Self> {
        // Log device opening at the INFO level. This is is intentionally left
        // at INFO level as a way to measure how much usage AzIHSM is getting
        tracing::info!("Opening new HsmDevice");
        let ddi = HsmDdi::default();

        let mut dev = ddi.open_dev(path)?;

        let req = DdiGetApiRevCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetApiRev,
                sess_id: None,
                rev: None,
            },
            data: DdiGetApiRevReq {},
            ext: None,
        };

        let mut cookie = None;

        let resp = dev.exec_op(&req, &mut cookie)?;
        let api_rev = DdiApiRev { major: 1, minor: 0 };

        let req = DdiGetDeviceInfoCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetDeviceInfo,
                sess_id: None,
                rev: Some(api_rev),
            },
            data: DdiGetDeviceInfoReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp_info = dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done opening new HsmDevice");

        dev.set_device_kind(resp_info.data.kind);

        Ok(Self {
            inner: Arc::new(RwLock::new(HsmDeviceInner {
                dev,
                api_rev_range: HsmApiRevisionRange {
                    min: HsmApiRevision {
                        major: resp.data.min.major,
                        minor: resp.data.min.minor,
                    },
                    max: HsmApiRevision {
                        major: resp.data.max.major,
                        minor: resp.data.max.minor,
                    },
                },
                device_info: HsmDeviceInfo {
                    kind: resp_info.data.kind.try_into()?,
                    tables: resp_info.data.tables,
                },
                session_open: false,
            })),
        })
    }

    /// Get HSM API Revision Range from cache
    ///
    /// # Returns
    /// `HsmApiRevisionRange` - HSM API Revision Range from cache
    pub fn get_api_revision_range(&self) -> HsmApiRevisionRange {
        self.inner.read().get_api_revision_range()
    }

    /// Get DDI device info from cache
    ///
    /// # Returns
    /// `HsmDeviceInfo` - HSM API device info from cache
    pub fn get_device_info(&self) -> HsmDeviceInfo {
        self.inner.read().get_device_info()
    }

    /// Establish Credentials
    ///
    /// # Arguments
    /// `api_rev` - API Revision for the session
    /// `credentials` - Application Credentials
    /// `masked_bk3` - Masked BK3 data
    /// `bmk` - Optional BMK data
    /// `masked_unwrapping_key` - Optional masked unwrapping key data
    ///
    /// # Returns
    /// `HsmResult`
    /// Ok(bmk) - on success
    /// else ddi error
    #[instrument(skip_all)]
    pub fn establish_credential(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
        masked_bk3: Vec<u8>,
        bmk: Option<Vec<u8>>,
        masked_unwrapping_key: Option<Vec<u8>>,
    ) -> HsmResult<Vec<u8>> {
        // Log credential establishing at the INFO level. This is is
        // intentionally left at INFO level as a way to measure how much usage
        // AzIHSM is getting
        tracing::info!("Establishing credential");

        self.inner.write().establish_credential(
            api_rev,
            credentials,
            masked_bk3,
            bmk,
            masked_unwrapping_key,
        )
    }

    /// Open Application Session
    ///
    /// # Arguments
    /// `api_rev` - API Revision for the session
    /// `credentials` - Application Credentials
    /// `kind` - Application Session Kind
    ///
    /// # Returns
    /// `HsmSession` - Application Session
    #[instrument(skip_all)]
    pub fn open_session(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<HsmSession> {
        // Log app session opening at the INFO level. This is is intentionally
        // left at INFO level as a way to measure how much usage AzIHSM is
        // getting
        tracing::info!("Opening App Session");

        let device = self.inner.clone();

        self.inner
            .write()
            .open_session(device, api_rev, credentials)
    }

    /// Initialize BK3 for device with custom data
    ///
    /// # Arguments
    /// * `api_rev` - API Revision for the transaction
    /// * `bk3_data` - The BK3 data to initialize
    ///
    /// # Returns
    /// * `Vec<u8>` - The masked BK3 data returned by the device
    ///
    /// # Errors
    /// DDI errors
    #[instrument(skip_all)]
    pub fn init_bk3(&self, api_rev: HsmApiRevision, bk3_data: &[u8]) -> HsmResult<Vec<u8>> {
        self.inner.write().init_bk3(api_rev, bk3_data)
    }

    /// Set the sealed BK3 data on the device
    /// for later use during partition provisioning.
    ///
    /// # Arguments
    /// * `api_rev` - API Revision for the transaction
    /// * `sealed_bk3` - The sealed BK3 data to store
    ///
    /// # Errors
    /// DDI errors
    #[instrument(skip_all)]
    pub fn set_sealed_bk3(&self, api_rev: HsmApiRevision, sealed_bk3: &[u8]) -> HsmResult<()> {
        self.inner.write().set_sealed_bk3(api_rev, sealed_bk3)
    }

    /// Get the sealed BK3 data from the device
    /// This retrieves the sealed BK3 data that was previously stored.
    ///
    /// # Arguments
    /// * `api_rev` - API Revision for the transaction
    ///
    /// # Returns
    /// * `Vec<u8>` - The sealed BK3 data
    ///
    /// # Errors
    /// DDI errors
    #[instrument(skip_all)]
    pub fn get_sealed_bk3(&self, api_rev: HsmApiRevision) -> HsmResult<Vec<u8>> {
        self.inner.read().get_sealed_bk3(api_rev)
    }
}

#[derive(Debug)]
struct HsmDeviceInner {
    /// Device
    dev: <HsmDdi as Ddi>::Dev,

    /// HSM API Revision Range
    api_rev_range: HsmApiRevisionRange,

    /// ddi device info
    device_info: HsmDeviceInfo,

    /// Only one session can be open at a time per device handle.
    session_open: bool,
}

impl Drop for HsmDeviceInner {
    fn drop(&mut self) {
        tracing::debug!("Dropping HsmDeviceInner");
        if self.session_open {
            tracing::error!("HsmDeviceInner Session not closed before dropping");
            panic!("Session not closed. Is there a bug?")
        }
    }
}

impl HsmDeviceInner {
    fn get_api_revision_range(&self) -> HsmApiRevisionRange {
        self.api_rev_range
    }

    fn get_device_info(&self) -> HsmDeviceInfo {
        self.device_info
    }

    /// Helper method to get session encryption key and encrypt credentials
    /// Returns the encrypted credential and public key for session operations
    fn prepare_session_encrypted_credentials(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
        session_seed: [u8; 48],
    ) -> HsmResult<(DdiEncryptedSessionCredential, DdiDerPublicKey)> {
        tracing::debug!("Getting session encryption key");
        let mut cookie = None;
        let req = DdiGetSessionEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetSessionEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: api_rev.major,
                    minor: api_rev.minor,
                }),
            },
            data: DdiGetSessionEncryptionKeyReq {},
            ext: None,
        };
        let resp = self.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done getting session encryption key");

        let nonce = resp.data.nonce;
        let param_encryption_key = DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce)?;
        tracing::debug!("Generating ephemeral encryption key");
        let (priv_key, ddi_public_key) =
            param_encryption_key.generate_ephemeral_encryption_key()?;

        let ddi_encrypted_credential = priv_key.encrypt_session_credential(
            credentials.id.into_bytes(),
            credentials.pin,
            session_seed,
            nonce,
        )?;

        Ok((ddi_encrypted_credential, ddi_public_key))
    }

    fn establish_credential(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
        masked_bk3: Vec<u8>,
        bmk: Option<Vec<u8>>,
        masked_unwrapping_key: Option<Vec<u8>>,
    ) -> HsmResult<Vec<u8>> {
        if api_rev < self.api_rev_range.min || api_rev > self.api_rev_range.max {
            tracing::error!(error = ?HsmError::InvalidApiRevision, api_rev = ?api_rev, supported = ?self.api_rev_range, "api_rev is not supported");
            return Err(HsmError::InvalidApiRevision);
        }

        tracing::debug!("Getting EstablishCredEncryptionKey");
        let mut cookie = None;
        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: api_rev.major,
                    minor: api_rev.minor,
                }),
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };

        let resp = self.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done getting EstablishCredEncryptionKey");

        let nonce = resp.data.nonce;
        let param_encryption_key = DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce)?;
        tracing::debug!("Generating ephemeral encryption key");
        let (priv_key, ddi_public_key) =
            param_encryption_key.generate_ephemeral_encryption_key()?;

        let ddi_encrypted_credential = priv_key.encrypt_establish_credential(
            credentials.id.into_bytes(),
            credentials.pin,
            nonce,
        )?;

        let bmk = bmk.unwrap_or_default(); // Empty BMK if not provided
        let masked_unwrapping_key = masked_unwrapping_key.unwrap_or_default(); // Empty masked unwrapping key if not provided
        tracing::debug!("Sending Establish Credential Command");
        let req = DdiEstablishCredentialCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::EstablishCredential,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: api_rev.major,
                    minor: api_rev.minor,
                }),
            },
            data: DdiEstablishCredentialReq {
                encrypted_credential: ddi_encrypted_credential,
                pub_key: ddi_public_key,
                masked_bk3: MborByteArray::from_slice(&masked_bk3)
                    .expect("Failed to create masked BK3 byte array"),
                bmk: MborByteArray::from_slice(&bmk).expect("Failed to create BMK byte array"),
                masked_unwrapping_key: MborByteArray::from_slice(&masked_unwrapping_key)
                    .expect("Failed to create empty masked unwrapping key"),
            },
            ext: None,
        };

        let mut cookie = None;
        let resp = self.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done establishing credential");

        let bmk = resp.data.bmk.as_slice().to_vec();

        Ok(bmk)
    }

    fn open_session(
        &mut self,
        device: Arc<RwLock<HsmDeviceInner>>,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<HsmSession> {
        if self.session_open {
            tracing::error!(
                error = ?HsmError::OnlyOneSessionAllowedPerDeviceHandle,
                "Session is already open, cannot open again"
            );
            return Err(HsmError::OnlyOneSessionAllowedPerDeviceHandle);
        }

        if api_rev < self.api_rev_range.min || api_rev > self.api_rev_range.max {
            tracing::error!(error = ?HsmError::InvalidApiRevision, api_rev = ?api_rev, supported = ?self.api_rev_range, "api_rev is not supported");
            return Err(HsmError::InvalidApiRevision);
        }

        let mut session_seed = [0u8; 48];
        crypto::rand::rand_bytes(&mut session_seed).map_err(|err| {
            tracing::error!("crypto::rand_bytes failure {:?}", err);
            HsmError::InternalError
        })?;

        let (ddi_encrypted_credential, ddi_public_key) =
            self.prepare_session_encrypted_credentials(api_rev, credentials, session_seed)?;

        tracing::debug!("Sending Open Session command");
        let req = DdiOpenSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::OpenSession,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: api_rev.major,
                    minor: api_rev.minor,
                }),
            },
            data: DdiOpenSessionReq {
                encrypted_credential: ddi_encrypted_credential,
                pub_key: ddi_public_key,
            },
            ext: None,
        };

        let mut cookie = None;
        let resp = self.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done open session command");

        let session = HsmSession::new(
            device,
            api_rev,
            credentials.id,
            resp.data.short_app_id,
            resp.data.sess_id,
            session_seed,
            resp.data.bmk_session.as_slice().to_vec(),
        );
        self.session_open = true;

        Ok(session)
    }

    fn init_bk3(&mut self, api_rev: HsmApiRevision, bk3_data: &[u8]) -> HsmResult<Vec<u8>> {
        if bk3_data.len() != BK3_SIZE {
            tracing::error!(
                expected = BK3_SIZE,
                actual = bk3_data.len(),
                "BK3 data exceeds maximum size"
            );
            return Err(HsmError::InvalidParameter);
        }

        let bk3_mbor = MborByteArray::new(bk3_data.try_into().unwrap(), BK3_SIZE)
            .map_err(|_| HsmError::MborEncodeFailed)?;

        let api_rev = DdiApiRev {
            major: api_rev.major,
            minor: api_rev.minor,
        };

        let req = DdiInitBk3CmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::InitBk3,
                sess_id: None,
                rev: Some(api_rev),
            },
            data: DdiInitBk3Req { bk3: bk3_mbor },
            ext: None,
        };

        let mut cookie = None;
        let init_result = self.dev.exec_op(&req, &mut cookie)?;

        tracing::debug!("BK3 initialization completed successfully");

        Ok(init_result.data.masked_bk3.as_slice().to_vec())
    }

    fn set_sealed_bk3(&mut self, api_rev: HsmApiRevision, sealed_bk3: &[u8]) -> HsmResult<()> {
        if sealed_bk3.len() > SEALED_BK3_SIZE {
            tracing::error!(
                expected_max = SEALED_BK3_SIZE,
                actual = sealed_bk3.len(),
                "Invalid sealed BK3 size"
            );
            return Err(HsmError::InvalidParameter);
        }
        let api_rev = DdiApiRev {
            major: api_rev.major,
            minor: api_rev.minor,
        };

        let set_sealed_req = DdiSetSealedBk3CmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::SetSealedBk3,
                sess_id: None,
                rev: Some(api_rev),
            },
            data: DdiSetSealedBk3Req {
                sealed_bk3: MborByteArray::from_slice(sealed_bk3)
                    .map_err(|_| HsmError::MborEncodeFailed)?,
            },
            ext: None,
        };

        let mut cookie = None;
        self.dev.exec_op(&set_sealed_req, &mut cookie)?;

        tracing::debug!("Sealed BK3 stored successfully");
        Ok(())
    }

    fn get_sealed_bk3(&self, api_rev: HsmApiRevision) -> HsmResult<Vec<u8>> {
        tracing::debug!("Getting sealed BK3 data from device");

        let api_rev = DdiApiRev {
            major: api_rev.major,
            minor: api_rev.minor,
        };

        let get_sealed_req = DdiGetSealedBk3CmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetSealedBk3,
                sess_id: None,
                rev: Some(api_rev),
            },
            data: DdiGetSealedBk3Req {},
            ext: None,
        };

        let mut cookie = None;
        let resp = self.dev.exec_op(&get_sealed_req, &mut cookie)?;

        tracing::debug!("Sealed BK3 retrieved successfully");
        Ok(resp.data.sealed_bk3.as_slice().to_vec())
    }
}

/// HSM Key Handle Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone)]
pub struct HsmKeyHandle {
    /// Key ID
    id: u16,

    /// Key Type
    kind: KeyType,

    /// DER encoded public key
    pub_key: Option<Vec<u8>>,

    /// bulk_key_id
    bulk_key_id: Option<u16>,

    /// Blob that contains current key in a encrypted format
    masked_key: Option<Vec<u8>>,
}

impl HsmKeyHandle {
    /// Get Key ID
    pub(crate) fn id(&self) -> u16 {
        self.id
    }

    // /// Get Key Tag
    // pub(crate) fn name(&self) -> u16 {
    //     self.name
    // }

    /// Get Key Type
    pub fn kind(&self) -> KeyType {
        self.kind
    }

    /// Get Masked Key
    pub fn masked_key(&self) -> Option<&[u8]> {
        self.masked_key.as_deref()
    }
}

/// Certificate returned by the Manticore device
#[derive(Debug)]
pub enum ManticoreCertificate {
    /// Represents certificates from a physical Manticore device.
    /// Contains array of PEM encoded certificate, concatenated by '\n'
    PhysicalManticore(Vec<u8>),

    /// Represents collateral from an virtual Manticore device.
    VirtualManticore {
        /// Attestation Key Cert
        /// PEM format
        ak_cert: Vec<u8>,
        /// The cert chain for TEE
        /// TODO: Collateral support for virtual device is pending
        tee_cert_chain: Vec<u8>,
        /// The TEE Report
        /// TODO: Collateral support for virtual device is pending
        tee_report: Vec<u8>,
    },
}

/// HSM Application Session Structure

#[derive(Debug)]
pub struct HsmSession {
    /// Device
    device_inner: Arc<RwLock<HsmDeviceInner>>,

    /// API Revision
    api_rev: HsmApiRevision,

    /// Application ID
    app_id: Uuid,

    /// Short Application ID
    short_app_id: u8,

    /// Session ID
    session_id: u16,

    /// Session seed
    session_seed: [u8; 48],

    /// Session bmk
    session_bmk: Vec<u8>,

    /// Session successfully closed flag
    closed: bool,
}

impl Drop for HsmSession {
    fn drop(&mut self) {
        tracing::debug!(session_id = self.session_id, "Dropping HsmSession");
        // Call close session and ignore any errors. The errors can be that the session is already closed which means
        // that we don't need to do anything. Or we can get an error that the session could not be closed.
        // If the session could not be closed, we expect the client to retry but the object is about to be dropped so
        // we can't retry anymore. We will depend on the hardware to clean up the session as we cannot do anything
        // else.
        if let Err(error) = self.close_session() {
            tracing::warn!(
                ?error,
                session_id = self.session_id,
                "Ignored error while closing HsmSession"
            );
        }

        // Session object is about to be dropped. If the above close_session() has failed then session_open would still
        // be true. This would mean we cannot attempt opening a new session using the device handle. However, the hardware
        // will clean up the session eventually. So we can safely set session_open to false here. This allows us to open a new
        // session. The hardware will only allow the session to be opened if the limit of the session hasn't been reached.
        self.device_inner.write().session_open = false;
    }
}

impl HsmSession {
    fn new(
        device: Arc<RwLock<HsmDeviceInner>>,
        api_rev: HsmApiRevision,
        app_id: Uuid,
        short_app_id: u8,
        session_id: u16,
        session_seed: [u8; 48],
        session_bmk: Vec<u8>,
    ) -> Self {
        tracing::debug!(session_id, "Creating new HsmSession");
        Self {
            device_inner: device,
            api_rev,
            app_id,
            short_app_id,
            session_id,
            session_seed,
            session_bmk,
            closed: false,
        }
    }

    /// Get Application ID for the current session
    pub fn app_id(&self) -> Uuid {
        self.app_id
    }

    /// Returns the length of the hash corresponding to the provided `DigestKind`.
    fn hash_len(digest: DigestKind) -> usize {
        match digest {
            DigestKind::Sha1 => 20,
            DigestKind::Sha256 => 32,
            DigestKind::Sha384 => 48,
            DigestKind::Sha512 => 64,
        }
    }

    /// Change User PIN
    ///
    /// # Arguments
    /// * `new_pin` - New User PIN
    ///
    /// # Errors
    /// `HsmError::SessionClosed` - Session is closed.
    #[instrument(skip_all, fields(sess_id = self.session_id))]
    pub fn change_pin(&self, new_pin: [u8; 16]) -> HsmResult<()> {
        tracing::debug!("Changing User PIN");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "change_pin failed: User Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let mut cookie = None;
        let req = DdiGetSessionEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetSessionEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiGetSessionEncryptionKeyReq {},
            ext: None,
        };
        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;

        let nonce = resp.data.nonce;
        let param_encryption_key = DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce)?;
        tracing::debug!("Generating ephemeral encryption key");
        let (priv_key, ddi_public_key) =
            param_encryption_key.generate_ephemeral_encryption_key()?;

        let encrypted_pin = priv_key.encrypt_pin(new_pin, nonce)?;

        let req = DdiChangePinCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::ChangePin,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiChangePinReq {
                new_pin: encrypted_pin,
                pub_key: ddi_public_key,
            },
            ext: None,
        };

        let mut cookie = None;

        read_locked_device.dev.exec_op(&req, &mut cookie)?;

        tracing::debug!("Done changing User PIN");

        Ok(())
    }

    /// Close Application Session
    ///
    /// # Errors
    /// `HsmError::SessionClosed` - Session is closed.
    /// DDI errors
    #[instrument(skip_all, fields(sess_id = self.session_id))]
    pub fn close_session(&mut self) -> HsmResult<()> {
        tracing::debug!("Closing App Session");
        let mut write_locked_device = self.device_inner.write();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "close_session failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let req = DdiCloseSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::CloseSession,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiCloseSessionReq {},
            ext: None,
        };

        let mut cookie = None;

        write_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done closing app session");

        write_locked_device.session_open = false;
        self.closed = true;

        Ok(())
    }

    /// Reopen session after live migration
    ///
    /// This method attempts to reopen a session that has become invalid due to live migration.
    /// The caller must have already re-established credentials on the device before calling this method.
    ///
    /// # Arguments
    /// * `credentials` - Application credentials for reopening
    ///
    /// # Errors
    /// `HsmError::SessionClosed` - Session is closed.
    /// DDI errors
    #[instrument(skip_all, fields(sess_id = self.session_id))]
    pub fn reopen(&self, credentials: HsmAppCredentials) -> HsmResult<()> {
        tracing::debug!("Reopening session after live migration");
        let write_locked_device = self.device_inner.write();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "reopen_session failed: Session already closed");
            return Err(HsmError::SessionClosed);
        }

        let (ddi_encrypted_credential, ddi_public_key) = write_locked_device
            .prepare_session_encrypted_credentials(self.api_rev, credentials, self.session_seed)?;

        // Send reopen session command
        tracing::debug!("Sending Reopen Session command");
        let req = DdiReopenSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::ReopenSession,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiReopenSessionReq {
                encrypted_credential: ddi_encrypted_credential,
                pub_key: ddi_public_key,
                bmk_session: MborByteArray::from_slice(&self.session_bmk)
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;
        let resp = write_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done reopening session");

        // Verify session ID matches
        if resp.data.sess_id != self.session_id {
            tracing::error!(
                expected_session_id = self.session_id,
                actual_session_id = resp.data.sess_id,
                "Reopened session ID mismatch"
            );
            return Err(HsmError::InternalError);
        }

        Ok(())
    }

    /// Clear Device
    ///
    /// # Errors
    /// `HsmError::SessionClosed` - Session is closed.
    /// DDI errors
    #[instrument(skip_all, fields(sess_id = self.session_id))]
    pub fn clear_device(&mut self) -> HsmResult<()> {
        tracing::debug!("Clearing Device");
        let mut write_locked_device = self.device_inner.write();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "clear_device failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let req = DdiResetFunctionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::ResetFunction,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiResetFunctionReq {},
            ext: None,
        };

        let mut cookie = None;

        write_locked_device.dev.exec_op(&req, &mut cookie)?;

        write_locked_device.session_open = false;
        self.closed = true;

        Ok(())
    }

    /// Open Key by Tag
    /// Only app  keys are allowed to be opened by tag.
    /// The tag must be 2 bytes in length and cannot be 0.
    /// It must also be unique for the application within the vault.
    ///
    /// # Arguments
    /// * `key_tag` - Key Tag
    ///
    /// # Returns
    /// * `HsmKeyHandle` - Key Handle
    ///
    /// # Errors
    /// `HsmError::SessionClosed` - Session is closed.
    /// `HsmError::InvalidParameter` - Key tag is invalid.
    #[instrument(skip(self), fields(sess_id = self.session_id))]
    pub fn open_key(&self, key_tag: u16) -> HsmResult<HsmKeyHandle> {
        tracing::debug!(key_tag, "Opening Key by tag");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "open_key failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        if key_tag == 0 {
            tracing::error!(error = ?HsmError::InvalidParameter, key_tag, "open_key failed: Key tag is invalid");
            Err(HsmError::InvalidParameter)?
        }

        let req = DdiOpenKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::OpenKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiOpenKeyReq { key_tag },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done opening key by tag");

        let pub_key = resp
            .data
            .pub_key
            .map(|resp_pub_key| resp_pub_key.der.as_slice().to_vec());

        Ok(HsmKeyHandle {
            id: resp.data.key_id,
            kind: resp.data.key_kind.try_into()?,
            pub_key,
            bulk_key_id: resp.data.bulk_key_id,
            masked_key: None, // Masked key is not returned in this operation
        })
    }

    /// Delete Key
    ///
    /// # Arguments
    /// * `key_id` - Key ID
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn delete_key(&self, key: &HsmKeyHandle) -> HsmResult<()> {
        tracing::debug!("Deleting Key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "delete_key failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let req = DdiDeleteKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::DeleteKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiDeleteKeyReq { key_id: key.id() },
            ext: None,
        };

        let mut cookie = None;

        read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done deleting key");

        Ok(())
    }

    /// Export Public Key
    ///
    /// # Arguments
    /// * `key` - Key Handle
    ///
    /// # Returns
    /// * `Vec<u8>` - Public Key in DER format
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn export_public_key(&self, key: &HsmKeyHandle) -> HsmResult<Vec<u8>> {
        tracing::debug!("Exporting Public Key");
        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "Cannot export pub key: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        key.pub_key.clone().ok_or(HsmError::InvalidKeyType)
    }

    /// Perform RSA Unwrap on the wrapped blob using the import key.
    ///
    /// # Arguments
    /// * `import_key` - Import Key Handle
    /// * `wrapped_blob` - Wrapped Blob
    /// * `wrapped_blob_key_type` - Wrapped Blob Key Type
    /// * `wrapped_blob_padding` - Wrapped Blob Padding
    /// * `wrapped_blob_hash_algorithm` - Wrapped Blob Hash Algorithm
    /// * `target_key_flags` - Target Key Flags
    /// * `target_key_tag` - Target Key Tag
    ///
    /// # Returns
    /// * `HsmKeyHandle` - Unwrapped Key Handle
    #[instrument(skip_all, fields(sess_id = self.session_id, import_key = import_key.id(), ?target_key_tag))]
    pub fn rsa_unwrap(
        &self,
        import_key: &HsmKeyHandle,
        wrapped_blob: Vec<u8>,
        wrapped_blob_params: RsaUnwrapParams,
        target_key_tag: Option<u16>,
        target_key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        tracing::debug!(import_key_kind = ?import_key.kind(), wrapped_blob_class = ?wrapped_blob_params.key_class, ?target_key_properties, "Performing RSA Unwrap");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "rsa_unwrap failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        if import_key.kind() != KeyType::Rsa2kPrivate
            && import_key.kind() != KeyType::Rsa3kPrivate
            && import_key.kind() != KeyType::Rsa4kPrivate
            && import_key.kind() != KeyType::Rsa2kPrivateCrt
            && import_key.kind() != KeyType::Rsa3kPrivateCrt
            && import_key.kind() != KeyType::Rsa4kPrivateCrt
        {
            tracing::error!(error = ?HsmError::InvalidKeyType, key_id = import_key.id(), "Key type is not RSA private");
            Err(HsmError::InvalidKeyType)?
        }

        let wrapped_blob_padding = match wrapped_blob_params.padding {
            RsaCryptoPadding::Oaep => DdiRsaCryptoPadding::Oaep,
        };

        let target_key_properties: DdiKeyProperties = target_key_properties.into();

        let req = DdiRsaUnwrapCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::RsaUnwrap,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiRsaUnwrapReq {
                key_id: import_key.id(),
                wrapped_blob: MborByteArray::from_slice(&wrapped_blob)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                wrapped_blob_key_class: wrapped_blob_params.key_class.into(),
                wrapped_blob_padding,
                wrapped_blob_hash_algorithm: wrapped_blob_params.hash_algorithm.into(),
                key_tag: target_key_tag,
                key_properties: target_key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!(key_id = resp.data.key_id, "Done RSA Unwrap");

        let data = resp.data;

        let pub_key = data
            .pub_key
            .map(|resp_pub_key| resp_pub_key.der.as_slice().to_vec());

        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: data.kind.try_into()?,
            pub_key,
            bulk_key_id: data.bulk_key_id,
            masked_key: Some(masked_key),
        })
    }

    /// RSA Encrypt using Public Key
    ///
    /// # Arguments
    /// * `key` - Private Key Handle, it must include a valid public key
    /// * `data` - Data to encrypt
    /// * `padding` - Padding type
    /// * `hash_algorithm` - Hash algorithm
    ///
    /// # Returns
    /// * `Vec<u8>` - Encrypted data
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - If the current App Session is closed.
    /// * `HsmError::InvalidParameter` - If the handle does not contain a valid public key, or data length exceeds limit.
    /// * `HsmError::InvalidKeyType` - If the Key type is not RSA public.
    /// * `HsmError::RsaFromDerError` - If fail to convert key handle to RSA Key.
    /// * `HsmError::DerAndKeyTypeMismatch` - If the handle's key and type mismatch.
    /// * `HsmError::RsaEncryptFailed` - If the encryption fails.
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn rsa_encrypt(
        &self,
        key: &HsmKeyHandle,
        data: Vec<u8>,
        padding: RsaCryptoPadding,
        hash_algorithm: Option<DigestKind>,
        label: Option<&[u8]>,
    ) -> HsmResult<Vec<u8>> {
        tracing::debug!(?padding, ?hash_algorithm, "Performing RSA Encrypt");

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "rsa_encrypt failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let (pub_key_kind, max_len) = match key.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => (KeyType::Rsa2kPublic, 256),
            KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => (KeyType::Rsa3kPublic, 384),
            KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => (KeyType::Rsa4kPublic, 512),
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not RSA Public or Private");
                Err(HsmError::InvalidKeyType)?
            }
        };

        if data.len() > max_len {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), len = data.len(), "Data length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        let der = key.pub_key.as_ref().ok_or_else(|| {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), "Public Key is required but missing");
            HsmError::InvalidParameter
        })?;

        let rsa_public_key = RsaPublicKey::from_der(der, Some(pub_key_kind.into()))?;
        let result = rsa_public_key.encrypt(
            &data,
            padding.into(),
            hash_algorithm.map(|kind| kind.into()),
            label,
        )?;

        tracing::debug!("Done RSA Encrypt");
        Ok(result)
    }

    /// RSA Decrypt using Private Key
    ///
    /// # Arguments
    /// * `data` - Data to decrypt
    /// * `key` - Private Key Handle
    /// * `padding` - Padding type
    /// * `hash_algorithm` - Hash algorithm
    ///
    /// # Returns
    /// * `Vec<u8>` - Decrypted data
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn rsa_decrypt(
        &self,
        key: &HsmKeyHandle,
        data: Vec<u8>,
        padding: RsaCryptoPadding,
        hash_algorithm: Option<DigestKind>,
        label: Option<&[u8]>,
    ) -> HsmResult<Vec<u8>> {
        tracing::debug!(?padding, ?hash_algorithm, "Performing RSA Decrypt");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "rsa_decrypt failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let expected_data_len: usize = match key.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => 256,
            KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => 384,
            KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => 512,
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not RSA private");
                Err(HsmError::InvalidKeyType)?
            }
        };

        if data.len() != expected_data_len {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), actual = data.len(), expected = expected_data_len, "Data length unexpected");
            Err(HsmError::InvalidParameter)?
        }

        let req = DdiRsaModExpCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::RsaModExp,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiRsaModExpReq {
                key_id: key.id(),
                y: MborByteArray::from_slice(&data)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                op_type: DdiRsaOpType::Decrypt,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done RSA Decrypt");

        let mut padded_data = [0u8; 512];
        padded_data[..resp.data.x.len()].copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

        let hash_algorithm = hash_algorithm.unwrap_or(DigestKind::Sha256);

        let unpadded_data = match padding {
            RsaCryptoPadding::Oaep => RsaEncoding::decode_oaep(
                &mut padded_data[..resp.data.x.len()],
                label,
                data.len(),
                hash_algorithm.into(),
                Self::hash_fn(hash_algorithm.into()),
            )
            .map_err(|_| {
                tracing::error!(error = ?HsmError::RsaDecryptFailed, ?hash_algorithm, "Failed to decode OAEP");
                HsmError::RsaDecryptFailed
            })?,
        };

        Ok(unpadded_data)
    }

    fn crypto_sha1(data: &[u8]) -> Vec<u8> {
        crypto::sha::sha(HashAlgorithm::Sha1, data).unwrap_or_default()
    }
    fn crypto_sha256(data: &[u8]) -> Vec<u8> {
        crypto::sha::sha(HashAlgorithm::Sha256, data).unwrap_or_default()
    }

    fn crypto_sha384(data: &[u8]) -> Vec<u8> {
        crypto::sha::sha(HashAlgorithm::Sha384, data).unwrap_or_default()
    }

    fn crypto_sha512(data: &[u8]) -> Vec<u8> {
        crypto::sha::sha(HashAlgorithm::Sha512, data).unwrap_or_default()
    }

    fn hash_fn(digest: RsaDigestKind) -> fn(&[u8]) -> Vec<u8> {
        match digest {
            RsaDigestKind::Sha1 => Self::crypto_sha1,
            RsaDigestKind::Sha256 => Self::crypto_sha256,
            RsaDigestKind::Sha384 => Self::crypto_sha384,
            RsaDigestKind::Sha512 => Self::crypto_sha512,
        }
    }

    /// RSA Sign using Private Key
    ///
    /// # Arguments
    /// * `digest` - Digest to sign
    /// * `key` - Private Key Handle
    /// * `padding` - Padding type
    /// * `hash_algorithm` - Hash algorithm
    /// * `salt_len` - Salt length
    ///
    /// # Returns
    /// * `Vec<u8>` - Signature
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn rsa_sign(
        &self,
        key: &HsmKeyHandle,
        digest: Vec<u8>,
        padding: RsaSignaturePadding,
        hash_algorithm: Option<DigestKind>,
        salt_len: Option<u16>,
    ) -> HsmResult<Vec<u8>> {
        tracing::debug!(
            digest_len = digest.len(),
            ?padding,
            ?hash_algorithm,
            ?salt_len,
            "Performing RSA Sign"
        );
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "rsa_sign failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let max_len = match key.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => 256,
            KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => 384,
            KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => 512,
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not RSA private");
                Err(HsmError::InvalidKeyType)?
            }
        };

        let hash_algorithm = hash_algorithm.unwrap_or(DigestKind::Sha256);
        if hash_algorithm == DigestKind::Sha1 {
            tracing::error!("SHA-1 is not supported for RSA Sign");
            Err(HsmError::InvalidParameter)?
        }

        let hash_len = Self::hash_len(hash_algorithm);
        if digest.len() != hash_len {
            tracing::error!(
                expected = hash_len,
                actual = digest.len(),
                "Digest size mismatch for the specified hash kind"
            );
            Err(HsmError::InvalidParameter)?
        }

        // Map salt_len to hash length if it is None
        // This is maximum allowable salt according to NIST.FIPS.186-5 Section 5.4 (g)
        let salt_len = salt_len.unwrap_or(Self::hash_len(hash_algorithm) as u16);
        let padded_digest = match padding {
            RsaSignaturePadding::Pss => RsaEncoding::encode_pss(
                &digest,
                max_len * 8 - 1,
                hash_algorithm.into(),
                Self::hash_fn(hash_algorithm.into()),
                salt_len,
                |buf| crypto::rand::rand_bytes(buf).map_err(|_| ()),
            )
            .map_err(|_| HsmError::RsaSignFailed)?,

            RsaSignaturePadding::Pkcs1_5 => {
                RsaEncoding::encode_pkcs_v15(&digest, max_len, hash_algorithm.into())
                    .map_err(|_| HsmError::RsaSignFailed)?
            }
        };

        let req = DdiRsaModExpCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::RsaModExp,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiRsaModExpReq {
                key_id: key.id(),
                y: MborByteArray::from_slice(&padded_digest)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                op_type: DdiRsaOpType::Sign,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done RSA Sign");

        Ok(resp.data.x.as_slice().to_vec())
    }

    /// RSA Verify using Public Key
    ///
    /// # Arguments
    /// * `key` - Private Key Handle, it must include a valid public key
    /// * `digest` - The digest used to generate the signature
    /// * `signature` - Signature to be verified
    /// * `padding` - Rsa Signature Padding
    /// * `hash_algorithm` - Hash Algorithm
    /// * `salt_len` - Optional Salt Length
    ///
    /// # Returns
    /// * `()` - If signature is valid
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - If the current App Session is closed.
    /// * `HsmError::InvalidParameter` - If the handle does not contain a valid public key, or parameters are invalid.
    /// * `HsmError::InvalidKeyType` - If the Key type is not RSA public.
    /// * `HsmError::RsaFromDerError` - If fail to convert key handle to RSA Key.
    /// * `HsmError::DerAndKeyTypeMismatch` - If the handle's key and type mismatch.
    /// * `HsmError::RsaVerifyFailed` - If the verification fails.
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn rsa_verify(
        &self,
        key: &HsmKeyHandle,
        digest: Vec<u8>,
        signature: Vec<u8>,
        padding: RsaSignaturePadding,
        hash_algorithm: Option<DigestKind>,
        salt_len: Option<u16>,
    ) -> HsmResult<()> {
        tracing::debug!(
            digest_len = digest.len(),
            ?padding,
            ?hash_algorithm,
            ?salt_len,
            "Performing RSA Verify"
        );

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "rsa_verify failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let (pub_key_kind, max_len) = match key.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => (KeyType::Rsa2kPublic, 256),
            KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => (KeyType::Rsa3kPublic, 384),
            KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => (KeyType::Rsa4kPublic, 512),
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not RSA public");
                Err(HsmError::InvalidKeyType)?
            }
        };

        if signature.len() != max_len {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), signature_len = signature.len(), max_len, "Signature length != max_len");
            Err(HsmError::InvalidParameter)?
        }

        let hash_algorithm = hash_algorithm.unwrap_or(DigestKind::Sha256);
        let hash_len = Self::hash_len(hash_algorithm);
        if digest.len() != hash_len {
            tracing::error!(
                expected = hash_len,
                actual = digest.len(),
                "Digest size mismatch for the specified hash kind"
            );
            Err(HsmError::InvalidParameter)?
        }

        let der = key.pub_key.as_ref().ok_or_else(|| {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), "Public Key is required but missing");
            HsmError::InvalidParameter
        })?;

        let rsa_public_key = RsaPublicKey::from_der(der, Some(pub_key_kind.into()))?;

        Ok(rsa_public_key.verify(
            &digest,
            &signature,
            padding.into(),
            Some(hash_algorithm).map(|kind| kind.into()),
            salt_len,
        )?)
    }

    /// Generate ECC Key
    #[instrument(skip_all, fields(sess_id = self.session_id, key_tag))]
    pub fn ecc_generate(
        &self,
        curve: EccCurve,
        key_tag: Option<u16>,
        key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        tracing::debug!("Generating ECC Key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "ecc_generate failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let key_properties: DdiKeyProperties = key_properties.into();

        let req = DdiEccGenerateKeyPairCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::EccGenerateKeyPair,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiEccGenerateKeyPairReq {
                curve: curve.into(),
                key_tag,
                key_properties: key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done generating ECC Key");

        let data = resp.data;

        let pub_key = data
            .pub_key
            .map(|resp_pub_key| resp_pub_key.der.as_slice().to_vec());

        let masked_key = data.masked_key.as_slice().to_vec();

        let key_type = match curve {
            EccCurve::P256 => KeyType::Ecc256Private,
            EccCurve::P384 => KeyType::Ecc384Private,
            EccCurve::P521 => KeyType::Ecc521Private,
        };

        Ok(HsmKeyHandle {
            id: data.private_key_id,
            kind: key_type,
            pub_key,
            bulk_key_id: None,
            masked_key: Some(masked_key),
        })
    }

    /// ECC Sign using Private Key
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn ecc_sign(&self, key: &HsmKeyHandle, digest: Vec<u8>) -> HsmResult<Vec<u8>> {
        tracing::debug!("Performing ECC Sign");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "ecc_sign failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        if !ALLOWED_DIGEST_LENGTHS.contains(&digest.len()) {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), len = digest.len(), "Digest length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        let max_len = match key.kind() {
            KeyType::Ecc256Private => 32,
            KeyType::Ecc384Private => 48,
            KeyType::Ecc521Private => 68,
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not ECC private");
                Err(HsmError::InvalidKeyType)?
            }
        };

        if digest.len() > max_len {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), len = digest.len(), max_len, "Digest length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        let digest_algo = match digest.len() {
            20 => DdiHashAlgorithm::Sha1,
            32 => DdiHashAlgorithm::Sha256,
            48 => DdiHashAlgorithm::Sha384,
            64 => DdiHashAlgorithm::Sha512,
            _ => {
                tracing::error!(error = ?HsmError::UnsupportedDigestHashAlgorithm, key_id = key.id(), len = digest.len(), "Digest length is invalid");
                Err(HsmError::UnsupportedDigestHashAlgorithm)?
            }
        };

        let req = DdiEccSignCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::EccSign,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiEccSignReq {
                key_id: key.id(),
                digest: MborByteArray::from_slice(&digest)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                digest_algo,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done ECC Sign");

        Ok(resp.data.signature.as_slice().to_vec())
    }

    /// ECC Verify using Public Key
    /// ECDSA signature verification
    ///
    /// # Arguments
    /// * `key` - Private Key Handle, it must include a valid public key
    /// * `digest` - The digest used to generate the signature
    /// * `signature` - The signature (in raw format) to be verified
    ///
    /// # Returns
    /// * `()` - If verification succeeds.
    ///
    /// # Errors
    /// * `HsmError::SessionClosed` - If the current App Session is closed.
    /// * `HsmError::InvalidParameter` - If the handle does not contain a valid public key, or parameters are invalid.
    /// * `HsmError::InvalidKeyType` - If the Key type is not ECC public.
    /// * `HsmError::EccFromDerError` - If fail to convert key handle to ECC Key.
    /// * `HsmError::DerAndKeyTypeMismatch` - If the handle's key and type mismatch.
    /// * `HsmError::EccVerifyFailed` - If the verification fails.
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn ecc_verify(
        &self,
        key: &HsmKeyHandle,
        digest: Vec<u8>,
        signature: Vec<u8>,
    ) -> HsmResult<()> {
        tracing::debug!("Performing ECC Verify");

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "ecc_verify failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        if !ALLOWED_DIGEST_LENGTHS.contains(&digest.len()) {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), len = digest.len(), "Digest length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        let (pub_key_kind, max_len_digest, max_len_sig) = match key.kind() {
            KeyType::Ecc256Private => (KeyType::Ecc256Public, 32, 64),
            KeyType::Ecc384Private => (KeyType::Ecc384Public, 48, 96),
            KeyType::Ecc521Private => (KeyType::Ecc521Public, 68, 132),
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not ECC public");
                Err(HsmError::InvalidKeyType)?
            }
        };

        if digest.len() > max_len_digest {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), digest_len = digest.len(), max_len_digest, "Digest length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        if signature.len() != max_len_sig {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), signature_len = signature.len(), max_len_sig, "Signature length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        let der = key.pub_key.as_ref().ok_or_else(|| {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), "Public Key is required but missing");
            HsmError::InvalidParameter
        })?;

        let ecc_public_key = EccPublicKey::from_der(der, Some(pub_key_kind.into()))?;

        Ok(ecc_public_key.verify(&digest, &signature)?)
    }

    /// ECDH Key Exchange
    ///
    /// # Arguments
    /// `priv_key` - Own private key, must be Ecc Private type, must have KeyUsage `Derive`
    /// `peer_pub_key` - Other party's public key, must be Ecc Public type and same curve name as `priv_key`
    /// `target_key_tag` - Target key tag
    /// `target_key_type` - Target key type, must be `Secret` type with matching bit size
    /// `target_key_properties` - Target key properties, must be `Derive` usage.
    ///
    /// # Returns
    /// Result has KeyType `Secret` and KeyUsage `Derive`
    #[instrument(skip_all, fields(sess_id = self.session_id, priv_key_id = priv_key.id()))]
    pub fn ecdh_key_exchange(
        &self,
        priv_key: &HsmKeyHandle,
        peer_pub_key: &[u8],
        target_key_tag: Option<u16>,
        target_key_type: KeyType,
        target_key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        tracing::debug!(
            ?target_key_tag,
            ?target_key_type,
            ?target_key_properties,
            "Performing ECDH Key Exchange"
        );
        let read_locked_device = self.device_inner.read();

        if self.closed {
            Err(HsmError::SessionClosed)?
        }

        let target_key_properties: DdiKeyProperties = target_key_properties.into();

        let req = DdiEcdhKeyExchangeCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::EcdhKeyExchange,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiEcdhKeyExchangeReq {
                priv_key_id: priv_key.id(),
                pub_key_der: MborByteArray::from_slice(peer_pub_key)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                key_type: target_key_type.into(),
                key_tag: target_key_tag,
                key_properties: target_key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done ECDH Key Exchange");

        let data = resp.data;

        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: target_key_type,
            pub_key: None,
            bulk_key_id: None,
            masked_key: Some(masked_key),
        })
    }

    /// HMAC Key Derivation Function
    ///
    /// # Arguments
    /// `secret_key` - Own key, must be Secret type, must have KeyUsage `Derive`
    /// `params` - Parameters for HKDF, including `hash_algorithm`, `salt`, `info` values
    /// `target_key_tag` - Target key tag
    /// `target_key_type` - Target key type, must be Secret or Aes
    /// `target_key_properties` - Target key properties
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = secret_key.id()))]
    pub fn hkdf_derive(
        &self,
        secret_key: &HsmKeyHandle,
        params: HkdfDeriveParameters<'_>,
        target_key_tag: Option<u16>,
        target_key_type: KeyType,
        target_key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        tracing::debug!("Performing HKDF Derive");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            Err(HsmError::SessionClosed)?
        }

        let salt = if let Some(salt_slice) = params.salt {
            Some(
                MborByteArray::from_slice(salt_slice)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            )
        } else {
            None
        };

        let info = if let Some(info_slice) = params.info {
            Some(
                MborByteArray::from_slice(info_slice)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            )
        } else {
            None
        };

        let target_key_properties: DdiKeyProperties = target_key_properties.into();

        let req = DdiHkdfDeriveCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::HkdfDerive,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiHkdfDeriveReq {
                key_id: secret_key.id(),
                hash_algorithm: params.hash_algorithm.into(),
                salt,
                info,
                key_type: target_key_type.into(),
                key_tag: target_key_tag,
                key_properties: target_key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done HKDF Derive");

        let data = resp.data;

        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: target_key_type,
            pub_key: None,
            bulk_key_id: None,
            masked_key: Some(masked_key),
        })
    }

    /// Key-Based Key Derivation Function (Counter-mode, HMAC)
    ///
    /// # Arguments
    /// `key` - Own key, must have KeyUsage `Derive`
    /// `params` - Parameters for KBKDF, including `hash_algorithm`, `salt`, `info` values
    /// `target_key_tag` - Target key tag
    /// `target_key_type` - Target key type, must be Secret or Aes
    /// `target_key_properties` - Target key properties
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn kbkdf_counter_hmac_derive(
        &self,
        key: &HsmKeyHandle,
        params: KbkdfDeriveParameters<'_>,
        target_key_tag: Option<u16>,
        target_key_type: KeyType,
        target_key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        tracing::debug!("Performing KBKDF Counter Mode Derive");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            Err(HsmError::SessionClosed)?
        }

        let label = if let Some(label_slice) = params.label {
            Some(
                MborByteArray::from_slice(label_slice)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            )
        } else {
            None
        };

        let context = if let Some(context_slice) = params.context {
            Some(
                MborByteArray::from_slice(context_slice)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            )
        } else {
            None
        };

        let target_key_properties: DdiKeyProperties = target_key_properties.into();

        let req = DdiKbkdfCounterHmacDeriveCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::KbkdfCounterHmacDerive,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiKbkdfCounterHmacDeriveReq {
                key_id: key.id(),
                hash_algorithm: params.hash_algorithm.into(),
                label,
                context,
                key_type: target_key_type.into(),
                key_tag: target_key_tag,
                key_properties: target_key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done KBKDF Counter Mode Derive");

        let data = resp.data;

        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: target_key_type,
            pub_key: None,
            bulk_key_id: None,
            masked_key: Some(masked_key),
        })
    }

    /// Hash-based Message Authentication Code
    ///
    /// # Arguments
    /// `key` - Own key, must have KeyUsage `Sign` and KeyType `HmacSha`
    /// `msg` - input data
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn hmac(&self, key: &HsmKeyHandle, msg: Vec<u8>) -> HsmResult<Vec<u8>> {
        tracing::debug!("Performing HMAC");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "HMAC failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let req = DdiHmacCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::Hmac,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiHmacReq {
                key_id: key.id(),
                msg: MborByteArray::from_slice(&msg)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done HMAC");

        Ok(resp.data.tag.as_slice().to_vec())
    }

    /// Attest the key and obtain key attestation report,
    /// Also fetch the certificate chain for that report,
    /// Then verify if the report is signed by the certificate's public key.
    /// If signature doesn't match, then LM might have occurred during two calls.
    ///
    /// # Arguments
    /// * `key` - handle to the Key to be attested
    /// * `report_data` - arbitrary user data to be included in the attestation report
    ///
    /// # Returns
    /// * `(Vec<u8>, ManticoreCertificate)` - Attestation report and certificate
    ///
    /// # Errors
    /// * `HsmError::SessionNeedsRenegotiation` - Thrown if the attestation report signature doesn't match the certificate's public key, LM might have occurred.
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn attest_key_and_obtain_cert(
        &self,
        key: &HsmKeyHandle,
        report_data: &[u8; REPORT_DATA_SIZE],
    ) -> HsmResult<(Vec<u8>, ManticoreCertificate)> {
        let attestation_report = self.attest_key(key, report_data)?;

        let certificate = self.get_certificate()?;
        let cert_chain = match &certificate {
            ManticoreCertificate::PhysicalManticore(cert_chain) => cert_chain,
            ManticoreCertificate::VirtualManticore { ak_cert, .. } => ak_cert,
        };

        // Find the leaf cert from cert chain
        let leaf_cert_pem = {
            let pattern_header = "-----BEGIN CERTIFICATE-----".as_bytes();
            let pattern_footer = "-----END CERTIFICATE-----".as_bytes();

            let start = cert_chain
                .windows(pattern_header.len())
                .position(|window| window == pattern_header)
                .ok_or(HsmError::GetCertificateError)?;
            let end = cert_chain
                .windows(pattern_footer.len())
                .position(|window| window == pattern_footer)
                .ok_or(HsmError::GetCertificateError)?;

            // Move to end of footer
            let end = end + pattern_footer.len();

            &cert_chain[start..end]
        };

        // Parse the leaf cert to get a ECC Pub key
        let ecc_pub_key = {
            let cert = X509Certificate::from_pem(leaf_cert_pem)
                .map_err(|_| HsmError::GetCertificateError)?;
            let der = cert
                .get_public_key_der()
                .map_err(|_| HsmError::GetCertificateError)?;
            EccPublicKey::from_der(&der, None)?
        };

        let key_attester = KeyAttester::parse(&attestation_report).map_err(|error| {
            tracing::error!(?error, "Failed to parse attestation report");
            HsmError::AttestKeyError
        })?;

        // If error is AttestationError::ReportSignatureMismatch, LM might occurred
        key_attester
            .verify(&ecc_pub_key)
            .map_err(|error| match error {
                AttestationError::ReportSignatureMismatch => {
                    tracing::error!(
                        error = ?HsmError::AttestReportSignatureMismatch,
                        "Attestation report signature mismatch, LM might have occurred"
                    );
                    HsmError::AttestReportSignatureMismatch
                }
                _ => {
                    tracing::error!(?error, "Failed to verify attestation report");
                    HsmError::AttestKeyError
                }
            })?;

        Ok((attestation_report, certificate))
    }

    /// Attest Key
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn attest_key(
        &self,
        key: &HsmKeyHandle,
        report_data: &[u8; REPORT_DATA_SIZE],
    ) -> HsmResult<Vec<u8>> {
        tracing::debug!("Performing Attest Key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "attest_key failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let req = DdiAttestKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::AttestKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiAttestKeyReq {
                key_id: key.id(),
                report_data: MborByteArray::from_slice(report_data)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done attest key");

        Ok(resp.data.report.as_slice().to_vec())
    }

    /// Get Unwrapping Key
    pub fn get_unwrapping_key(&self) -> HsmResult<HsmKeyHandle> {
        tracing::debug!("Getting unwrapping key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            Err(HsmError::SessionClosed)?
        }

        let req = DdiGetUnwrappingKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetUnwrappingKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiGetUnwrappingKeyReq {},
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!(
            unwrap_key_id = resp.data.key_id,
            "Done getting unwrapping key"
        );
        let data = resp.data;

        let pub_key = data.pub_key.der.as_slice().to_vec();
        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: KeyType::Rsa2kPrivate,
            pub_key: Some(pub_key),
            bulk_key_id: None,
            masked_key: Some(masked_key),
        })
    }

    /// Fetch all certificates from the device
    /// Return cert chain, leaf cert first, all cert in DER
    fn get_cert_chain(&self, slot_id: u8) -> HsmResult<Vec<Vec<u8>>> {
        let read_locked_device = self.device_inner.read();

        // Fetch cert chain info
        let req = DdiGetCertChainInfoCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetCertChainInfo,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiGetCertChainInfoReq { slot_id },
            ext: None,
        };
        let mut cookie = None;
        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        let num_certs = resp.data.num_certs;
        let thumbprint = resp.data.thumbprint.as_slice();
        tracing::debug!(num_certs, slot_id, "Got Cert Chain Length");

        // Fetch each cert
        // Array of certificates, root cert first, leaf cert last
        // Before returning, reverse the order so leaf cert is first
        let mut certs: Vec<Vec<u8>> = Vec::with_capacity(num_certs as usize);

        // 0-based, root cert at index 0, leaf cert at last
        for i in 0..num_certs {
            tracing::debug!("Fetching cert {}, total {}", i, num_certs);
            let req = DdiGetCertificateCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetCertificate,
                    sess_id: None,
                    rev: Some(DdiApiRev {
                        major: self.api_rev.major,
                        minor: self.api_rev.minor,
                    }),
                },
                data: DdiGetCertificateReq {
                    slot_id,
                    cert_id: i,
                },
                ext: None,
            };
            let mut cookie = None;
            let result = read_locked_device.dev.exec_op(&req, &mut cookie)?;
            tracing::debug!("Done fetching cert {}", i);

            let der = result.data.certificate.as_slice();

            certs.push(der.to_vec());
        }
        tracing::debug!("Done fetching certificate chain");

        // Valid cert chain by comparing hash
        let req = DdiGetCertChainInfoCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetCertChainInfo,
                sess_id: None,
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiGetCertChainInfoReq { slot_id },
            ext: None,
        };
        let mut cookie = None;
        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        let num_certs_after = resp.data.num_certs;
        let thumbprint_after = resp.data.thumbprint.as_slice();
        if num_certs != num_certs_after || thumbprint != thumbprint_after {
            tracing::error!(error = ?HsmError::CertificateHashMismatch, "Certificate chain hash mismatch");
            Err(HsmError::CertificateHashMismatch)?
        }

        // Reverse so leaf cert is first, root cert is last
        certs.reverse();

        Ok(certs)
    }

    /// Get Certificate
    #[instrument(skip_all, fields(sess_id = self.session_id))]
    pub fn get_certificate(&self) -> HsmResult<ManticoreCertificate> {
        tracing::debug!("Getting Certificate");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "get certificates failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let slot_id = 0;
        let cert_chain = self.get_cert_chain(slot_id)?;

        // Flatten cert by converting to PEM
        let mut flatten_certs = Vec::new();
        for (i, cert_der) in cert_chain.iter().enumerate() {
            if i != 0 {
                // Add separator except for first item
                flatten_certs.push(b'\n');
            }

            let cert_pem = der_to_pem(cert_der).map_err(|err| {
                tracing::error!(?err, cert_index = i, "Failed to convert Cert DER to PEM");
                HsmError::GetCertificateError
            })?;
            flatten_certs.extend_from_slice(&cert_pem);
        }

        tracing::debug!("Done getting certificates");
        Ok(match read_locked_device.get_device_info().kind {
            DeviceKind::Virtual => {
                ManticoreCertificate::VirtualManticore {
                    ak_cert: flatten_certs,
                    // TODO: return empty until vManticore collateral support
                    tee_cert_chain: Vec::new(),
                    // TODO: return empty until vManticore collateral support
                    tee_report: Vec::new(),
                }
            }
            DeviceKind::Physical => ManticoreCertificate::PhysicalManticore(flatten_certs),
        })
    }

    /// Generate AES Key
    #[instrument(skip_all, fields(sess_id = self.session_id, key_tag = key_tag))]
    pub fn aes_generate(
        &self,
        key_size: AesKeySize,
        key_tag: Option<u16>,
        key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        tracing::debug!("Generating AES Key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "aes_generate failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let key_properties: DdiKeyProperties = key_properties.into();

        let req = DdiAesGenerateKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::AesGenerateKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiAesGenerateKeyReq {
                key_size: key_size.into(),
                key_tag,
                key_properties: key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done generating AES key");

        let data = resp.data;
        let masked_key = data.masked_key.as_slice().to_vec();

        let key_type = match key_size {
            AesKeySize::Aes128 => KeyType::Aes128,
            AesKeySize::Aes192 => KeyType::Aes192,
            AesKeySize::Aes256 => KeyType::Aes256,
            AesKeySize::AesXtsBulk256 => KeyType::AesXtsBulk256,
            AesKeySize::AesGcmBulk256 => KeyType::AesGcmBulk256,
            AesKeySize::AesGcmBulk256Unapproved => KeyType::AesGcmBulk256Unapproved,
        };

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: key_type,
            pub_key: None,
            bulk_key_id: data.bulk_key_id,
            masked_key: Some(masked_key),
        })
    }

    /// AES Encrypt/ Decrypt
    #[instrument(skip_all, fields(sess_id = self.session_id, key_id = key.id()))]
    pub fn aes_encrypt_decrypt(
        &self,
        key: &HsmKeyHandle,
        mode: AesMode,
        data: Vec<u8>,
        iv: [u8; 16usize],
    ) -> HsmResult<AesResult> {
        tracing::debug!("Performing AES Encrypt/ Decrypt");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "aes_encrypt_decrypt failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let max_len = match key.kind() {
            KeyType::Aes128 | KeyType::Aes192 | KeyType::Aes256 => 1024,
            _ => {
                tracing::error!(error = ?HsmError::InvalidKeyType, key_id = key.id(), "Key type is not AES");
                Err(HsmError::InvalidKeyType)?
            }
        };

        if data.len() > max_len {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), len = data.len(), max_len, "Data length is invalid");
            Err(HsmError::InvalidParameter)?
        }

        if data.len() % 16 != 0 {
            tracing::error!(error = ?HsmError::InvalidParameter, key_id = key.id(), len = data.len(), "Data length is not multiple of 16");
            Err(HsmError::InvalidParameter)?
        }

        let req = DdiAesEncryptDecryptCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::AesEncryptDecrypt,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiAesEncryptDecryptReq {
                key_id: key.id(),
                op: mode.into(),
                msg: MborByteArray::from_slice(&data)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                iv: MborByteArray::from_slice(&iv)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done AES encrypt/decrypt");

        Ok(AesResult {
            data: resp.data.msg.as_slice().to_vec(),
            iv: resp.data.iv.data_take(),
        })
    }

    /// Fast path AES GCM encrypt and decrypt
    /// key
    /// mode : Encrypt or decrypt
    /// data : Data to be encrypted (cleartext) or decrypted
    /// iv : Initialization vector
    /// aad :- Optional additional authentication data
    /// tag : Optional for encryption, required for decryption
    #[instrument(skip_all, fields(sess_id = self.session_id, short_app_id = self.short_app_id, key_id = key.id()))]
    pub fn aes_gcm_encrypt_decrypt(
        &self,
        key: &HsmKeyHandle,
        mode: AesMode,
        data: Vec<u8>,
        iv: [u8; 12usize],
        aad: Option<Vec<u8>>,
        tag: Option<[u8; 16usize]>,
    ) -> HsmResult<AesGcmResult> {
        tracing::debug!("Performing AES GCM Encrypt/Decrypt");
        // If mode is decryption and tag is not provided
        // error
        // Providing tag for encryption is a no-op
        // means tag will be ignored
        if mode == AesMode::Decrypt && tag.is_none() {
            Err(HsmError::AesGcmDecryptionNoTagProvided)?
        }

        // Key kind must be AES Bulk GCM type
        if key.kind() != KeyType::AesGcmBulk256Unapproved && key.kind() != KeyType::AesGcmBulk256 {
            Err(HsmError::InvalidKeyType)?;
        }

        let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams::default();
        let read_locked_device = self.device_inner.read();
        let ddi_aes_mode = if mode == AesMode::Encrypt {
            DdiAesOp::Encrypt
        } else {
            DdiAesOp::Decrypt
        };

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "aes_gcm_encrypt_decrypt failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        mcr_fp_gcm_params.iv = iv;
        mcr_fp_gcm_params.aad = aad;
        mcr_fp_gcm_params.key_id = key.bulk_key_id.ok_or(HsmError::InvalidKeyType)? as u32;
        mcr_fp_gcm_params.tag = tag;
        mcr_fp_gcm_params.session_id = self.session_id;
        mcr_fp_gcm_params.short_app_id = self.short_app_id;

        let resp = read_locked_device
            .dev
            .exec_op_fp_gcm(ddi_aes_mode, mcr_fp_gcm_params, data)?;
        tracing::debug!("Done AES GCM Encrypt/Decrypt");

        Ok(AesGcmResult {
            data: resp.data,
            tag: resp.tag,
        })
    }

    /// Fast path AES Xts encrypt and decrypt
    /// key
    /// mode : Encrypt or decrypt
    /// key_1: First key
    /// key_2: Second key
    ///
    #[instrument(skip_all, fields(sess_id = self.session_id, short_app_id = self.short_app_id, key1_id = key_1.id(), key2_id = key_2.id()))]
    pub fn aes_xts_encrypt_decrypt(
        &self,
        mode: AesMode,
        key_1: &HsmKeyHandle,
        key_2: &HsmKeyHandle,
        dul: usize,
        tweak: [u8; 16usize],
        data: Vec<u8>,
    ) -> HsmResult<AesXtsResult> {
        tracing::debug!("Performing AES XTS Encrypt/Decrypt");

        // both keys must be AesBulk256
        if key_1.kind() != KeyType::AesXtsBulk256 {
            Err(HsmError::InvalidKeyType)?;
        }

        if key_2.kind() != KeyType::AesXtsBulk256 {
            Err(HsmError::InvalidKeyType)?;
        }

        let mut mcr_fp_xts_params: DdiAesXtsParams = DdiAesXtsParams::default();
        let read_locked_device = self.device_inner.read();
        let ddi_aes_mode = if mode == AesMode::Encrypt {
            DdiAesOp::Encrypt
        } else {
            DdiAesOp::Decrypt
        };

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "aes_gcm_encrypt_decrypt failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        mcr_fp_xts_params.key_id1 = key_1.bulk_key_id.ok_or(HsmError::InvalidKeyType)? as u32;
        mcr_fp_xts_params.key_id2 = key_2.bulk_key_id.ok_or(HsmError::InvalidKeyType)? as u32;
        mcr_fp_xts_params.data_unit_len = dul;
        mcr_fp_xts_params.session_id = self.session_id;
        mcr_fp_xts_params.short_app_id = self.short_app_id;
        mcr_fp_xts_params.tweak = tweak;

        let resp = read_locked_device
            .dev
            .exec_op_fp_xts(ddi_aes_mode, mcr_fp_xts_params, data)?;
        tracing::debug!("Done AES XTS Encrypt/Decrypt");

        Ok(AesXtsResult { data: resp.data })
    }

    /// Unmask/Import a key
    ///
    /// # Arguments
    /// * `key` - Key to unmask, this will be modified in place to point to the unmasked key
    ///
    /// # Returns
    /// * `HsmKeyHandle` - Unmasked key
    pub fn unmask_key_from_handle(&self, key: &mut HsmKeyHandle) -> HsmResult<()> {
        tracing::debug!("Unmasking key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "unmask_key failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let masked_key = key.masked_key().ok_or_else(|| {
            tracing::error!(error = ?HsmError::InvalidParameter, "HsmKeyHandle::masked_key is None");
            HsmError::InvalidParameter
        })?;

        let req = DdiUnmaskKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::UnmaskKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiUnmaskKeyReq {
                masked_key: MborByteArray::from_slice(masked_key)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done unmasking key");

        let data = resp.data;
        let masked_key = data.masked_key.as_slice().to_vec();
        let pub_key = data
            .pub_key
            .map(|resp_pub_key| resp_pub_key.der.as_slice().to_vec());

        // Check type same as before
        if data.kind != key.kind.into() || pub_key != key.pub_key {
            tracing::error!(error = ?HsmError::InternalError, "Unmasked key has different kind or public key than original");
            Err(HsmError::InternalError)?
        }

        // Update field on key
        key.id = data.key_id;
        key.bulk_key_id = data.bulk_key_id;
        key.masked_key = Some(masked_key);

        Ok(())
    }

    /// Unmask/Import a key given a encrypted key blob
    ///
    /// # Arguments
    /// * `blob` - Encrypted key blob, i.e. the `masked_key`
    ///
    /// # Returns
    /// * `HsmKeyHandle` - Unmasked key
    pub fn unmask_key(&self, blob: &[u8]) -> HsmResult<HsmKeyHandle> {
        tracing::debug!("Unmasking key");
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::error!(error = ?HsmError::SessionClosed, "unmask_key failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        if blob.is_empty() {
            tracing::error!(error = ?HsmError::InvalidParameter, "Blob is empty");
            Err(HsmError::InvalidParameter)?
        }

        let req = DdiUnmaskKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::UnmaskKey,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiUnmaskKeyReq {
                masked_key: MborByteArray::from_slice(blob)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        tracing::debug!("Done unmasking key from blob");

        let data = resp.data;

        let pub_key = data
            .pub_key
            .map(|resp_pub_key| resp_pub_key.der.as_slice().to_vec());
        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            kind: data.kind.try_into()?,
            pub_key,
            bulk_key_id: data.bulk_key_id,
            masked_key: Some(masked_key),
        })
    }

    #[cfg(feature = "testhooks")]
    /// Import Key
    ///
    /// # Arguments
    /// * `der` - Key in DER format
    /// * `key_kind` - Key kind
    ///
    /// # Returns
    /// * `u16` - Public Key ID
    #[instrument(skip_all, fields(sess_id = self.session_id, key_tag = key_tag))]
    pub fn import_key(
        &self,
        der: Vec<u8>,
        key_class: KeyClass,
        key_tag: Option<u16>,
        key_properties: KeyProperties,
    ) -> HsmResult<HsmKeyHandle> {
        let read_locked_device = self.device_inner.read();

        if self.closed {
            tracing::debug!(error = ?HsmError::SessionClosed, "import_key failed: App Session already closed");
            Err(HsmError::SessionClosed)?
        }

        let key_properties: DdiKeyProperties = key_properties.into();

        let req = DdiDerKeyImportCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::DerKeyImport,
                sess_id: Some(self.session_id),
                rev: Some(DdiApiRev {
                    major: self.api_rev.major,
                    minor: self.api_rev.minor,
                }),
            },
            data: DdiDerKeyImportReq {
                der: MborByteArray::from_slice(&der)
                    .map_err(|_| HsmError::CborByteArrayCreationError)?,
                key_class: key_class.into(),
                key_tag,
                key_properties: key_properties
                    .try_into()
                    .map_err(|_| HsmError::InvalidParameter)?,
            },
            ext: None,
        };

        let mut cookie = None;

        let resp = read_locked_device.dev.exec_op(&req, &mut cookie)?;
        let data = resp.data;

        let pub_key = data
            .pub_key
            .map(|resp_pub_key| resp_pub_key.der.as_slice().to_vec());
        let masked_key = data.masked_key.as_slice().to_vec();

        Ok(HsmKeyHandle {
            id: data.key_id,
            pub_key,
            bulk_key_id: data.bulk_key_id,
            kind: data.key_type.try_into()?,
            masked_key: Some(masked_key),
        })
    }
}

/// RSA Unwrap Parameters
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug)]
pub struct RsaUnwrapParams {
    /// Key Type of the wrapped blob
    pub key_class: KeyClass,

    /// Padding of the wrapped blob
    pub padding: RsaCryptoPadding,

    /// Hash Algorithm of the wrapped blob
    pub hash_algorithm: DigestKind,
}

/// Device Kind
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// virtual device
    Virtual,

    /// physical device
    Physical,
}

impl TryFrom<DdiDeviceKind> for DeviceKind {
    type Error = HsmError;

    fn try_from(kind: DdiDeviceKind) -> Result<Self, Self::Error> {
        match kind {
            DdiDeviceKind::Virtual => Ok(DeviceKind::Virtual),
            DdiDeviceKind::Physical => Ok(DeviceKind::Physical),
            _ => Err(HsmError::InvalidParameter),
        }
    }
}

/// Cryptographic Key Class.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyClass {
    /// RSA Private
    Rsa,

    /// RSA CRT Private
    RsaCrt,

    /// AES
    Aes,

    /// AES XTS Bulk
    AesXtsBulk,

    /// AES GCM Bulk
    AesGcmBulk,

    /// AES GCM Bulk Unapproved
    AesGcmBulkUnapproved,

    /// ECC Private
    Ecc,
}

impl From<KeyClass> for DdiKeyClass {
    fn from(value: KeyClass) -> Self {
        match value {
            KeyClass::Rsa => DdiKeyClass::Rsa,
            KeyClass::RsaCrt => DdiKeyClass::RsaCrt,
            KeyClass::Aes => DdiKeyClass::Aes,
            KeyClass::AesXtsBulk => DdiKeyClass::AesXtsBulk,
            KeyClass::AesGcmBulk => DdiKeyClass::AesGcmBulk,
            KeyClass::AesGcmBulkUnapproved => DdiKeyClass::AesGcmBulkUnapproved,
            KeyClass::Ecc => DdiKeyClass::Ecc,
        }
    }
}

/// Key Type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA 2048 Public Key
    Rsa2kPublic,

    /// RSA 3072 Public Key
    Rsa3kPublic,

    /// RSA 4096 Public Key
    Rsa4kPublic,

    /// RSA 2048 Private Key
    Rsa2kPrivate,

    /// RSA 3072 Private Key
    Rsa3kPrivate,

    /// RSA 4096 Private Key
    Rsa4kPrivate,

    /// RSA 2048 Private CRT Key
    Rsa2kPrivateCrt,

    /// RSA 3072 Private CRT Key
    Rsa3kPrivateCrt,

    /// RSA 4096 Private CRT Key
    Rsa4kPrivateCrt,

    /// ECC 256 Public Key
    Ecc256Public,

    /// ECC 384 Public Key
    Ecc384Public,

    /// ECC 521 Public Key
    Ecc521Public,

    /// ECC 256 Private Key
    Ecc256Private,

    /// ECC 384 Private Key
    Ecc384Private,

    /// ECC 521 Private Key
    Ecc521Private,

    /// AES 128-bit Key
    Aes128,

    /// AES 192-bit Key
    Aes192,

    /// AES 256-bit Key
    Aes256,

    /// AES XTS Bulk 256-bit Key
    AesXtsBulk256,

    /// AES GCM Bulk 256-bit Key
    AesGcmBulk256,

    /// AES GCM Bulk 256-bit Unapproved Key
    AesGcmBulk256Unapproved,

    /// 256-bit Secret from key exchange
    Secret256,

    /// 384-bit Secret from key exchange
    Secret384,

    /// 521-bit Secret from key exchange
    Secret521,

    /// 256-bit HMAC key for SHA256
    HmacSha256,

    /// 384-bit HMAC key for SHA384
    HmacSha384,

    /// 512-bit HMAC key for SHA512
    HmacSha512,
}

impl From<KeyType> for DdiKeyType {
    fn from(kind: KeyType) -> Self {
        match kind {
            KeyType::Rsa2kPublic => DdiKeyType::Rsa2kPublic,
            KeyType::Rsa3kPublic => DdiKeyType::Rsa3kPublic,
            KeyType::Rsa4kPublic => DdiKeyType::Rsa4kPublic,
            KeyType::Rsa2kPrivate => DdiKeyType::Rsa2kPrivate,
            KeyType::Rsa3kPrivate => DdiKeyType::Rsa3kPrivate,
            KeyType::Rsa4kPrivate => DdiKeyType::Rsa4kPrivate,
            KeyType::Rsa2kPrivateCrt => DdiKeyType::Rsa2kPrivateCrt,
            KeyType::Rsa3kPrivateCrt => DdiKeyType::Rsa3kPrivateCrt,
            KeyType::Rsa4kPrivateCrt => DdiKeyType::Rsa4kPrivateCrt,
            KeyType::Ecc256Public => DdiKeyType::Ecc256Public,
            KeyType::Ecc384Public => DdiKeyType::Ecc384Public,
            KeyType::Ecc521Public => DdiKeyType::Ecc521Public,
            KeyType::Ecc256Private => DdiKeyType::Ecc256Private,
            KeyType::Ecc384Private => DdiKeyType::Ecc384Private,
            KeyType::Ecc521Private => DdiKeyType::Ecc521Private,
            KeyType::Aes128 => DdiKeyType::Aes128,
            KeyType::Aes192 => DdiKeyType::Aes192,
            KeyType::Aes256 => DdiKeyType::Aes256,
            KeyType::AesXtsBulk256 => DdiKeyType::AesXtsBulk256,
            KeyType::AesGcmBulk256 => DdiKeyType::AesGcmBulk256,
            KeyType::AesGcmBulk256Unapproved => DdiKeyType::AesGcmBulk256Unapproved,
            KeyType::Secret256 => DdiKeyType::Secret256,
            KeyType::Secret384 => DdiKeyType::Secret384,
            KeyType::Secret521 => DdiKeyType::Secret521,
            KeyType::HmacSha256 => DdiKeyType::HmacSha256,
            KeyType::HmacSha384 => DdiKeyType::HmacSha384,
            KeyType::HmacSha512 => DdiKeyType::HmacSha512,
        }
    }
}

impl TryFrom<DdiKeyType> for KeyType {
    type Error = HsmError;

    fn try_from(kind: DdiKeyType) -> Result<Self, Self::Error> {
        match kind {
            DdiKeyType::Rsa2kPublic => Ok(KeyType::Rsa2kPublic),
            DdiKeyType::Rsa3kPublic => Ok(KeyType::Rsa3kPublic),
            DdiKeyType::Rsa4kPublic => Ok(KeyType::Rsa4kPublic),
            DdiKeyType::Rsa2kPrivate => Ok(KeyType::Rsa2kPrivate),
            DdiKeyType::Rsa3kPrivate => Ok(KeyType::Rsa3kPrivate),
            DdiKeyType::Rsa4kPrivate => Ok(KeyType::Rsa4kPrivate),
            DdiKeyType::Rsa2kPrivateCrt => Ok(KeyType::Rsa2kPrivateCrt),
            DdiKeyType::Rsa3kPrivateCrt => Ok(KeyType::Rsa3kPrivateCrt),
            DdiKeyType::Rsa4kPrivateCrt => Ok(KeyType::Rsa4kPrivateCrt),
            DdiKeyType::Ecc256Public => Ok(KeyType::Ecc256Public),
            DdiKeyType::Ecc384Public => Ok(KeyType::Ecc384Public),
            DdiKeyType::Ecc521Public => Ok(KeyType::Ecc521Public),
            DdiKeyType::Ecc256Private => Ok(KeyType::Ecc256Private),
            DdiKeyType::Ecc384Private => Ok(KeyType::Ecc384Private),
            DdiKeyType::Ecc521Private => Ok(KeyType::Ecc521Private),
            DdiKeyType::Aes128 => Ok(KeyType::Aes128),
            DdiKeyType::Aes192 => Ok(KeyType::Aes192),
            DdiKeyType::Aes256 => Ok(KeyType::Aes256),
            DdiKeyType::AesXtsBulk256 => Ok(KeyType::AesXtsBulk256),
            DdiKeyType::AesGcmBulk256 => Ok(KeyType::AesGcmBulk256),
            DdiKeyType::AesGcmBulk256Unapproved => Ok(KeyType::AesGcmBulk256Unapproved),
            DdiKeyType::Secret256 => Ok(KeyType::Secret256),
            DdiKeyType::Secret384 => Ok(KeyType::Secret384),
            DdiKeyType::Secret521 => Ok(KeyType::Secret521),
            DdiKeyType::HmacSha256 => Ok(KeyType::HmacSha256),
            DdiKeyType::HmacSha384 => Ok(KeyType::HmacSha384),
            DdiKeyType::HmacSha512 => Ok(KeyType::HmacSha512),
            _ => Err(HsmError::InvalidKeyType),
        }
    }
}

impl From<KeyType> for CryptoKeyKind {
    fn from(kind: KeyType) -> Self {
        match kind {
            KeyType::Rsa2kPublic => CryptoKeyKind::Rsa2kPublic,
            KeyType::Rsa3kPublic => CryptoKeyKind::Rsa3kPublic,
            KeyType::Rsa4kPublic => CryptoKeyKind::Rsa4kPublic,
            KeyType::Rsa2kPrivate => CryptoKeyKind::Rsa2kPrivate,
            KeyType::Rsa3kPrivate => CryptoKeyKind::Rsa3kPrivate,
            KeyType::Rsa4kPrivate => CryptoKeyKind::Rsa4kPrivate,
            KeyType::Rsa2kPrivateCrt => CryptoKeyKind::Rsa2kPrivateCrt,
            KeyType::Rsa3kPrivateCrt => CryptoKeyKind::Rsa3kPrivateCrt,
            KeyType::Rsa4kPrivateCrt => CryptoKeyKind::Rsa4kPrivateCrt,
            KeyType::Ecc256Public => CryptoKeyKind::Ecc256Public,
            KeyType::Ecc384Public => CryptoKeyKind::Ecc384Public,
            KeyType::Ecc521Public => CryptoKeyKind::Ecc521Public,
            KeyType::Ecc256Private => CryptoKeyKind::Ecc256Private,
            KeyType::Ecc384Private => CryptoKeyKind::Ecc384Private,
            KeyType::Ecc521Private => CryptoKeyKind::Ecc521Private,
            KeyType::Aes128 => CryptoKeyKind::Aes128,
            KeyType::Aes192 => CryptoKeyKind::Aes192,
            KeyType::Aes256 => CryptoKeyKind::Aes256,
            KeyType::AesXtsBulk256 => CryptoKeyKind::AesXtsBulk256,
            KeyType::AesGcmBulk256 => CryptoKeyKind::AesGcmBulk256,
            KeyType::AesGcmBulk256Unapproved => CryptoKeyKind::AesGcmBulk256Unapproved,
            KeyType::Secret256 => CryptoKeyKind::Secret256,
            KeyType::Secret384 => CryptoKeyKind::Secret384,
            KeyType::Secret521 => CryptoKeyKind::Secret521,
            KeyType::HmacSha256 => CryptoKeyKind::HmacSha256,
            KeyType::HmacSha384 => CryptoKeyKind::HmacSha384,
            KeyType::HmacSha512 => CryptoKeyKind::HmacSha512,
        }
    }
}

/// RSA Encryption/ Decryption Padding
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaCryptoPadding {
    /// OAEP Padding
    Oaep,
}

impl From<RsaCryptoPadding> for CryptoRsaCryptoPadding {
    fn from(padding: RsaCryptoPadding) -> Self {
        match padding {
            RsaCryptoPadding::Oaep => CryptoRsaCryptoPadding::Oaep,
        }
    }
}

/// RSA Signature Padding
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaSignaturePadding {
    /// PSS Padding
    Pss,

    /// PKCS1.5 Padding
    Pkcs1_5,
}

impl From<RsaSignaturePadding> for CryptoRsaSignaturePadding {
    fn from(padding: RsaSignaturePadding) -> Self {
        match padding {
            RsaSignaturePadding::Pss => CryptoRsaSignaturePadding::Pss,
            RsaSignaturePadding::Pkcs1_5 => CryptoRsaSignaturePadding::Pkcs1_5,
        }
    }
}

/// Digest Kind
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestKind {
    /// SHA1
    Sha1,

    /// SHA256
    Sha256,

    /// SHA384
    Sha384,

    /// SHA512
    Sha512,
}

impl From<DigestKind> for DdiHashAlgorithm {
    fn from(kind: DigestKind) -> Self {
        match kind {
            DigestKind::Sha1 => DdiHashAlgorithm::Sha1,
            DigestKind::Sha256 => DdiHashAlgorithm::Sha256,
            DigestKind::Sha384 => DdiHashAlgorithm::Sha384,
            DigestKind::Sha512 => DdiHashAlgorithm::Sha512,
        }
    }
}

impl From<DigestKind> for CryptoHashAlgorithm {
    fn from(kind: DigestKind) -> Self {
        match kind {
            DigestKind::Sha1 => CryptoHashAlgorithm::Sha1,
            DigestKind::Sha256 => CryptoHashAlgorithm::Sha256,
            DigestKind::Sha384 => CryptoHashAlgorithm::Sha384,
            DigestKind::Sha512 => CryptoHashAlgorithm::Sha512,
        }
    }
}

impl From<DigestKind> for RsaDigestKind {
    fn from(kind: DigestKind) -> Self {
        match kind {
            DigestKind::Sha1 => RsaDigestKind::Sha1,
            DigestKind::Sha256 => RsaDigestKind::Sha256,
            DigestKind::Sha384 => RsaDigestKind::Sha384,
            DigestKind::Sha512 => RsaDigestKind::Sha512,
        }
    }
}

impl From<DigestKind> for HashAlgorithm {
    fn from(kind: DigestKind) -> Self {
        match kind {
            DigestKind::Sha1 => HashAlgorithm::Sha1,
            DigestKind::Sha256 => HashAlgorithm::Sha256,
            DigestKind::Sha384 => HashAlgorithm::Sha384,
            DigestKind::Sha512 => HashAlgorithm::Sha512,
        }
    }
}

/// Allowed Key Usage
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    /// The key may be used for signing and verifying.
    SignVerify,

    /// The key may be used for encryption and decryption.
    EncryptDecrypt,

    /// The key may be used for unwrapping.
    Unwrap,

    /// The key may be used for ECDH or key derivation. This flag is invalid for RSA/AES key types.
    Derive,
}

/// Key Availability
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAvailability {
    /// The key will be available for all sessions for the current app.
    App,

    /// The key is only available for the current session.
    Session,
}

/// Key Properties
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug)]
pub struct KeyProperties {
    /// Key Usage
    pub key_usage: KeyUsage,

    /// Key Availability
    pub key_availability: KeyAvailability,
}

impl From<KeyProperties> for DdiKeyProperties {
    fn from(props: KeyProperties) -> Self {
        let key_usage = match props.key_usage {
            KeyUsage::SignVerify => DdiKeyUsage::SignVerify,
            KeyUsage::EncryptDecrypt => DdiKeyUsage::EncryptDecrypt,
            KeyUsage::Unwrap => DdiKeyUsage::Unwrap,
            KeyUsage::Derive => DdiKeyUsage::Derive,
        };

        let key_availability = match props.key_availability {
            KeyAvailability::App => DdiKeyAvailability::App,
            KeyAvailability::Session => DdiKeyAvailability::Session,
        };

        DdiKeyProperties {
            key_usage,
            key_availability,
            key_label: MborByteArray::from_slice(&[]).unwrap(),
        }
    }
}

/// ECC Curve enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EccCurve {
    /// ECC 256
    P256,

    /// ECC 384
    P384,

    /// ECC 521
    P521,
}

impl From<EccCurve> for DdiEccCurve {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::P256 => DdiEccCurve::P256,
            EccCurve::P384 => DdiEccCurve::P384,
            EccCurve::P521 => DdiEccCurve::P521,
        }
    }
}

/// HMAC Key Derivation Function Parameters
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Copy)]
pub struct HkdfDeriveParameters<'a> {
    /// Hash Algorithm
    pub hash_algorithm: DigestKind,

    /// Optional salt
    /// Salt is padded based on size of Hash Algorithm
    pub salt: Option<&'a [u8]>,

    /// Optional info
    pub info: Option<&'a [u8]>,
}

/// Key-Based Key Derivation Function Parameters
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug)]
pub struct KbkdfDeriveParameters<'a> {
    /// Hash Algorithm
    pub hash_algorithm: DigestKind,

    /// Optional label, "salt" in OpenSSL
    pub label: Option<&'a [u8]>,

    /// Optional context, "info" in OpenSSL
    pub context: Option<&'a [u8]>,
}

/// AES Key Size
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesKeySize {
    /// AES 128
    Aes128,

    /// AES 192
    Aes192,

    /// AES 256
    Aes256,

    /// AES XTS Bulk 256
    AesXtsBulk256,

    /// AES GCM Bulk 256
    AesGcmBulk256,

    /// AES GCM Bulk 256 Unapproved
    AesGcmBulk256Unapproved,
}

impl From<AesKeySize> for DdiAesKeySize {
    fn from(key_size: AesKeySize) -> Self {
        match key_size {
            AesKeySize::Aes128 => DdiAesKeySize::Aes128,
            AesKeySize::Aes192 => DdiAesKeySize::Aes192,
            AesKeySize::Aes256 => DdiAesKeySize::Aes256,
            AesKeySize::AesXtsBulk256 => DdiAesKeySize::AesXtsBulk256,
            AesKeySize::AesGcmBulk256 => DdiAesKeySize::AesGcmBulk256,
            AesKeySize::AesGcmBulk256Unapproved => DdiAesKeySize::AesGcmBulk256Unapproved,
        }
    }
}

/// AES Mode
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum AesMode {
    /// Encrypt
    Encrypt,

    /// Decrypt
    Decrypt,
}

impl From<AesMode> for DdiAesOp {
    fn from(mode: AesMode) -> Self {
        match mode {
            AesMode::Encrypt => DdiAesOp::Encrypt,
            AesMode::Decrypt => DdiAesOp::Decrypt,
        }
    }
}

/// AES Result
#[derive(Clone, Debug)]
pub struct AesResult {
    /// Output data.
    pub data: Vec<u8>,

    /// Output IV.
    pub iv: [u8; 16usize],
}

/// AES Gcm Result
#[derive(Debug)]
pub struct AesGcmResult {
    /// Output data.
    pub data: Vec<u8>,

    /// Tag
    pub tag: Option<[u8; 16usize]>,
}

/// Aes Xts Result
#[derive(Debug)]
pub struct AesXtsResult {
    /// Output data.
    pub data: Vec<u8>,
}

impl From<CryptoError> for HsmError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidParameter => HsmError::InvalidParameter,
            CryptoError::InvalidCertificate => HsmError::InvalidCertificate,
            CryptoError::RsaEncryptFailed => HsmError::RsaEncryptFailed,
            CryptoError::RsaDecryptFailed => HsmError::RsaDecryptFailed,
            CryptoError::RsaSignFailed => HsmError::RsaSignFailed,
            CryptoError::RsaVerifyFailed => HsmError::RsaVerifyFailed,
            CryptoError::DerAndKeyTypeMismatch => HsmError::DerAndKeyTypeMismatch,
            CryptoError::EccSignFailed => HsmError::EccSignFailed,
            CryptoError::EccVerifyFailed => HsmError::EccVerifyFailed,
            CryptoError::AesEncryptFailed => HsmError::AesEncryptFailed,
            CryptoError::AesDecryptFailed => HsmError::AesDecryptFailed,
            CryptoError::RsaToDerError => HsmError::RsaToDerError,
            CryptoError::RsaFromDerError => HsmError::RsaFromDerError,
            CryptoError::RsaFromRawError => HsmError::RsaFromRawError,
            CryptoError::RsaGenerateError => HsmError::RsaGenerateError,
            CryptoError::RsaGetModulusError => HsmError::RsaGetModulusError,
            CryptoError::RsaGetPublicExponentError => HsmError::RsaGetPublicExponentError,
            CryptoError::RsaInvalidKeyLength => HsmError::RsaInvalidKeyLength,
            CryptoError::EccToDerError => HsmError::EccToDerError,
            CryptoError::EccFromDerError => HsmError::EccFromDerError,
            CryptoError::EccGenerateError => HsmError::EccGenerateError,
            CryptoError::EccDeriveError => HsmError::EccDeriveError,
            CryptoError::EccGetCurveError => HsmError::EccGetCurveError,
            CryptoError::EccGetCoordinatesError => HsmError::EccGetCoordinatesError,
            CryptoError::ShaError => HsmError::ShaError,
            CryptoError::AesGenerateError => HsmError::AesGenerateError,
            CryptoError::RngError => HsmError::RngError,
            CryptoError::AesInvalidKeyLength => HsmError::AesInvalidKeyLength,
            CryptoError::HmacError => HsmError::ShaError,
            CryptoError::HkdfError => HsmError::HkdfError,
            CryptoError::EccFromRawError => HsmError::EccFromRawError,
            CryptoError::ByteArrayCreationError => HsmError::CborByteArrayCreationError,
            CryptoError::KbkdfError => HsmError::KbkdfError,
            CryptoError::OutputBufferTooSmall => HsmError::OutputBufferTooSmall,
            CryptoError::InvalidKeyLength => HsmError::InvalidKeyLength,
            CryptoError::InvalidAlgorithm => HsmError::InvalidAlgorithm,
            CryptoError::MetadataEncodeFailed => HsmError::MetadataEncodeFailed,
            CryptoError::MetadataDecodeFailed => HsmError::MetadataDecodeFailed,
            CryptoError::MaskedKeyPreEncodeFailed => HsmError::MaskedKeyPreEncodeFailed,
            CryptoError::MaskedKeyEncodeFailed => HsmError::MaskedKeyEncodeFailed,
            CryptoError::MaskedKeyDecodeFailed => HsmError::MaskedKeyDecodeFailed,
            CryptoError::MborEncodeFailed => HsmError::MborEncodeFailed,
        }
    }
}

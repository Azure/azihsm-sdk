// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto::*;
use azihsm_ddi_mbor::MborByteArray;
use parking_lot::RwLock;

use crate::*;

/// Dummy BK3 key data for initialization
const DUMMY_BK3: &[u8; 48] = &[1u8; 48];

/// HSM Partition information
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// Partition Path
    pub path: String,
}

/// HSM API Revision Range Structure
#[derive(Clone, Copy, Debug)]
pub struct ApiRevRange {
    /// Minimum Supported API Revision
    pub min: ApiRev,

    /// Maximum Supported API Revision
    pub max: ApiRev,
}

impl PartialOrd for ApiRev {
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

/// HSM Partition
pub struct Partition {
    inner: Arc<RwLock<PartitionInner>>,
}

/// Retrieve the HSM partition information list
///
/// # Returns
/// * `Vec<PartitonInfo>` - HSM partition information list
pub fn partition_info_list() -> Vec<PartitionInfo> {
    DDI.dev_info_list()
        .iter()
        .map(|info| PartitionInfo {
            path: info.path.clone(),
        })
        .collect()
}

/// Open HSM partition
///
/// # Arguments
/// `path` - Partition path
///
/// # Returns
/// `Partition` - HSM Partition
pub fn partition_open(path: &str) -> Result<Partition, AzihsmError> {
    let mut partition = DDI
        .open_dev(path)
        .map_err(|_| AZIHSM_OPEN_PARTITION_FAILED)?;

    // Get the api revision range for the opened partition.
    let resp = ddi::get_api_rev(&partition).map_err(|_| AZIHSM_GET_API_REVISION_FAILED)?;

    // Get the device info for the opened partition.
    let resp_info = ddi::get_device_info(&partition, resp.data.max)
        .map_err(|_| AZIHSM_GET_PARTITION_INFO_FAILED)?;

    partition.set_device_kind(resp_info.data.kind);

    Ok(Partition {
        inner: Arc::new(RwLock::new(PartitionInner {
            partition,
            api_rev_range: ApiRevRange {
                min: ApiRev {
                    major: resp.data.min.major,
                    minor: resp.data.min.minor,
                },
                max: ApiRev {
                    major: resp.data.max.major,
                    minor: resp.data.max.minor,
                },
            },
            part_info: PartitionInfo {
                path: path.to_string(),
            },
            open_sessions: 0,
        })),
    })
}

impl Partition {
    delegate::delegate! {
    to self.inner.read() {
        /// Get the API revision range
        pub fn api_rev_range(&self) -> ApiRevRange;

        /// Get the partition info
        pub fn part_info(&self) -> PartitionInfo;
    }}

    /// Open a session within the HSM partition
    ///
    /// # Arguments
    /// `kind` - Session type
    /// `api_rev` - API revision
    /// `credentials` - Application credentials
    ///
    /// # Returns
    /// `Session` - HSM Session
    pub fn open_session(
        &self,
        kind: SessionType,
        api_rev: ApiRev,
        credentials: AppCreds,
    ) -> Result<Session, AzihsmError> {
        self.inner
            .write()
            .open_session(self.inner.clone(), kind, api_rev, credentials)
    }

    /// Temporary function to initialize the partition with dummy BK3 and credentials
    pub fn init(&self, credentials: AppCreds) -> Result<(), AzihsmError> {
        // Init BK3.
        let masked_bk3 = self.inner.write().init_bk3(DUMMY_BK3)?;

        // Establish credentials.
        let _ = self.inner.write().establish_credential(
            credentials,
            masked_bk3.as_slice(),
            None,
            None,
        )?;

        Ok(())
    }
}

/// Inner structure of the Partition
pub struct PartitionInner {
    /// Device partition
    pub(crate) partition: <HsmDdi as Ddi>::Dev,

    /// API Revision Range
    api_rev_range: ApiRevRange,

    /// Partition info
    part_info: PartitionInfo,

    /// Open session count
    open_sessions: usize,
}

impl Drop for PartitionInner {
    fn drop(&mut self) {
        if self.open_sessions > 0 {
            panic!("Session(s) not closed!")
        }
    }
}

impl PartitionInner {
    /// Get the api revision range of the partition
    pub(super) fn api_rev_range(&self) -> ApiRevRange {
        self.api_rev_range
    }

    /// Get the partition info
    pub(super) fn part_info(&self) -> PartitionInfo {
        self.part_info.clone()
    }

    /// Update the open session count
    pub(crate) fn update_open_session_count(&mut self, increment: bool) {
        if increment {
            self.open_sessions += 1;
        } else {
            if self.open_sessions == 0 {
                panic!("Open session count is already zero");
            }
            self.open_sessions -= 1;
        }
    }

    fn open_session(
        &mut self,
        partition: Arc<RwLock<PartitionInner>>,
        session_type: SessionType,
        api_rev: ApiRev,
        credentials: AppCreds,
    ) -> Result<Session, AzihsmError> {
        if api_rev < self.api_rev_range.min || api_rev > self.api_rev_range.max {
            Err(AZIHSM_ERROR_INVALID_API_REV)?
        }

        let mut session_seed = [0u8; SESSION_SEED_SIZE_BYTES];
        Rng::rand_bytes(&mut session_seed).map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        let (encrypted_credential, pub_key) =
            self.prepare_session_encrypted_credentials(api_rev, credentials, session_seed)?;

        let resp = ddi::open_session(
            &self.partition,
            api_rev.into(),
            encrypted_credential,
            pub_key,
        )
        .map_err(|_| AZIHSM_OPEN_SESSION_FAILED)?;

        // Create a new session object
        let session = Session::new(
            partition,
            api_rev,
            session_type,
            credentials.id,
            resp.data.short_app_id,
            resp.data.sess_id,
            session_seed,
        );
        // Update the open session count on the partition.
        self.update_open_session_count(true);

        Ok(session)
    }

    fn prepare_session_encrypted_credentials(
        &self,
        api_rev: ApiRev,
        credentials: AppCreds,
        session_seed: [u8; 48],
    ) -> Result<(DdiEncryptedSessionCredential, DdiDerPublicKey), AzihsmError> {
        let resp = ddi::get_session_encryption_key(&self.partition, api_rev.into())
            .map_err(|_| AZIHSM_GET_SESSION_ENCRYPTION_KEY_FAILED)?;

        let nonce = resp.data.nonce;
        let param_encryption_key =
            DeviceCredKey::new(&resp.data.pub_key, nonce).map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        let (priv_key, ddi_public_key) = param_encryption_key
            .generate_ephemeral_encryption_key()
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        let ddi_encrypted_credential = priv_key
            .encrypt_session_credential(credentials.id, credentials.pin, session_seed, nonce)
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        Ok((ddi_encrypted_credential, ddi_public_key))
    }

    fn init_bk3(&self, bk3: &[u8; 48]) -> Result<MborByteArray<1024>, AzihsmError> {
        // [TODO] Using hardcoded api_rev for now.
        let resp = ddi::init_bk3(&self.partition, DdiApiRev { major: 1, minor: 0 }, bk3)
            .map_err(|_| AZIHSM_INIT_BK3_FAILED)?;

        Ok(resp.data.masked_bk3)
    }

    fn establish_credential(
        &self,
        credentials: AppCreds,
        masked_bk3: &[u8],
        bmk: Option<&[u8]>,
        masked_unwrapping_key: Option<&[u8]>,
    ) -> Result<DdiEstablishCredentialCmdResp, AzihsmError> {
        // [TODO] Using hardcoded api_rev for now.
        let api_rev = ApiRev { major: 1, minor: 0 };
        let resp = ddi::get_establish_cred_encryption_key(&self.partition, api_rev.into())
            .map_err(|_| AZIHSM_GET_ESTABLISH_CREDENTIAL_ENCRYPTION_KEY_FAILED)?;

        let nonce = resp.data.nonce;
        let param_encryption_key =
            DeviceCredKey::new(&resp.data.pub_key, nonce).map_err(|_| AZIHSM_INTERNAL_ERROR)?;
        let (priv_key, pub_key) = param_encryption_key
            .generate_ephemeral_encryption_key()
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        let encrypted_credential = priv_key
            .encrypt_establish_credential(credentials.id, credentials.pin, nonce)
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        let bmk = bmk.unwrap_or_default(); // Empty BMK if not provided
        let masked_unwrapping_key = masked_unwrapping_key.unwrap_or_default(); // Empty masked unwrapping key if not provided

        ddi::establish_credential(
            &self.partition,
            api_rev.into(),
            encrypted_credential,
            pub_key,
            MborByteArray::from_slice(masked_bk3).map_err(|_| AZIHSM_INTERNAL_ERROR)?,
            MborByteArray::from_slice(bmk).map_err(|_| AZIHSM_INTERNAL_ERROR)?,
            MborByteArray::from_slice(masked_unwrapping_key).map_err(|_| AZIHSM_INTERNAL_ERROR)?,
        )
        .map_err(|_| AZIHSM_INVALID_CREDENTIALS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_open() {
        // Get the first available partition.
        let partition_list = partition_info_list();
        assert!(
            !partition_list.is_empty(),
            "No partitions available for testing"
        );

        let expected_partition_info = &partition_list[0];

        // Test that partition_open succeeds.
        let partition =
            partition_open(&expected_partition_info.path).expect("Failed to open partition");

        // Verify partition properties.
        let actual_partition_info = partition.part_info();
        assert_eq!(actual_partition_info.path, expected_partition_info.path);

        // Verify API revision range is valid.
        let api_rev_range = partition.api_rev_range();
        assert!(api_rev_range.min <= api_rev_range.max);
        assert!(api_rev_range.min.major > 0 || api_rev_range.min.minor > 0);
        assert!(api_rev_range.max.major > 0 || api_rev_range.max.minor > 0);
    }

    #[test]
    fn test_partition_info_list() {
        let partition_list = partition_info_list();

        // Should have at least one partition availabl.
        assert!(
            !partition_list.is_empty(),
            "Expected at least one partition to be available"
        );

        // Verify partition info structure
        for partition_info in &partition_list {
            assert!(
                !partition_info.path.is_empty(),
                "Partition path should not be empty"
            );
        }
    }
}

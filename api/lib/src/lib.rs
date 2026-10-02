// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod algo;
mod ddi;
mod error;
mod op;
mod partition;
mod resiliency;
mod session;
mod shared_types;
pub mod traits;

pub use algo::*;
pub use ddi::EVIDENCE_CHAIN_MAX_CERTS;
pub use ddi::LOCAL_MK_BACKUP_LEN;
pub use ddi::MASKED_SD_LEN;
pub use ddi::MAX_CERTS;
pub use ddi::PART_POLICY_LEN;
pub use ddi::POK_REMOTE_BACKUP_LEN;
pub use ddi::POLICY_BACKUP_PART_ID_LEN;
pub use ddi::POLICY_INFO_LEN;
pub use ddi::POLICY_MAX_KEY_LEN;
pub use ddi::PTA_CSR_MAX_LEN;
pub use ddi::PTA_REPORT_MAX_LEN;
pub use ddi::PartPolicy;
pub use ddi::PartPolicyBuilder;
pub use ddi::PolicyFlags;
pub use ddi::PolicyKeyKind;
pub use ddi::PolicyPubKey;
pub use ddi::PolicyVer;
pub use ddi::SD_MK_BACKUP_LEN;
pub use error::*;
pub use op::*;
pub use partition::*;
pub use resiliency::*;
pub use session::*;
pub use shared_types::*;
pub use traits::*;

pub type HsmResult<T> = Result<T, HsmError>;

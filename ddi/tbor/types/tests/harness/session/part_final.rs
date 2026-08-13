// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `PartFinal` command.
//!
//! Re-supplies the unified `PartPolicy` (so the device can re-derive
//! `POTAPubKey` and verify `SHA-384(part_policy) == policy_hash`), the PTA
//! certificate chain, and an optional prior `local_mk` backup to restore.
//! The emulator carries the certificate DERs out of band and describes them
//! with `(index, length)` [`CertDescriptor`]s. Native M1.0 firmware does not
//! consume certificate descriptors yet, so native tests send one
//! schema-required placeholder descriptor and no OOB payload.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::tbor_int::U16;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborPartFinalReq;
use azihsm_ddi_tbor_types::TborPartFinalResp;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use super::finish::SessionHandshake;

/// Issue `PartFinal` on the CO session represented by `session`.
///
/// `part_policy` must be exactly [`PART_POLICY_LEN`] and match the policy
/// bound at `PartInit`. `certs` are the PTA-chain certificate DERs
/// (root → PTA). Emulator builds transfer them out of band; native M1.0
/// builds intentionally ignore them and emit one placeholder descriptor.
/// `prev_local_mk_backup` is the optional prior backup to restore
/// (empty = first instantiation).
pub(crate) fn part_final(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session: &SessionHandshake,
    part_policy: &[u8],
    prev_local_mk_backup: &[u8],
    certs: &[&[u8]],
) -> Result<TborPartFinalResp, DdiError> {
    if part_policy.len() != PART_POLICY_LEN {
        return Err(DdiError::InvalidParameter);
    }
    let policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| DdiError::InvalidParameter)?;

    #[cfg(feature = "emu")]
    let (cert_descriptors, oob) = {
        let descriptors = if certs.is_empty() {
            vec![CertDescriptor::default()]
        } else {
            certs
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    // The wire format is `index: u8` + `length: u16`; reject
                    // (rather than silently truncate) inputs that don't fit.
                    let index = u8::try_from(i).map_err(|_| DdiError::InvalidParameter)?;
                    let length = u16::try_from(c.len()).map_err(|_| DdiError::InvalidParameter)?;
                    Ok(CertDescriptor {
                        index,
                        length: U16::new(length),
                    })
                })
                .collect::<Result<Vec<_>, DdiError>>()?
        };
        (descriptors, (!certs.is_empty()).then_some(certs))
    };

    #[cfg(not(feature = "emu"))]
    let (cert_descriptors, oob) = {
        let _ = certs;
        (vec![CertDescriptor::default()], None)
    };

    let req = TborPartFinalReq {
        session_id: session.session_id,
        part_policy: policy,
        cert_descriptors,
        prev_local_mk_backup: prev_local_mk_backup.to_vec(),
    };

    dev.exec_op_tbor(&req, oob, &mut None)
}

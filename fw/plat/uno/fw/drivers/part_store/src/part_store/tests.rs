// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host unit tests for the GSRAM-backed partition store.
//!
//! These run on the host target (`--target x86_64-unknown-linux-gnu`). The
//! fixed GSRAM slot is backed by a heap allocation under `cfg(test)` via
//! [`super::store_base`], so every [`Partition`] handle addresses real memory
//! rather than the on-target MMIO region.

use super::*;

/// Views a fixed-length test pattern as a `&DmaBuf` for the setters.
fn buf(bytes: &[u8]) -> &DmaBuf {
    // SAFETY: `DmaBuf::from_raw` requires `bytes` to lie in a DMA-addressable
    // region. That requirement is vacuous in these host unit tests: there is
    // no DMA engine off-target, and the branded buffer is only ever consumed
    // by CPU-side `copy_from_slice` into the partition store, never handed to
    // hardware. `bytes` outlives the returned borrow and `DmaBuf` is a `[u8]`
    // newtype, so the reference cast is layout-compatible.
    unsafe { DmaBuf::from_raw(bytes) }
}

/// `clear_state(Migrate)` must wipe per-tenant runtime state while keeping the
/// partition's provisioning material intact (mirrors the reference
/// `state.migrate()`). This is the regression guard for that split.
#[test]
fn preserves_provisioning_and_clears_tenant_state() {
    // A child module may address the parent module's private slot constructor
    // directly; `store_base()` backs it with real memory under `cfg(test)`.
    let pid = 7usize;

    // Provisioning material — must survive a migrate.
    let psk_co = [0x11u8; PSK_LEN];
    let psk_cu = [0x22u8; PSK_LEN];
    let guid = [0x33u8; GUID_LEN];
    let pta = [0x44u8; PUB_KEY_LEN];

    // Per-tenant state — must be cleared by a migrate.
    let nonce = [0x55u8; NONCE_LEN];
    let cred = [0x66u8; CREDENTIAL_LEN];
    let bk3 = [0x77u8; BK3_KEY_LEN];

    // Seed both sets of fields.
    {
        let p = Partition(pid);
        p.set_psk_co(buf(&psk_co)).unwrap();
        p.set_psk_cu(buf(&psk_cu)).unwrap();
        p.set_vm_launch_guid(buf(&guid)).unwrap();
        p.set_pta_pub_key(buf(&pta)).unwrap();
        p.set_bk3_initialized(true);

        p.set_nonce(buf(&nonce)).unwrap();
        p.set_credential(buf(&cred)).unwrap();
        p.set_bk3_session(buf(&bk3)).unwrap();
        p.set_ec_key_id(Some(HsmKeyId::from(0x0102u16)));
        p.set_se_key_id(Some(HsmKeyId::from(0x0304u16)));
        p.set_mk_key_id(Some(HsmKeyId::from(0x0506u16)));
        p.set_ups_key_id(Some(HsmKeyId::from(0x0708u16)));
        p.set_pta_key_id(Some(HsmKeyId::from(0x090au16)));
        p.set_local_mk_key_id(Some(HsmKeyId::from(0x0d0eu16)));
        p.set_ephemeral_mk_key_id(Some(HsmKeyId::from(0x0f10u16)));
        p.set_unwrapping_key_id(Some(HsmKeyId::from(0x0b0cu16)));
        p.set_pin_policy(PinPolicy {
            state: PinPolicyState::Lockout,
            delay_factor: 5,
            allowed_attempts: 3,
            lockout_time: [9u8; 8],
        });
    }
    {
        let mut p = Partition(pid);
        p.session_table_mut().fill(0xAB);
        p.session_meta_mut().fill(0xCD);
    }

    // Act.
    Partition(pid).clear_state(PartResetKind::Migrate);

    let p = Partition(pid);

    // Provisioning preserved.
    assert_eq!(&p.psk_co()[..], &psk_co[..], "psk_co must survive migrate");
    assert_eq!(&p.psk_cu()[..], &psk_cu[..], "psk_cu must survive migrate");
    assert_eq!(
        &p.vm_launch_guid()[..],
        &guid[..],
        "vm_launch_guid must survive migrate"
    );
    assert!(p.pta_pub_key_valid(), "pta_pub_key must survive migrate");
    assert_eq!(
        &p.pta_pub_key()[..],
        &pta[..],
        "pta_pub_key bytes must survive migrate"
    );
    assert!(p.bk3_initialized(), "bk3_initialized must survive migrate");

    // Per-tenant state cleared.
    assert_eq!(
        &p.nonce()[..],
        &[0u8; NONCE_LEN][..],
        "nonce must be cleared"
    );
    assert!(!p.credential_valid(), "credential must be cleared");
    assert!(!p.bk3_session_valid(), "bk3 session key must be cleared");
    assert!(p.ec_key_id().is_none(), "ec key handle must be cleared");
    assert!(p.se_key_id().is_none(), "se key handle must be cleared");
    assert!(p.mk_key_id().is_none(), "mk key handle must be cleared");
    assert!(p.ups_key_id().is_none(), "ups key handle must be cleared");
    assert!(p.pta_key_id().is_none(), "pta key handle must be cleared");
    assert!(
        p.unwrapping_key_id().is_none(),
        "unwrapping key handle must be cleared"
    );
    assert!(
        p.local_mk_key_id().is_none(),
        "local mk key handle must be cleared"
    );
    assert!(
        p.ephemeral_mk_key_id().is_none(),
        "ephemeral mk key handle must be cleared"
    );
    assert_eq!(
        p.session_table(),
        &[0u8; SESSION_TABLE_LEN],
        "session table must be cleared"
    );
    assert_eq!(p.session_meta(), &[0u8; 2], "session meta must be cleared");

    let policy = p.pin_policy();
    assert_eq!(
        policy.state,
        PinPolicyState::Ready,
        "pin policy must reset to default"
    );
    assert_eq!(policy.delay_factor, 0, "pin policy delay_factor must reset");
    assert_eq!(
        policy.allowed_attempts, 0,
        "pin policy allowed_attempts must reset"
    );
    assert_eq!(
        policy.lockout_time, [0u8; 8],
        "pin policy lockout_time must reset"
    );
}

/// `clear_identity` must zero the 16-byte id, drop the identity key handle
/// (dropping `partition_id_valid` with it), and zero the cached public key.
///
/// The NSSR migrate path relies on this to erase the stale `id_key_id` before
/// re-provisioning a fresh identity, so this guards that the identity fields
/// don't linger and dangle at a deleted vault key.
#[test]
fn clear_identity_zeros_id_handle_and_pub_key() {
    let pid = 9usize;

    let id = [0x5Au8; ID_LEN];
    let id_pub = [0xA5u8; PUB_KEY_LEN];

    {
        let mut p = Partition(pid);
        p.set_id(buf(&id)).unwrap();
        p.set_id_key_id(Some(HsmKeyId::from(0x1234u16)));
        p.id_pub_key_mut().copy_from_slice(&id_pub);
    }

    // Precondition: identity is present.
    {
        let p = Partition(pid);
        assert!(p.id_key_id().is_some(), "id key handle must be seeded");
        assert_eq!(&p.id()[..], &id[..], "id must be seeded");
    }

    // Act.
    Partition(pid).clear_identity();

    let p = Partition(pid);
    assert!(p.id_key_id().is_none(), "id key handle must be cleared");
    assert_eq!(&p.id()[..], &[0u8; ID_LEN][..], "id must be zeroed");
    assert_eq!(
        &p.id_pub_key()[..],
        &[0u8; PUB_KEY_LEN][..],
        "id public key must be zeroed"
    );
}

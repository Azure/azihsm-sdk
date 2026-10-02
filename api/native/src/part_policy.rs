// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition-policy builder for the native C API.
//!
//! The `azihsm_sess_ex_part_init` / `azihsm_sess_ex_part_final` entry
//! points consume the partition policy as an opaque fixed-size image
//! (`PART_POLICY_LEN` bytes). Rather than require C callers to lay out
//! that image by poking raw byte offsets, this module exposes a small
//! opaque builder that sets named, typed fields and then serializes the
//! canonical wire image into a caller-provided buffer.
//!
//! The on-wire format is unchanged: [`azihsm_part_policy_build`] emits
//! exactly the bytes the init/final handlers already accept, so the
//! builder is purely an ergonomic, ABI-additive convenience.

use super::*;

/// Opaque partition-policy builder handle.
///
/// Created by [`azihsm_part_policy_builder_new`], populated through the
/// `azihsm_part_policy_builder_set_*` setters, serialized with
/// [`azihsm_part_policy_build`], and released with
/// [`azihsm_part_policy_builder_free`].
pub struct AzihsmPartPolicyBuilder {
    inner: api::PartPolicyBuilder,
}

/// Apply a fluent setter to the boxed builder in place.
///
/// The host [`api::PartPolicyBuilder`] setters consume and return `self`;
/// this helper swaps the inner builder out, applies `f`, and stores the
/// result back, so the C handle keeps a stable address.
#[allow(unsafe_code)]
fn with_builder<F>(builder: *mut AzihsmPartPolicyBuilder, f: F) -> Result<(), AzihsmStatus>
where
    F: FnOnce(api::PartPolicyBuilder) -> api::PartPolicyBuilder,
{
    if builder.is_null() {
        return Err(AzihsmStatus::InvalidArgument);
    }
    // Safety: non-null, caller guarantees it points at a live builder.
    let b = unsafe { &mut *builder };
    let taken = std::mem::replace(&mut b.inner, api::PartPolicyBuilder::new());
    b.inner = f(taken);
    Ok(())
}

/// @brief Allocate a new partition-policy builder
///
/// The returned handle starts from a policy whose version defaults to
/// `major = 1, minor = 0` with every other field zeroed; set the fields
/// you need through the `azihsm_part_policy_builder_set_*` functions,
/// then serialize it with `azihsm_part_policy_build`. Release it with
/// `azihsm_part_policy_builder_free`.
///
/// Oversized key / `info` / backing-id input is rejected at
/// `azihsm_part_policy_build` time (returning `AZIHSM_INVALID_ARGUMENT`)
/// rather than silently truncated.
///
/// @return A non-NULL builder handle on success, or NULL on allocation
///         failure.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn azihsm_part_policy_builder_new() -> *mut AzihsmPartPolicyBuilder {
    Box::into_raw(Box::new(AzihsmPartPolicyBuilder {
        inner: api::PartPolicyBuilder::new(),
    }))
}

/// @brief Free a partition-policy builder
///
/// Releases a handle returned by `azihsm_part_policy_builder_new`.
/// Passing NULL is a no-op. The handle must not be used afterwards.
///
/// @param[in] builder Builder handle to free (may be NULL)
///
/// # Safety
///
/// - `builder` must be NULL or a handle returned by
///   `azihsm_part_policy_builder_new` that has not already been freed.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_free(builder: *mut AzihsmPartPolicyBuilder) {
    if !builder.is_null() {
        // Safety: reclaim the Box allocated in `_new`.
        drop(unsafe { Box::from_raw(builder) });
    }
}

/// @brief Set the policy version (`major.minor`)
///
/// @param[in] builder Builder handle
/// @param[in] major Major version number
/// @param[in] minor Minor version number
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL handle
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_version(
    builder: *mut AzihsmPartPolicyBuilder,
    major: u8,
    minor: u8,
) -> AzihsmStatus {
    abi_boundary(|| with_builder(builder, |b| b.version(major, minor)))
}

/// @brief Set the POTA (Partition Owner Trust Anchor) public key
///
/// @param[in] builder Builder handle
/// @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
/// @param[in] key Raw public-key bytes
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_pota_key(
    builder: *mut AzihsmPartPolicyBuilder,
    kind: u16,
    key: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(key)?.try_into()?;
        with_builder(builder, |b| b.pota_key(api::PolicyKeyKind(kind), raw))
    })
}

/// @brief Set the SATA (Sealing Authority Trust Anchor) public key
///
/// @param[in] builder Builder handle
/// @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
/// @param[in] key Raw public-key bytes
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_sata_key(
    builder: *mut AzihsmPartPolicyBuilder,
    kind: u16,
    key: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(key)?.try_into()?;
        with_builder(builder, |b| b.sata_key(api::PolicyKeyKind(kind), raw))
    })
}

/// @brief Set the SAPOTA (Sealing Authority's POTA) public key
///
/// @param[in] builder Builder handle
/// @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
/// @param[in] key Raw public-key bytes
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_sapota_key(
    builder: *mut AzihsmPartPolicyBuilder,
    kind: u16,
    key: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(key)?.try_into()?;
        with_builder(builder, |b| b.sapota_key(api::PolicyKeyKind(kind), raw))
    })
}

/// @brief Set the backing-partition identifier
///
/// @param[in] builder Builder handle
/// @param[in] id Backing-partition identifier bytes
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_backup_part_id(
    builder: *mut AzihsmPartPolicyBuilder,
    id: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(id)?.try_into()?;
        with_builder(builder, |b| b.backup_part_id(raw))
    })
}

/// @brief Set the backing-partition public key
///
/// @param[in] builder Builder handle
/// @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
/// @param[in] key Raw public-key bytes
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_backup_part_pub_key(
    builder: *mut AzihsmPartPolicyBuilder,
    kind: u16,
    key: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(key)?.try_into()?;
        with_builder(builder, |b| {
            b.backup_part_pub_key(api::PolicyKeyKind(kind), raw)
        })
    })
}

/// @brief Set the caller-provided opaque `info` field
///
/// @param[in] builder Builder handle
/// @param[in] info Opaque info bytes
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - the buffer pointer must be NULL or point to a valid `azihsm_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_info(
    builder: *mut AzihsmPartPolicyBuilder,
    info: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(info)?.try_into()?;
        with_builder(builder, |b| b.info(raw))
    })
}

/// @brief Set the policy flag bits
///
/// @param[in] builder Builder handle
/// @param[in] flags Raw flag bits (see the `PolicyFlags` definition)
/// @return `AZIHSM_SUCCESS`, or `AZIHSM_INVALID_ARGUMENT` on a NULL handle
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_builder_set_flags(
    builder: *mut AzihsmPartPolicyBuilder,
    flags: u8,
) -> AzihsmStatus {
    abi_boundary(|| with_builder(builder, |b| b.flags(api::PolicyFlags::from_bits(flags))))
}

/// @brief Serialize the policy into its canonical wire image
///
/// Writes exactly `PART_POLICY_LEN` bytes — the image accepted by
/// `azihsm_sess_ex_part_init` / `azihsm_sess_ex_part_final` — into
/// `out`. If `out` is too small, sets `out.len` to the required size and
/// returns `AZIHSM_BUFFER_TOO_SMALL` without writing. The builder is left
/// usable (unchanged) for further serialization.
///
/// @param[in] builder Builder handle
/// @param[out] out Buffer to receive the serialized policy image
/// @return `AZIHSM_SUCCESS`, `AZIHSM_INVALID_ARGUMENT` on a NULL handle /
///         buffer, or `AZIHSM_BUFFER_TOO_SMALL` if `out` is too small
///
/// # Safety
///
/// - `builder` must be a live handle from `azihsm_part_policy_builder_new`.
/// - `out` must be a valid pointer to an `azihsm_buffer` with writable
///   backing storage of its advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_policy_build(
    builder: *mut AzihsmPartPolicyBuilder,
    out: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        if builder.is_null() {
            return Err(AzihsmStatus::InvalidArgument);
        }
        // Safety: non-null, caller guarantees it points at a live builder.
        let b = unsafe { &mut *builder };
        let output = deref_mut_ptr(out)?;
        let policy = b.inner.clone().build()?;
        copy_to_buffer(output, policy.as_bytes())
    })
}

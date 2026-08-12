// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

// Security-domain provisioning helper for the sealing round-trip test.
//
// `SdSealingKeyGen` needs a partition in the `Initialized` state on a CO
// session, reached via the full provisioning flow (rotate CO PSK ->
// `PartInit` -> POTA-anchored PTA chain -> `PartFinal`) — the same sequence
// a real C consumer performs, except the consumer brings its own PKI chain.
//
// The chain is built with the platform host crypto (OpenSSL on Linux,
// BCrypt on Windows), no HSM session. Excluded from the mock backend; runs
// on the emu and hardware backends.
#if !defined(AZIHSM_FEATURE_MOCK)

/// Provision a freshly-reset partition's security domain and return a live,
/// provisioned Crypto-Officer session handle (`Initialized` state):
/// open CO under the default PSK, rotate it, reopen, `PartInit`, build a
/// POTA-anchored root -> PTA chain from the CSR, then `PartFinal`.
///
/// Records a gtest failure and returns 0 on error. The caller owns the
/// returned handle and must close it with `azihsm_sess_close`.
///
/// @param part_handle An opened, factory-reset partition handle.
/// @return A provisioned CO session handle, or 0 on failure.
azihsm_handle provision_sd_co_session(azihsm_handle part_handle);

/// Opaque host CA key (defined in `sd_provision.cpp`). Exposed only as a
/// `std::shared_ptr` handle so a caller can keep the SATA anchor alive
/// across the evidence-building step without seeing the definition.
class CaKey;

/// A provisioned backing-partition security-domain context: the live CO
/// session plus the exact policy image, partition-identity public key, and
/// SATA anchor key that the create-backup call and its evidence depend on.
struct SdBackingContext
{
    /// Provisioned CO session handle (`Initialized`); 0 on failure.
    azihsm_handle session = 0;
    /// Exact 484-byte backing-partition policy image.
    std::vector<uint8_t> policy;
    /// Raw P-384 partition-identity public key (`X ‖ Y`, 96 B).
    std::vector<uint8_t> pid_pub;
    /// SATA anchor key that roots the partition-owner evidence chain.
    std::shared_ptr<CaKey> sata_key;
    /// POTA anchor key that roots the CSR -> PTA chain. Retained so a
    /// restore target can re-provision under the same policy.
    std::shared_ptr<CaKey> pota_key;
    /// Device-local master-key (`local_mk`) backup emitted by `PartFinal`.
    std::vector<uint8_t> local_mk_backup;
};

/// Provision `part_handle` with a backing-partition policy that names this
/// partition (via its `PartInfo` PID / raw public key) as the backup
/// backing partition, anchored to a freshly-generated internal SATA key.
///
/// Records a gtest failure and returns a default `SdBackingContext`
/// (`session == 0`) on error. The caller owns `session` and must close it
/// with `azihsm_sess_close`. `allow_peer_cloning` sets that policy flag
/// (default `true`); clear it to exercise the peer-cloning policy gate.
SdBackingContext provision_sd_backing_co_session(
    azihsm_handle part_handle,
    bool allow_peer_cloning = true
);

/// Re-provision `part_handle` — the same physical backing partition after a
/// simulated reboot (`azihsm_part_reset`) — as a restore target, reusing
/// `prev`'s policy and SATA/POTA anchors and supplying
/// `prev.local_mk_backup` to `PartFinal` for device-local master-key
/// continuity. This reproduces the receiver (device-2) side of a restore
/// round trip.
///
/// Records a gtest failure and returns a default `SdBackingContext`
/// (`session == 0`) on error. The caller owns `session` and must close it
/// with `azihsm_sess_close`.
SdBackingContext provision_sd_restore_target(
    azihsm_handle part_handle,
    const SdBackingContext &prev
);

/// A minted SD sealing key: its masked private-key blob and a COSE_Sign1
/// `KeyReport` attesting it.
struct SealingKeyMaterial
{
    /// Masked sealing-key blob (180 B).
    std::vector<uint8_t> masked;
    /// COSE_Sign1 `KeyReport` DER bytes.
    std::vector<uint8_t> report;
};

/// Mint an SD sealing key on `session` and return its 180-byte masked blob
/// plus a `KeyReport` built over 128 zero report-data bytes. Records a
/// gtest failure and returns empty vectors on error.
SealingKeyMaterial sealing_key_and_report(azihsm_handle session);

/// Owns the DER bytes and `azihsm_buffer` arrays backing one party's SD
/// attestation evidence and exposes a wired-up `azihsm_sd_evidence` that
/// points into them. The holder must outlive the create-backup call.
///
/// Copies are forbidden (the internal `azihsm_buffer` / `azihsm_sd_evidence`
/// pointers are self-referential); moves re-point them at the moved-to
/// storage.
class SdEvidenceHolder
{
  public:
    SdEvidenceHolder() = default;
    SdEvidenceHolder(const SdEvidenceHolder &) = delete;
    SdEvidenceHolder &operator=(const SdEvidenceHolder &) = delete;
    SdEvidenceHolder(SdEvidenceHolder &&other) noexcept
    {
        *this = std::move(other);
    }
    SdEvidenceHolder &operator=(SdEvidenceHolder &&other) noexcept
    {
        mfgr_root_ = std::move(other.mfgr_root_);
        mfgr_leaf_ = std::move(other.mfgr_leaf_);
        owner_root_ = std::move(other.owner_root_);
        owner_leaf_ = std::move(other.owner_leaf_);
        po_root_ = std::move(other.po_root_);
        po_leaf_ = std::move(other.po_leaf_);
        report_ = std::move(other.report_);
        wire();
        return *this;
    }

    /// The wired-up evidence view; valid for this holder's lifetime.
    const azihsm_sd_evidence &get() const
    {
        return ev_;
    }

  private:
    friend SdEvidenceHolder build_receiver_evidence(
        const SdBackingContext &ctx,
        const std::vector<uint8_t> &report
    );

    /// Re-point the `azihsm_buffer` arrays and `azihsm_sd_evidence` at the
    /// currently-held vectors. Called after population and every move.
    void wire();

    std::vector<uint8_t> mfgr_root_;
    std::vector<uint8_t> mfgr_leaf_;
    std::vector<uint8_t> owner_root_;
    std::vector<uint8_t> owner_leaf_;
    std::vector<uint8_t> po_root_;
    std::vector<uint8_t> po_leaf_;
    std::vector<uint8_t> report_;
    azihsm_buffer mfgr_bufs_[2]{};
    azihsm_buffer owner_bufs_[2]{};
    azihsm_buffer po_bufs_[2]{};
    azihsm_buffer report_buf_{};
    azihsm_sd_evidence ev_{};
};

/// Build the receiver's three-chain SD attestation evidence for
/// `ctx.pid_pub`: the manufacturer and owner chains are rooted at fresh
/// CAs, and the partition-owner chain is rooted at `ctx.sata_key`. Every
/// leaf certifies `ctx.pid_pub` (the report signer); `report` is the
/// attestation report. Records a gtest failure and returns an empty holder
/// on error.
SdEvidenceHolder build_receiver_evidence(
    const SdBackingContext &ctx,
    const std::vector<uint8_t> &report
);

#endif // !defined(AZIHSM_FEATURE_MOCK)

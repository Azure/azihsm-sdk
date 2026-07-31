// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdRestorePeerBackup` round trip against the emulator.
//
// Self-backup "reboot" flow on one physical partition: device 1 provisions
// a peer-cloning-enabled backing partition, creates the security domain,
// and creates a **peer** backup of it (capturing `pok_peer_backup`,
// `sd_mk_backup`, and the `local_mk_backup` from `PartFinal`); the same
// partition is factory-reset (a simulated reboot) and re-provisioned as a
// restore target — reusing the policy and SATA/POTA anchors and supplying
// the captured `local_mk_backup` so the sealing key unmasks — and the
// security domain is restored from the peer backup via
// `azihsm_sess_ex_sd_restore_peer_backup`. A successful restore is itself
// the correctness check: the HPKE open only succeeds if the receiver key
// and the attested source-peer key match those that sealed the backup.
//
// Like the create/reseal/restore tests this needs the two-phase TBOR HPKE
// handshake and a fully provisioned partition, which only the emu backend
// provides, so it is gated to `AZIHSM_FEATURE_EMU`.
#if defined(AZIHSM_FEATURE_EMU)

#include <array>
#include <azihsm_api.h>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/part_list_handle.hpp"
#include "utils/sd_provision.hpp"
#include "utils/utils.hpp"

namespace
{
// Pinned wire lengths. Mirror the `azihsm_ddi_tbor_types` constants
// (`MASKED_SEALING_KEY_LEN`, `POK_REMOTE_BACKUP_LEN`, `MASKED_SD_LEN`,
// `SD_MK_BACKUP_LEN`), which are not exposed in the C header.
constexpr uint32_t kMaskedSealingKeyLen = 180;
constexpr uint32_t kPokRemoteBackupLen = 161;
constexpr uint32_t kMaskedSdLen = 180;
constexpr uint32_t kSdMkBackupLen = 164;

bool any_nonzero(const std::vector<uint8_t> &bytes)
{
    for (uint8_t b : bytes)
    {
        if (b != 0)
        {
            return true;
        }
    }
    return false;
}

// Create the security domain, capturing both the 180-byte device-local
// backup (the input CreatePeerBackup recovers BKS3 from) and the 164-byte
// masking-key backup (the previous SDMK backup RestorePeerBackup consumes).
// Sizes the three output buffers via the probe/fill convention. Records a
// gtest failure and returns false on error.
bool create_sd_capture(
    azihsm_handle session,
    std::vector<uint8_t> &masked,
    const azihsm_sd_evidence &receiver,
    const std::vector<uint8_t> &policy,
    std::vector<uint8_t> &out_local,
    std::vector<uint8_t> &out_mk
)
{
    azihsm_buffer masked_buf{ masked.data(), static_cast<uint32_t>(masked.size()) };
    azihsm_buffer policy_buf{ const_cast<uint8_t *>(policy.data()),
                              static_cast<uint32_t>(policy.size()) };
    azihsm_sess_ex_sd_create_remote_backup_params params{
        &masked_buf,
        &receiver,
        &policy_buf,
    };

    std::vector<uint8_t> remote;
    std::vector<uint8_t> local;
    std::vector<uint8_t> mk;
    azihsm_buffer remote_buf{ nullptr, 0 };
    azihsm_buffer local_buf{ nullptr, 0 };
    azihsm_buffer mk_buf{ nullptr, 0 };
    azihsm_status err = AZIHSM_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = azihsm_sess_ex_sd_create_remote_backup(
            session,
            &params,
            &remote_buf,
            &local_buf,
            &mk_buf
        );
        if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }
        if (remote_buf.len > remote.size())
        {
            remote.resize(remote_buf.len);
        }
        if (local_buf.len > local.size())
        {
            local.resize(local_buf.len);
        }
        if (mk_buf.len > mk.size())
        {
            mk.resize(mk_buf.len);
        }
        remote_buf = { remote.data(), static_cast<uint32_t>(remote.size()) };
        local_buf = { local.data(), static_cast<uint32_t>(local.size()) };
        mk_buf = { mk.data(), static_cast<uint32_t>(mk.size()) };
    }
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "create remote backup failed: " << err;
        return false;
    }
    local.resize(local_buf.len);
    mk.resize(mk_buf.len);
    out_local = std::move(local);
    out_mk = std::move(mk);
    return true;
}

// Run the create-peer-backup call, sizing the single output buffer via the
// probe/fill convention. Returns the final status and, on success, sizes
// `dst` to the bytes written.
azihsm_status create_peer_fill(
    azihsm_handle session,
    const azihsm_sess_ex_sd_create_peer_backup_params *params,
    std::vector<uint8_t> &dst
)
{
    azihsm_buffer dst_buf{ nullptr, 0 };
    azihsm_status err = AZIHSM_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = azihsm_sess_ex_sd_create_peer_backup(session, params, &dst_buf);
        if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }
        if (dst_buf.len > dst.size())
        {
            dst.resize(dst_buf.len);
        }
        dst_buf = { dst.data(), static_cast<uint32_t>(dst.size()) };
    }
    if (err == AZIHSM_STATUS_SUCCESS)
    {
        dst.resize(dst_buf.len);
    }
    return err;
}

// Run the restore-peer call, sizing both output buffers via the probe/fill
// convention. The FFI validates the output buffers before restoring, so a
// too-small buffer never performs the restore. Returns the final status
// and, on success, sizes `pok_local` / `sd_mk` to the bytes written.
azihsm_status restore_peer_fill(
    azihsm_handle session,
    const azihsm_sess_ex_sd_restore_peer_backup_params *params,
    std::vector<uint8_t> &pok_local,
    std::vector<uint8_t> &sd_mk
)
{
    azihsm_buffer pok_buf{ nullptr, 0 };
    azihsm_buffer mk_buf{ nullptr, 0 };
    azihsm_status err = AZIHSM_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = azihsm_sess_ex_sd_restore_peer_backup(session, params, &pok_buf, &mk_buf);
        if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }
        if (pok_buf.len > pok_local.size())
        {
            pok_local.resize(pok_buf.len);
        }
        if (mk_buf.len > sd_mk.size())
        {
            sd_mk.resize(mk_buf.len);
        }
        pok_buf = { pok_local.data(), static_cast<uint32_t>(pok_local.size()) };
        mk_buf = { sd_mk.data(), static_cast<uint32_t>(sd_mk.size()) };
    }
    if (err == AZIHSM_STATUS_SUCCESS)
    {
        pok_local.resize(pok_buf.len);
        sd_mk.resize(mk_buf.len);
    }
    return err;
}
} // namespace

/// Test fixture for security-domain restore-peer-backup
/// (`azihsm_sess_ex_sd_restore_peer_backup`).
class azihsm_sd_restore_peer_backup : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Open and factory-reset a partition into a clean state. Records a
    // gtest failure and returns 0 on error; the returned handle must be
    // closed by the caller.
    static azihsm_handle open_reset_partition(std::vector<azihsm_char> &path)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle, test_api_rev());
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "azihsm_part_open failed: " << err;
            return 0;
        }

        err = azihsm_part_reset(part_handle);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "azihsm_part_reset failed: " << err;
            azihsm_part_close(part_handle);
            return 0;
        }

        return part_handle;
    }
};

// Happy path: create a peer backup on one incarnation, then restore it on a
// rebooted (factory-reset, re-provisioned) incarnation of the same
// partition; the restore returns non-zero refreshed device-local backups of
// the pinned lengths.
TEST_F(azihsm_sd_restore_peer_backup, restore_peer_backup_roundtrip)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        // Device 1: provision, create the SD, and create a peer backup,
        // capturing the peer backup and the previous masking-key backup.
        SdBackingContext dev1 = provision_sd_backing_co_session(part_handle);
        if (dev1.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        // Safety net for an early ASSERT exit; the happy path closes the
        // session explicitly before the reboot (zeroing the handle), which
        // makes this guard a no-op.
        auto dev1_guard = scope_guard::make_scope_exit([&dev1] {
            if (dev1.session != 0)
            {
                azihsm_sess_close(dev1.session);
            }
        });

        SealingKeyMaterial key = sealing_key_and_report(dev1.session);
        ASSERT_EQ(key.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(key.report.empty());

        // Self-peer backup: the same attested key is both source and
        // receiver.
        SdEvidenceHolder evidence = build_receiver_evidence(dev1, key.report);

        std::vector<uint8_t> local_backup;
        std::vector<uint8_t> prev_sd_mk;
        ASSERT_TRUE(create_sd_capture(
            dev1.session,
            key.masked,
            evidence.get(),
            dev1.policy,
            local_backup,
            prev_sd_mk
        ));
        ASSERT_EQ(local_backup.size(), kMaskedSdLen);
        ASSERT_EQ(prev_sd_mk.size(), kSdMkBackupLen);

        // Seal a peer backup to our own attested identity as destination.
        azihsm_buffer masked_buf{ key.masked.data(), static_cast<uint32_t>(key.masked.size()) };
        azihsm_buffer policy_buf{ dev1.policy.data(), static_cast<uint32_t>(dev1.policy.size()) };
        azihsm_buffer local_buf{ local_backup.data(), static_cast<uint32_t>(local_backup.size()) };
        azihsm_sess_ex_sd_create_peer_backup_params create_params{
            &masked_buf,
            &evidence.get(),
            &policy_buf,
            &local_buf,
        };
        std::vector<uint8_t> peer_backup;
        ASSERT_EQ(
            create_peer_fill(dev1.session, &create_params, peer_backup),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(peer_backup.size(), kPokRemoteBackupLen);

        // Close device 1's session before the reboot.
        azihsm_sess_close(dev1.session);
        dev1.session = 0;

        // Device 2 (reboot): factory-reset the same partition and
        // re-provision it as a restore target, reusing device 1's policy
        // and anchors and its captured local_mk backup.
        auto err = azihsm_part_reset(part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "reboot reset failed";
        SdBackingContext dev2 = provision_sd_restore_target(part_handle, dev1);
        if (dev2.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&dev2] { azihsm_sess_close(dev2.session); });

        // Restore the security domain from device 1's peer backup.
        azihsm_buffer r_masked_buf{ key.masked.data(), static_cast<uint32_t>(key.masked.size()) };
        azihsm_buffer r_policy_buf{ dev2.policy.data(), static_cast<uint32_t>(dev2.policy.size()) };
        azihsm_buffer peer_buf{ peer_backup.data(), static_cast<uint32_t>(peer_backup.size()) };
        azihsm_buffer prev_mk_buf{ prev_sd_mk.data(), static_cast<uint32_t>(prev_sd_mk.size()) };
        azihsm_sess_ex_sd_restore_peer_backup_params restore_params{
            &r_masked_buf, &evidence.get(), &r_policy_buf, &peer_buf, &prev_mk_buf,
        };

        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        ASSERT_EQ(
            restore_peer_fill(dev2.session, &restore_params, pok_local, sd_mk),
            AZIHSM_STATUS_SUCCESS
        );

        // Refreshed device-local backups: 180-byte local pok backup and
        // 164-byte masking-key backup, both non-zero.
        ASSERT_EQ(pok_local.size(), kMaskedSdLen);
        ASSERT_TRUE(any_nonzero(pok_local)) << "pok_local_backup must not be all-zero";
        ASSERT_EQ(sd_mk.size(), kSdMkBackupLen);
        ASSERT_TRUE(any_nonzero(sd_mk)) << "sd_mk_backup must not be all-zero";
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the restore is performed.
TEST_F(azihsm_sd_restore_peer_backup, restore_peer_backup_null_params)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        SdBackingContext ctx = provision_sd_backing_co_session(part_handle);
        if (ctx.session == 0)
        {
            return;
        }
        auto sess_guard = scope_guard::make_scope_exit([&ctx] { azihsm_sess_close(ctx.session); });

        azihsm_buffer pok_local{ nullptr, 0 };
        azihsm_buffer sd_mk{ nullptr, 0 };
        auto err = azihsm_sess_ex_sd_restore_peer_backup(ctx.session, nullptr, &pok_local, &sd_mk);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

#endif // defined(AZIHSM_FEATURE_EMU)

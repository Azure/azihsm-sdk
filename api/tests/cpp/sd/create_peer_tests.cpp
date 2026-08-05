// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdCreatePeerBackup` round trip against the emulator.
//
// Self-peer backup on one partition: provision a peer-cloning-enabled
// backing partition, mint an SD sealing key, `CreateSD`
// (`azihsm_sess_ex_sd_create_remote_backup`) to obtain the device-local
// backup, then `azihsm_sess_ex_sd_create_peer_backup` to HPKE-Auth-seal
// BKS3 to the destination peer (our own attested identity). A successful
// seal is itself the correctness check.
//
// Like the create/reseal/restore tests this needs the two-phase TBOR HPKE
// handshake and a fully provisioned partition, which the mock backend does
// not implement, so it is excluded from the mock lane and runs on the emu
// and hardware backends.
#if !defined(AZIHSM_FEATURE_MOCK)

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
// (`MASKED_SEALING_KEY_LEN`, `MASKED_SD_LEN`, `POK_REMOTE_BACKUP_LEN`),
// which are not exposed in the C header.
constexpr uint32_t kMaskedSealingKeyLen = 180;
constexpr uint32_t kMaskedSdLen = 180;
constexpr uint32_t kPokRemoteBackupLen = 161;

// Create the security domain and capture the 180-byte device-local backup
// that CreatePeerBackup recovers BKS3 from. Sizes the three output buffers
// via the probe/fill convention. Records a gtest failure and returns false
// on error.
bool create_sd_local_backup(
    azihsm_handle session,
    std::vector<uint8_t> &masked,
    const azihsm_sd_evidence &receiver,
    const std::vector<uint8_t> &policy,
    std::vector<uint8_t> &out_local
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
    out_local = std::move(local);
    return true;
}

// Run the create-peer-backup call, sizing the single output buffer via the
// probe/fill convention. The FFI validates the output buffer before
// sealing, so a too-small buffer never performs the seal. Returns the final
// status and, on success, sizes `dst` to the bytes written.
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
} // namespace

/// Test fixture for security-domain create-peer-backup
/// (`azihsm_sess_ex_sd_create_peer_backup`).
class azihsm_sd_create_peer_backup : public ::testing::Test
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

// Happy path: create the security domain, then a peer backup of it; the
// peer backup is a fresh 161-byte, non-zero HPKE-Auth seal.
TEST_F(azihsm_sd_create_peer_backup, create_peer_backup_roundtrip)
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
            return; // provisioning recorded its own failure
        }
        auto sess_guard = scope_guard::make_scope_exit([&ctx] { azihsm_sess_close(ctx.session); });

        SealingKeyMaterial key = sealing_key_and_report(ctx.session);
        ASSERT_EQ(key.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(key.report.empty());

        // Self-peer backup: the same attested key is sender and destination.
        SdEvidenceHolder evidence = build_receiver_evidence(ctx, key.report);

        // Create the security domain to obtain the device-local backup.
        std::vector<uint8_t> local_backup;
        ASSERT_TRUE(create_sd_local_backup(
            ctx.session,
            key.masked,
            evidence.get(),
            ctx.policy,
            local_backup
        ));
        ASSERT_EQ(local_backup.size(), kMaskedSdLen);

        // Seal a peer backup to our own attested identity as destination.
        azihsm_buffer masked_buf{ key.masked.data(), static_cast<uint32_t>(key.masked.size()) };
        azihsm_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        azihsm_buffer local_buf{ local_backup.data(), static_cast<uint32_t>(local_backup.size()) };
        azihsm_sess_ex_sd_create_peer_backup_params params{
            &masked_buf,
            &evidence.get(),
            &policy_buf,
            &local_buf,
        };

        std::vector<uint8_t> peer_backup;
        ASSERT_EQ(create_peer_fill(ctx.session, &params, peer_backup), AZIHSM_STATUS_SUCCESS);

        // Peer backup: HPKE-Auth seal of BKS3, 161 B, non-zero.
        ASSERT_EQ(peer_backup.size(), kPokRemoteBackupLen);
        ASSERT_TRUE(any_nonzero(peer_backup)) << "pok_peer_backup must not be all-zero";
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the peer backup is created.
TEST_F(azihsm_sd_create_peer_backup, create_peer_backup_null_params)
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

        azihsm_buffer out{ nullptr, 0 };
        auto err = azihsm_sess_ex_sd_create_peer_backup(ctx.session, nullptr, &out);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

#endif // !defined(AZIHSM_FEATURE_MOCK)

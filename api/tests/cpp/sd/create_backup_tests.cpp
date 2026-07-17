// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdCreateRemoteBackup` round trip against the emulator.
//
// Provisions a partition whose policy names itself as the backup backing
// partition (`provision_sd_backing_co_session`), mints an SD sealing key,
// attests it via the masked-blob `KeyReport`, builds the receiver's
// three-chain attestation evidence, then calls
// `azihsm_sess_ex_sd_create_remote_backup` and validates the three returned
// backups. This is a self-backup (sender == receiver): the partition seals
// to its own attested identity key.
//
// The whole file needs the two-phase TBOR HPKE handshake and a fully
// provisioned partition, which only the emu (in-process firmware) backend
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
// Pinned wire lengths of the create-backup outputs. Mirror the
// `azihsm_ddi_tbor_types` constants (`POK_REMOTE_BACKUP_LEN`,
// `MASKED_SD_LEN`, `SD_MK_BACKUP_LEN`, `MASKED_SEALING_KEY_LEN`), which are
// not exposed in the C header.
constexpr uint32_t kPokRemoteBackupLen = 161;
constexpr uint32_t kPokLocalBackupLen = 180;
constexpr uint32_t kSdMkBackupLen = 164;
constexpr uint32_t kMaskedSealingKeyLen = 180;

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

// Run the create-backup call, sizing the three output buffers via the
// probe/fill convention. The FFI validates each output buffer in sequence
// and reports the first that is too small, so a single len=0 probe only
// sizes the first buffer; loop until every buffer is large enough. Buffer
// validation runs before the domain is created, so a too-small buffer never
// consumes the one-shot command. Returns the final status and sizes the
// caller vectors to the bytes written on success.
azihsm_status create_backup_fill(
    azihsm_handle session,
    const azihsm_sess_ex_sd_create_remote_backup_params *params,
    std::vector<uint8_t> &remote,
    std::vector<uint8_t> &local,
    std::vector<uint8_t> &mk
)
{
    azihsm_buffer remote_buf{ nullptr, 0 };
    azihsm_buffer local_buf{ nullptr, 0 };
    azihsm_buffer mk_buf{ nullptr, 0 };
    azihsm_status err = AZIHSM_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = azihsm_sess_ex_sd_create_remote_backup(
            session,
            params,
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
    if (err == AZIHSM_STATUS_SUCCESS)
    {
        remote.resize(remote_buf.len);
        local.resize(local_buf.len);
        mk.resize(mk_buf.len);
    }
    return err;
}
} // namespace

/// Test fixture for security-domain create-remote-backup
/// (`azihsm_sess_ex_sd_create_remote_backup`).
class azihsm_sd_create_backup : public ::testing::Test
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

    // Open a Crypto-Officer security-domain session on an already-open
    // partition handle. Records a gtest failure and returns 0 on error;
    // the returned handle must be closed by the caller.
    static azihsm_handle open_sd_session(azihsm_handle part_handle)
    {
        azihsm_handle sess_handle = 0;
        azihsm_session_psk psk{ 0, nullptr };
        auto err = azihsm_sess_ex_open(
            part_handle,
            &psk,
            AZIHSM_SESSION_EX_TYPE_AUTHENTICATED,
            &sess_handle
        );
        if (err != AZIHSM_STATUS_SUCCESS || sess_handle == 0)
        {
            ADD_FAILURE() << "azihsm_sess_ex_open failed: " << err;
            return 0;
        }
        return sess_handle;
    }
};

// Happy path: creating a security domain on a partition that names itself
// as the backing partition returns three non-zero backups of the pinned
// wire lengths.
TEST_F(azihsm_sd_create_backup, create_backup_roundtrip)
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

        SealingKeyMaterial sealing = sealing_key_and_report(ctx.session);
        ASSERT_EQ(sealing.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(sealing.report.empty());

        SdEvidenceHolder evidence = build_receiver_evidence(ctx, sealing.report);

        azihsm_buffer masked_buf{ sealing.masked.data(),
                                  static_cast<uint32_t>(sealing.masked.size()) };
        azihsm_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        azihsm_sess_ex_sd_create_remote_backup_params params{
            &masked_buf,
            &evidence.get(),
            &policy_buf,
        };

        std::vector<uint8_t> pok_remote;
        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        auto err = create_backup_fill(ctx.session, &params, pok_remote, pok_local, sd_mk);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Remote backup: HPKE-Auth seal of BKS3, 161 B, non-zero.
        ASSERT_EQ(pok_remote.size(), kPokRemoteBackupLen);
        ASSERT_TRUE(any_nonzero(pok_remote)) << "pok_remote_backup must not be all-zero";

        // Local backup: BKS3 masked under the partition-local key, 180 B,
        // non-zero.
        ASSERT_EQ(pok_local.size(), kPokLocalBackupLen);
        ASSERT_TRUE(any_nonzero(pok_local)) << "pok_local_backup must not be all-zero";

        // Masking-key backup: SDMK masked under the derived SDBMK, 164 B,
        // non-zero.
        ASSERT_EQ(sd_mk.size(), kSdMkBackupLen);
        ASSERT_TRUE(any_nonzero(sd_mk)) << "sd_mk_backup must not be all-zero";
    });
}

// One-shot: creating a security domain is a once-per-partition operation,
// so a second create on the now-initialized partition is rejected by the
// firmware with `SD_ALREADY_INITIALIZED`.
TEST_F(azihsm_sd_create_backup, create_backup_is_one_shot)
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

        SealingKeyMaterial sealing = sealing_key_and_report(ctx.session);
        ASSERT_EQ(sealing.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(sealing.report.empty());

        SdEvidenceHolder evidence = build_receiver_evidence(ctx, sealing.report);

        azihsm_buffer masked_buf{ sealing.masked.data(),
                                  static_cast<uint32_t>(sealing.masked.size()) };
        azihsm_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        azihsm_sess_ex_sd_create_remote_backup_params params{
            &masked_buf,
            &evidence.get(),
            &policy_buf,
        };

        // First create succeeds and sizes the output vectors.
        std::vector<uint8_t> pok_remote;
        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        ASSERT_EQ(
            create_backup_fill(ctx.session, &params, pok_remote, pok_local, sd_mk),
            AZIHSM_STATUS_SUCCESS
        );

        // A second create on the same (now initialized) partition must
        // fail. The buffers are already large enough, so the request clears
        // validation and reaches the firmware's one-shot guard.
        azihsm_buffer remote_buf{ pok_remote.data(), static_cast<uint32_t>(pok_remote.size()) };
        azihsm_buffer local_buf{ pok_local.data(), static_cast<uint32_t>(pok_local.size()) };
        azihsm_buffer mk_buf{ sd_mk.data(), static_cast<uint32_t>(sd_mk.size()) };
        auto second = azihsm_sess_ex_sd_create_remote_backup(
            ctx.session,
            &params,
            &remote_buf,
            &local_buf,
            &mk_buf
        );
        ASSERT_EQ(second, AZIHSM_STATUS_SD_ALREADY_INITIALIZED);
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the domain is created.
TEST_F(azihsm_sd_create_backup, create_backup_null_params)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { azihsm_part_close(part_handle); });

        azihsm_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { azihsm_sess_close(sess_handle); });

        azihsm_buffer out{ nullptr, 0 };
        auto err = azihsm_sess_ex_sd_create_remote_backup(sess_handle, nullptr, &out, &out, &out);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

#endif // defined(AZIHSM_FEATURE_EMU)

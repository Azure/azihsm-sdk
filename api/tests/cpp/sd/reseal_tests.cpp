// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdResealRemoteBackup` round trip against the emulator.
//
// Self-reseal on one partition: mint receiver / sender / destination SD
// sealing keys, use `azihsm_sd_create_remote_backup` to produce a
// real source backup (BKS3 sealed to the receiver by the sender), then
// reseal it to the destination via
// `azihsm_sd_reseal_remote_backup`. A successful reseal is itself
// the correctness check: the HPKE open only succeeds if the receiver key
// and the attested sender key match those that sealed the source.
//
// Like the create-backup tests, this needs the two-phase TBOR HPKE
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
// (`POK_REMOTE_BACKUP_LEN`, `MASKED_SEALING_KEY_LEN`), which are not
// exposed in the C header.
constexpr uint32_t kPokRemoteBackupLen = 161;
constexpr uint32_t kMaskedSealingKeyLen = 180;

// Create a real source backup: a fresh BKS3 sealed to the receiver's
// attested public key (`receiver_report`) by `masked_sender`. Returns the
// 161-byte remote backup, or an empty vector on failure (recording a gtest
// failure). Sizes the three output buffers via the probe/fill convention.
std::vector<uint8_t> create_source_backup(
    SdBackingContext &ctx,
    std::vector<uint8_t> &masked_sender,
    const std::vector<uint8_t> &receiver_report
)
{
    SdEvidenceHolder receiver = build_receiver_evidence(ctx, receiver_report);

    azihsm_buffer masked_buf{ masked_sender.data(), static_cast<uint32_t>(masked_sender.size()) };
    azihsm_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
    azihsm_sd_create_remote_backup_params params{
        &masked_buf,
        &receiver.get(),
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
        err =
            azihsm_sd_create_remote_backup(ctx.session, &params, &remote_buf, &local_buf, &mk_buf);
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
        ADD_FAILURE() << "create source backup failed: " << err;
        return {};
    }
    remote.resize(remote_buf.len);
    return remote;
}

// Run the reseal call, sizing the single output buffer via the probe/fill
// convention. The FFI validates the output buffer before resealing, so a
// too-small buffer never performs the reseal. Returns the final status and
// sizes `dst` to the bytes written on success.
azihsm_status reseal_fill(
    azihsm_handle session,
    const azihsm_sd_reseal_remote_backup_params *params,
    std::vector<uint8_t> &dst
)
{
    azihsm_buffer dst_buf{ nullptr, 0 };
    azihsm_status err = AZIHSM_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = azihsm_sd_reseal_remote_backup(session, params, &dst_buf);
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

/// Test fixture for security-domain reseal-remote-backup
/// (`azihsm_sd_reseal_remote_backup`).
class azihsm_sd_reseal_backup_test : public ::testing::Test
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

// Happy path: resealing a real source backup yields a fresh 161-byte,
// non-zero backup distinct from the source ciphertext.
TEST_F(azihsm_sd_reseal_backup_test, reseal_backup_roundtrip)
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

        // Receiver (unseals the source), sender (sealed the source), and
        // destination (the reseal target) SD sealing keys, each attested.
        SealingKeyMaterial rcvr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial sndr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial dst = sealing_key_and_report(ctx.session);
        ASSERT_EQ(rcvr.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(rcvr.report.empty());
        ASSERT_FALSE(sndr.report.empty());
        ASSERT_FALSE(dst.report.empty());

        std::vector<uint8_t> src_backup = create_source_backup(ctx, sndr.masked, rcvr.report);
        ASSERT_EQ(src_backup.size(), kPokRemoteBackupLen);

        // Reseal: open with the receiver key (auth = sender), reseal to the
        // destination receiver.
        SdEvidenceHolder src_ev = build_receiver_evidence(ctx, sndr.report);
        SdEvidenceHolder dst_ev = build_receiver_evidence(ctx, dst.report);

        azihsm_buffer masked_buf{ rcvr.masked.data(), static_cast<uint32_t>(rcvr.masked.size()) };
        azihsm_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        azihsm_buffer src_buf{ src_backup.data(), static_cast<uint32_t>(src_backup.size()) };
        azihsm_sd_reseal_remote_backup_params params{
            &masked_buf, &src_ev.get(), &dst_ev.get(), &policy_buf, &src_buf,
        };

        std::vector<uint8_t> dst_backup;
        ASSERT_EQ(reseal_fill(ctx.session, &params, dst_backup), AZIHSM_STATUS_SUCCESS);

        // A successful HPKE open -> seal yields a 161-byte, non-zero backup.
        ASSERT_EQ(dst_backup.size(), kPokRemoteBackupLen);
        ASSERT_TRUE(any_nonzero(dst_backup)) << "dst_remote_backup must not be all-zero";
        // The resealed backup is a fresh HPKE encapsulation, not the source.
        ASSERT_NE(dst_backup, src_backup)
            << "reseal must produce a fresh encapsulation, not echo the source";
    });
}

// Re-randomization: two reseals of the same source produce distinct
// ciphertexts (a fresh HPKE ephemeral each call).
TEST_F(azihsm_sd_reseal_backup_test, reseal_backup_rerandomizes)
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

        SealingKeyMaterial rcvr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial sndr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial dst = sealing_key_and_report(ctx.session);
        ASSERT_FALSE(rcvr.report.empty());
        ASSERT_FALSE(sndr.report.empty());
        ASSERT_FALSE(dst.report.empty());

        std::vector<uint8_t> src_backup = create_source_backup(ctx, sndr.masked, rcvr.report);
        ASSERT_EQ(src_backup.size(), kPokRemoteBackupLen);

        SdEvidenceHolder src_ev = build_receiver_evidence(ctx, sndr.report);
        SdEvidenceHolder dst_ev = build_receiver_evidence(ctx, dst.report);

        azihsm_buffer masked_buf{ rcvr.masked.data(), static_cast<uint32_t>(rcvr.masked.size()) };
        azihsm_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        azihsm_buffer src_buf{ src_backup.data(), static_cast<uint32_t>(src_backup.size()) };
        azihsm_sd_reseal_remote_backup_params params{
            &masked_buf, &src_ev.get(), &dst_ev.get(), &policy_buf, &src_buf,
        };

        std::vector<uint8_t> first;
        std::vector<uint8_t> second;
        ASSERT_EQ(reseal_fill(ctx.session, &params, first), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(reseal_fill(ctx.session, &params, second), AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(first, second) << "each reseal must re-randomize the HPKE encapsulation";
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the reseal is performed.
TEST_F(azihsm_sd_reseal_backup_test, reseal_backup_null_params)
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
        auto err = azihsm_sd_reseal_remote_backup(ctx.session, nullptr, &out);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

#endif // !defined(AZIHSM_FEATURE_MOCK)

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level tests for the security-domain backup command family
//! (`SdCreateRemoteBackup`, `SdResealRemoteBackup`, `SdRestoreRemoteBackup`,
//! `SdCreatePeerBackup`, `SdRestorePeerBackup`).

mod create_backup_tests;
mod create_peer_tests;
mod reseal_tests;
mod restore_peer_tests;
mod restore_tests;

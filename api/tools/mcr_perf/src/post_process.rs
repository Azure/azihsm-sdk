// Copyright (C) Microsoft Corporation. All rights reserved.

use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::path::PathBuf;

use open_enum::open_enum;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

use super::*;

pub(crate) fn helper_post_process_log(bin_log: PathBuf) {
    let mut out_log = bin_log.clone();
    out_log.set_extension("log");

    println!("Opening in file {:?}", bin_log);
    let mut bin_file = File::open(bin_log).unwrap();

    let mut perf_log_raw = Vec::new();
    let _ = bin_file.read_to_end(&mut perf_log_raw).unwrap();

    let mut checkpoints = CheckpointLog::new();
    let mut offset = 0;
    let cp_size = size_of::<Checkpoint>();

    while offset + cp_size < perf_log_raw.len() {
        let (checkpoint, _) =
            Checkpoint::try_ref_from_prefix(&perf_log_raw[offset..offset + cp_size])
                .expect("Could not convert binary log to friendly log");

        offset += cp_size;

        // Check if checkpoint is empty
        if checkpoint.start_time == 0 && checkpoint.next == 0 {
            continue;
        }

        checkpoints.push(checkpoint.clone());
    }

    println!("Opening out file {:?}", out_log);
    let mut log_file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open(out_log)
        .unwrap();

    println!("Writing out file");
    writeln!(log_file, "{}", checkpoints).unwrap();
    println!("Written out file");
}

pub struct CheckpointLog {
    checkpoints: Vec<Checkpoint>,
}

impl CheckpointLog {
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
        }
    }

    pub fn push(&mut self, checkpoint: Checkpoint) {
        self.checkpoints.push(checkpoint)
    }
}

impl std::fmt::Display for CheckpointLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for checkpoint in self.checkpoints.clone() {
            writeln!(f, "{},", checkpoint)?;
        }

        Ok(())
    }
}

const MAX_CHECKPOINTS: usize = 16;

/// Enumeration of various checkpoint id's
#[repr(u8)]
#[allow(missing_docs)]
#[open_enum]
#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable)]
pub enum CheckpointId {
    /// Unknown
    Unknown,

    /// RX Ready
    RxReady,

    /// TX Complete
    TxComplete,

    /// DMA Complete
    DmaComplete,

    /// Start Command
    StartCmd,

    /// FLR
    Flr,

    /// Admin IPC Request
    AdminIpcReq,

    /// FP IPC Response
    FpIpcResponse,

    /// AES Done
    AesDone,

    /// AES Error
    AesError,

    /// PKA Done
    Pka0Done,
    Pka1Done,
    Pka2Done,
    Pka3Done,
    Pka4Done,
    Pka5Done,
    Pka6Done,
    Pka7Done,
    Pka8Done,
    Pka9Done,
    PkaADone,
    PkaBDone,
    PkaCDone,
    PkaDDone,
    PkaEDone,
    PkaFDone,

    /// PKA Error
    Pka0Error,
    Pka1Error,
    Pka2Error,
    Pka3Error,
    Pka4Error,
    Pka5Error,
    Pka6Error,
    Pka7Error,
    Pka8Error,
    Pka9Error,
    PkaAError,
    PkaBError,
    PkaCError,
    PkaDError,
    PkaEError,
    PkaFError,

    /// Resource Ready
    ResourceReadyAes,
    ResourceReadyFpIpc,
    ResourceReadyPka,

    /// Other events
    InitCmd,

    /// Invalid operation
    DdiOpInvalid,

    /// Get API revision
    DdiOpGetApiRev,

    /// Get Device Info
    DdiOpGetDeviceInfo,

    /// Open manager session
    DdiOpOpenManagerSession,

    /// Open app session
    DdiOpOpenAppSession,

    /// Close manager session
    DdiOpCloseManagerSession,

    /// Close app session
    DdiOpCloseAppSession,

    /// Create app
    DdiOpCreateApp,

    /// Delete app
    DdiOpDeleteApp,

    /// Change manager credential
    DdiOpChangeManagerCredential,

    /// Change app PIN
    DdiOpChangeAppPin,

    /// Delete key
    DdiOpDeleteKey,

    /// Open key
    DdiOpOpenKey,

    /// Generate attestation report for key
    DdiOpAttestKey,

    /// RSA Modular Exponentiation
    DdiOpRsaModExp,

    /// RSA unwrap
    DdiOpRsaUnwrap,

    /// Get unwrapping RSA key
    DdiOpGetUnwrappingKey,

    /// ECC generate key pair
    DdiOpEccGenerateKeyPair,

    /// ECC sign
    DdiOpEccSign,

    /// AES Generate Key
    DdiOpAesGenerateKey,

    /// AES Encrypt/ Decrypt
    DdiOpAesEncryptDecrypt,

    /// ECDH key exchange
    DdiOpEcdhKeyExchange,

    /// HKDF Derive
    DdiOpHkdfDerive,

    /// KBKDF (SP800-108) Counter HMAC Derive
    DdiOpKbkdfCounterHmacDerive,

    // Test only opcodes below
    /// Reset function to default state for testing
    DdiOpResetFunction,

    /// Import key in DER format for testing including private keys
    DdiOpDerKeyImport,

    /// Get Perf Log Chunk
    DdiOpGetPerfLogChunk,

    /// Unknown PKA Done
    UnknownPkaDone,

    /// Unknown PKA Error
    UnknownPkaError,

    /// Unknown IPC 1
    UnknownIpc1,

    /// Unknown IPC 2
    UnknownIpc2,

    /// IPC
    Ipc,

    /// Misc Checkpoints
    MiscCp0,
    MiscCp1,
    MiscCp2,
    MiscCp3,
    MiscCp4,
    MiscCp5,
    MiscCp6,
    MiscCp7,
    MiscCp8,
    MiscCp9,
    MiscCpA,
    MiscCpB,
    MiscCpC,
    MiscCpD,
    MiscCpE,
    MiscCpF,
}

/// Enumeration of checkpoint kind
#[repr(u8)]
#[open_enum]
#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoBytes, TryFromBytes, Immutable)]
pub enum CheckpointKind {
    /// Independent event
    Independent,

    /// Begin event
    BeginEvent,

    /// End event
    EndEvent,
}

/// Represents a checkpoint.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct Checkpoint {
    version: u32,
    next: u32,
    start_time: u64,
    end_time: u64,
    checkpoints: [CheckPointRecord; MAX_CHECKPOINTS],
}

/// Checkpoint record
#[repr(C)]
#[derive(Debug, Copy, Clone, IntoBytes, TryFromBytes, Immutable)]
pub struct CheckPointRecord {
    time: u32,
    kind: CheckpointKind,
    id: CheckpointId,
    rsvd: u16,
}

impl std::fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ start_time: {}, ", self.start_time)?;

        let mut last_time = self.start_time;

        for index in 0..self.next {
            let cp_time = self.checkpoints[index as usize].time as u64 + self.start_time;
            let diff_time = cp_time - last_time;

            write!(
                f,
                "{} : {}_{} ({}) :, ",
                diff_time,
                self.checkpoints[index as usize].kind,
                self.checkpoints[index as usize].id,
                cp_time,
            )?;

            last_time = cp_time;
        }

        write!(f, "}}")
    }
}

impl std::fmt::Display for CheckpointKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_string = match self.to_owned() {
            CheckpointKind::BeginEvent => "B",
            CheckpointKind::EndEvent => "E",
            CheckpointKind::Independent => "I",
            _ => "U",
        };

        write!(f, "{}", display_string)
    }
}

impl std::fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let self_owned = self.to_owned();
        let mut _unknown = String::new();
        let display_string = match self_owned {
            CheckpointId::Unknown => "Unknown",
            CheckpointId::RxReady => "RxReady",
            CheckpointId::TxComplete => "TxComplete",
            CheckpointId::DmaComplete => "DmaComplete",
            CheckpointId::StartCmd => "StartCmd",
            CheckpointId::Flr => "Flr",
            CheckpointId::AdminIpcReq => "AdminIpcReq",
            CheckpointId::FpIpcResponse => "FpIpcResponse",
            CheckpointId::AesDone => "AesDone",
            CheckpointId::AesError => "AesError",
            CheckpointId::Pka0Done => "Pka0Done",
            CheckpointId::Pka1Done => "Pka1Done",
            CheckpointId::Pka2Done => "Pka2Done",
            CheckpointId::Pka3Done => "Pka3Done",
            CheckpointId::Pka4Done => "Pka4Done",
            CheckpointId::Pka5Done => "Pka5Done",
            CheckpointId::Pka6Done => "Pka6Done",
            CheckpointId::Pka7Done => "Pka7Done",
            CheckpointId::Pka8Done => "Pka8Done",
            CheckpointId::Pka9Done => "Pka9Done",
            CheckpointId::PkaADone => "PkaADone",
            CheckpointId::PkaBDone => "PkaBDone",
            CheckpointId::PkaCDone => "PkaCDone",
            CheckpointId::PkaDDone => "PkaDDone",
            CheckpointId::PkaEDone => "PkaEDone",
            CheckpointId::PkaFDone => "PkaFDone",
            CheckpointId::Pka0Error => "Pka0Error",
            CheckpointId::Pka1Error => "Pka1Error",
            CheckpointId::Pka2Error => "Pka2Error",
            CheckpointId::Pka3Error => "Pka3Error",
            CheckpointId::Pka4Error => "Pka4Error",
            CheckpointId::Pka5Error => "Pka5Error",
            CheckpointId::Pka6Error => "Pka6Error",
            CheckpointId::Pka7Error => "Pka7Error",
            CheckpointId::Pka8Error => "Pka8Error",
            CheckpointId::Pka9Error => "Pka9Error",
            CheckpointId::PkaAError => "PkaAError",
            CheckpointId::PkaBError => "PkaBError",
            CheckpointId::PkaCError => "PkaCError",
            CheckpointId::PkaDError => "PkaDError",
            CheckpointId::PkaEError => "PkaEError",
            CheckpointId::PkaFError => "PkaFError",
            CheckpointId::ResourceReadyAes => "ResourceReadyAes",
            CheckpointId::ResourceReadyFpIpc => "ResourceReadyFpIpc",
            CheckpointId::ResourceReadyPka => "ResourceReadyPka",
            CheckpointId::InitCmd => "InitCmd",
            CheckpointId::DdiOpInvalid => "DdiOpInvalid",
            CheckpointId::DdiOpGetApiRev => "DdiOpGetApiRev",
            CheckpointId::DdiOpGetDeviceInfo => "DdiOpGetDeviceInfo",
            CheckpointId::DdiOpOpenManagerSession => "DdiOpOpenManagerSession",
            CheckpointId::DdiOpOpenAppSession => "DdiOpOpenAppSession",
            CheckpointId::DdiOpCloseManagerSession => "DdiOpCloseManagerSession",
            CheckpointId::DdiOpCloseAppSession => "DdiOpCloseAppSession",
            CheckpointId::DdiOpCreateApp => "DdiOpCreateApp",
            CheckpointId::DdiOpDeleteApp => "DdiOpDeleteApp",
            CheckpointId::DdiOpChangeManagerCredential => "DdiOpChangeManagerCredential",
            CheckpointId::DdiOpChangeAppPin => "DdiOpChangeAppPin",
            CheckpointId::DdiOpDeleteKey => "DdiOpDeleteKey",
            CheckpointId::DdiOpOpenKey => "DdiOpOpenKey",
            CheckpointId::DdiOpAttestKey => "DdiOpAttestKey",
            CheckpointId::DdiOpRsaModExp => "DdiOpRsaModExp",
            CheckpointId::DdiOpRsaUnwrap => "DdiOpRsaUnwrap",
            CheckpointId::DdiOpGetUnwrappingKey => "DdiOpGetUnwrappingKey",
            CheckpointId::DdiOpEccGenerateKeyPair => "DdiOpEccGenerateKeyPair",
            CheckpointId::DdiOpEccSign => "DdiOpEccSign",
            CheckpointId::DdiOpAesGenerateKey => "DdiOpAesGenerateKey",
            CheckpointId::DdiOpAesEncryptDecrypt => "DdiOpAesEncryptDecrypt",
            CheckpointId::DdiOpEcdhKeyExchange => "DdiOpEcdhKeyExchange",
            CheckpointId::DdiOpHkdfDerive => "DdiOpHkdfDerive",
            CheckpointId::DdiOpKbkdfCounterHmacDerive => "DdiOpKbkdfCounterHmacDerive",
            CheckpointId::DdiOpResetFunction => "DdiOpResetFunction",
            CheckpointId::DdiOpDerKeyImport => "DdiOpDerKeyImport",
            CheckpointId::DdiOpGetPerfLogChunk => "DdiOpGetPerfLogChunk",
            CheckpointId::UnknownPkaDone => "UnknownPkaDone",
            CheckpointId::UnknownPkaError => "UnknownPkaError",
            CheckpointId::UnknownIpc1 => "UnknownIpc1",
            CheckpointId::UnknownIpc2 => "UnknownIpc2",

            CheckpointId::MiscCp0 => "MiscCp0",
            CheckpointId::MiscCp1 => "MiscCp1",
            CheckpointId::MiscCp2 => "MiscCp2",
            CheckpointId::MiscCp3 => "MiscCp3",
            CheckpointId::MiscCp4 => "MiscCp4",
            CheckpointId::MiscCp5 => "MiscCp5",
            CheckpointId::MiscCp6 => "MiscCp6",
            CheckpointId::MiscCp7 => "MiscCp7",
            CheckpointId::MiscCp8 => "MiscCp8",
            CheckpointId::MiscCp9 => "MiscCp9",
            CheckpointId::MiscCpA => "MiscCpA",
            CheckpointId::MiscCpB => "MiscCpB",
            CheckpointId::MiscCpC => "MiscCpC",
            CheckpointId::MiscCpD => "MiscCpD",
            CheckpointId::MiscCpE => "MiscCpE",
            CheckpointId::MiscCpF => "MiscCpF",

            _ => {
                _unknown = format!("UNKNOWN_{:?}", &mut self_owned.as_bytes());
                _unknown.as_str()
            }
        };

        write!(f, "{}", display_string)
    }
}

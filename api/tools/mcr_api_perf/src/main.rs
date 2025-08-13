// Copyright (C) Microsoft Corporation. All rights reserved.

mod cli;
mod common;
mod consts;

use std::sync::Arc;
use std::thread;
use std::time::Instant;

use circular_queue::CircularQueue;
use clap::*;
use indicatif::ProgressBar;
use mcr_api::*;
use parking_lot::*;
use quantogram::Quantogram;
use rand::distributions::Distribution;
use rand::prelude::*;
use rand_distr::WeightedAliasIndex;
use uuid::*;

use crate::cli::*;
use crate::common::*;
use crate::consts::*;

fn main() {
    helper_print_banner();

    let cli_args = CliArgs::parse();

    match cli_args.command {
        CliCommand::Perf(perf_args) => command_perf(perf_args),
    }
}

fn command_perf(perf_args: PerfArgs) {
    let mut devices = HsmDevice::get_devices();
    devices.sort();

    let threads = perf_args.threads;
    let stabilize_seconds = perf_args.stabilize_seconds;

    let test_seconds = perf_args.test_seconds;

    if devices.is_empty() {
        panic!("No devices found");
    }

    println!("Found devices:");
    for (index, device) in devices.iter().enumerate() {
        println!("    {}. {:?}", index, device.path);
    }

    let selected_device = &devices[perf_args.device].path;
    println!("Selected device: {:?}", selected_device);

    // Setup device for perf test
    helper_setup(selected_device.clone()).unwrap();

    let mix_ratios = PerfMixRatios::from(perf_args.mix);

    // Open App Session
    let dev_with_shared_session = Arc::new(RwLock::new(
        HsmDevice::open(&selected_device.clone()).unwrap(),
    ));
    let dev_shared_without_session = Arc::new(RwLock::new(
        HsmDevice::open(&selected_device.clone()).unwrap(),
    ));

    let app_session = helper_open_session(
        &dev_with_shared_session.read(),
        dev_with_shared_session.read().get_api_revision_range().max,
        TEST_APP_CREDENTIALS,
    );

    let mix_keys = helper_create_keys_for_mix(&app_session).unwrap();

    let app_session = if perf_args.shared_session {
        Some(Arc::new(RwLock::new(app_session)))
    } else {
        drop(app_session);
        None
    };

    let mut thread_list = Vec::new();
    for i in 0..threads {
        let thread_id = i as u8;
        let thread_device_path = selected_device.clone();

        let dev_with_session = dev_with_shared_session.clone();

        let perf_mix_args = PerfMixArguments {
            app_session: app_session.clone(),
            stabilize_seconds,
            test_seconds,
            prt_queue_length: perf_args.prt_queue_length,
            keys: mix_keys.clone(),
            ratios: mix_ratios.clone(),
        };

        let thread_dev_with_session = dev_with_session.clone();
        let thread_dev_without_session = dev_shared_without_session.clone();

        let thread = thread::spawn(move || {
            perf_test_thread(
                thread_id,
                thread_device_path,
                thread_dev_with_session,
                thread_dev_without_session,
                perf_mix_args,
            )
        });
        thread_list.push(thread);
    }

    const PROGRESS_PERIOD_MS: u64 = 1000;

    if !perf_args.hide_progress {
        println!(
            "Waiting for pre test stabilization time: {} seconds",
            stabilize_seconds
        );

        let progress_period = stabilize_seconds * 1000 / PROGRESS_PERIOD_MS;
        let pb = ProgressBar::new(progress_period);
        for _ in 0..progress_period {
            thread::sleep(std::time::Duration::from_millis(PROGRESS_PERIOD_MS));
            pb.inc(1);
        }
        pb.finish_and_clear();
        println!();
    }

    if !perf_args.hide_progress {
        println!("Waiting for performance tests: {} seconds", test_seconds);

        let progress_period = test_seconds * 1000 / PROGRESS_PERIOD_MS;
        let pb = ProgressBar::new(progress_period);
        for _ in 0..progress_period {
            thread::sleep(std::time::Duration::from_millis(PROGRESS_PERIOD_MS));
            pb.inc(1);
        }
        pb.finish_and_clear();
        println!();
    }

    if !perf_args.hide_progress {
        println!(
            "Waiting for post test stabilization time: {} seconds",
            stabilize_seconds
        );

        let progress_period = stabilize_seconds * 1000 / PROGRESS_PERIOD_MS;
        let pb = ProgressBar::new(progress_period);
        for _ in 0..progress_period {
            thread::sleep(std::time::Duration::from_millis(PROGRESS_PERIOD_MS));
            pb.inc(1);
        }
        pb.finish_and_clear();
        println!();
    }

    let mut threads_failed = 0;
    let mut total_counter: usize = 0;
    let mut total_prt = Vec::with_capacity(perf_args.prt_queue_length * perf_args.threads);
    let mut q = Quantogram::new();

    for thread in thread_list {
        let result = thread.join();
        if let Ok((thread_counter, thread_prt)) = result {
            total_counter += thread_counter;
            total_prt.extend(thread_prt);
        } else {
            threads_failed += 1;
        }
    }
    println!();

    println!(
        "MainThread: thread_count {} total_counter {} in secs {}: RPS: {}",
        threads,
        total_counter,
        test_seconds,
        total_counter as u64 / test_seconds
    );

    // Cleanup device for perf test
    if let Some(app_session) = app_session {
        drop(app_session);
    };
    helper_cleanup(selected_device.clone()).unwrap();

    for prt in total_prt {
        q.add(prt as f64);
    }

    println!(
        "MainThread: Per request time: Samples {} Mean: {:.1}us, Median: {:.1}us, Min: {:.1}us, Max: {:.1}us, Std Dev: {:.1}us, P75: {:.1}us P90: {:.1}us P95: {:.1}us P99: {:.1}us",
        q.count(),
        q.mean().unwrap()/1000.0,
        q.median().unwrap()/1000.0,
        q.min().unwrap()/1000.0,
        q.max().unwrap()/1000.0,
        q.stddev().unwrap()/1000.0,
        q.quantile(0.75).unwrap()/1000.0,
        q.quantile(0.90).unwrap()/1000.0,
        q.quantile(0.95).unwrap()/1000.0,
        q.quantile(0.99).unwrap()/1000.0,
    );

    if threads_failed != 0 {
        panic!("MainThread: {} threads failed", threads_failed);
    }
}

fn perf_test_thread(
    thread_id: u8,
    device_path: String,
    dev_with_session: Arc<RwLock<HsmDevice>>,
    dev_without_session: Arc<RwLock<HsmDevice>>,
    perf_mix_args: PerfMixArguments,
) -> (usize, Vec<u128>) {
    let dev_without_session_thread_specific =
        Arc::new(RwLock::new(HsmDevice::open(&device_path.clone()).unwrap()));

    let dev_with_session_thread_specific =
        Arc::new(RwLock::new(HsmDevice::open(&device_path.clone()).unwrap()));

    let dev_with_session = if perf_mix_args.app_session.is_none() {
        dev_with_session_thread_specific
    } else {
        dev_with_session
    };

    let _dev_without_session = if perf_mix_args.app_session.is_none() {
        dev_without_session_thread_specific
    } else {
        dev_without_session
    };

    let mut opened_new_app_session = false;
    let app_session = if let Some(app_session) = perf_mix_args.app_session {
        app_session
    } else {
        opened_new_app_session = true;
        Arc::new(RwLock::new(helper_open_session(
            &dev_with_session.read(),
            dev_with_session.read().get_api_revision_range().max,
            TEST_APP_CREDENTIALS,
        )))
    };

    let mut rng = thread_rng();

    let mix_items = [
        ("rsa_sign_2k", perf_mix_args.ratios.rsa_sign_2k),
        ("rsa_sign_3k", perf_mix_args.ratios.rsa_sign_3k),
        ("rsa_sign_4k", perf_mix_args.ratios.rsa_sign_4k),
        ("rsa_sign_crt_2k", perf_mix_args.ratios.rsa_sign_crt_2k),
        ("rsa_sign_crt_3k", perf_mix_args.ratios.rsa_sign_crt_3k),
        ("rsa_sign_crt_4k", perf_mix_args.ratios.rsa_sign_crt_4k),
    ];

    let mix_distribution =
        WeightedAliasIndex::new(mix_items.iter().map(|item| item.1).collect()).unwrap();

    let mut prt_queue = CircularQueue::with_capacity(perf_mix_args.prt_queue_length);

    let mut loop_counter: usize = 0;

    thread::sleep(std::time::Duration::from_secs(
        perf_mix_args.stabilize_seconds,
    ));

    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < perf_mix_args.test_seconds {
        let selected_command = mix_items[mix_distribution.sample(&mut rng)];
        let request_start = Instant::now();

        let resp = match selected_command.0 {
            "rsa_sign_2k" => app_session
                .read()
                .rsa_sign(
                    &perf_mix_args.keys.key_id_rsa_sign_2k.read(),
                    vec![100u8; 64],
                    RsaSignaturePadding::Pss,
                    Some(DigestKind::Sha512),
                    None,
                )
                .map(|_| ()),

            "rsa_sign_3k" => app_session
                .read()
                .rsa_sign(
                    &perf_mix_args.keys.key_id_rsa_sign_3k.read(),
                    vec![100u8; 64],
                    RsaSignaturePadding::Pss,
                    Some(DigestKind::Sha512),
                    None,
                )
                .map(|_| ()),

            "rsa_sign_4k" => app_session
                .read()
                .rsa_sign(
                    &perf_mix_args.keys.key_id_rsa_sign_4k.read(),
                    vec![100u8; 64],
                    RsaSignaturePadding::Pss,
                    Some(DigestKind::Sha512),
                    None,
                )
                .map(|_| ()),

            "rsa_sign_crt_2k" => app_session
                .read()
                .rsa_sign(
                    &perf_mix_args.keys.key_id_rsa_sign_crt_2k.read(),
                    vec![100u8; 64],
                    RsaSignaturePadding::Pss,
                    Some(DigestKind::Sha512),
                    None,
                )
                .map(|_| ()),

            "rsa_sign_crt_3k" => app_session
                .read()
                .rsa_sign(
                    &perf_mix_args.keys.key_id_rsa_sign_crt_3k.read(),
                    vec![100u8; 64],
                    RsaSignaturePadding::Pss,
                    Some(DigestKind::Sha512),
                    None,
                )
                .map(|_| ()),

            "rsa_sign_crt_4k" => app_session
                .read()
                .rsa_sign(
                    &perf_mix_args.keys.key_id_rsa_sign_crt_4k.read(),
                    vec![100u8; 64],
                    RsaSignaturePadding::Pss,
                    Some(DigestKind::Sha512),
                    None,
                )
                .map(|_| ()),

            val => panic!("Unknown mix: {}", val),
        };

        let request_time = request_start.elapsed().as_nanos();

        if let Err(e) = resp {
            panic!(
                "TestThread{}: Error: {:?} Selected command: {:?}",
                thread_id, e, selected_command
            );
        }

        prt_queue.push(request_time);

        loop_counter += 1;
    }

    thread::sleep(std::time::Duration::from_secs(
        perf_mix_args.stabilize_seconds,
    ));

    if opened_new_app_session {
        drop(app_session);
    }

    let mut prt_vec = Vec::with_capacity(prt_queue.len());
    for &duration in prt_queue.asc_iter() {
        prt_vec.push(duration);
    }

    (loop_counter, prt_vec)
}

#[derive(Debug, Clone)]
struct PerfMixRatios {
    /// Ratio of RSA 2K Sign operations
    rsa_sign_2k: u16,

    /// Ratio of RSA 3K Sign operations
    rsa_sign_3k: u16,

    /// Ratio of RSA 4K Sign operations
    rsa_sign_4k: u16,

    /// Ratio of RSA 2K CRT Sign operations
    rsa_sign_crt_2k: u16,

    /// Ratio of RSA 3K CRT Sign operations
    rsa_sign_crt_3k: u16,

    /// Ratio of RSA 4K CRT Sign operations
    rsa_sign_crt_4k: u16,
}

#[derive(Debug, Clone)]
struct PerfMixKeys {
    /// Key ID for RSA 2K Sign
    key_id_rsa_sign_2k: Arc<RwLock<HsmKeyHandle>>,

    /// Key ID for RSA 3K Sign
    key_id_rsa_sign_3k: Arc<RwLock<HsmKeyHandle>>,

    /// Key ID for RSA 4K Sign
    key_id_rsa_sign_4k: Arc<RwLock<HsmKeyHandle>>,

    /// Key ID for RSA 2K CRT Sign
    key_id_rsa_sign_crt_2k: Arc<RwLock<HsmKeyHandle>>,

    /// Key ID for RSA 3K CRT Sign
    key_id_rsa_sign_crt_3k: Arc<RwLock<HsmKeyHandle>>,

    /// Key ID for RSA 4K CRT Sign
    key_id_rsa_sign_crt_4k: Arc<RwLock<HsmKeyHandle>>,
}

#[derive(Debug, Clone)]
struct PerfMixArguments {
    /// App Session
    app_session: Option<Arc<RwLock<HsmSession>>>,

    /// Stabilization time in seconds
    stabilize_seconds: u64,

    /// Number of seconds to run performance test
    test_seconds: u64,

    /// Per request time queue size
    prt_queue_length: usize,

    /// Keys for performance mix
    keys: PerfMixKeys,

    /// Ratio of operations
    ratios: PerfMixRatios,
}

impl From<PerfMix> for PerfMixRatios {
    fn from(mix: PerfMix) -> Self {
        match mix {
            PerfMix::Custom(args) => Self {
                rsa_sign_2k: args.rsa_sign_2k,
                rsa_sign_3k: args.rsa_sign_3k,
                rsa_sign_4k: args.rsa_sign_4k,
                rsa_sign_crt_2k: args.rsa_sign_crt_2k,
                rsa_sign_crt_3k: args.rsa_sign_crt_3k,
                rsa_sign_crt_4k: args.rsa_sign_crt_4k,
            },
        }
    }
}

// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_print_banner() {
    println!();
    println!("    ███╗   ███╗ ██████╗██████╗     ██████╗ ███████╗██████╗ ███████╗");
    println!("    ████╗ ████║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔══██╗██╔════╝");
    println!("    ██╔████╔██║██║     ██████╔╝    ██████╔╝█████╗  ██████╔╝█████╗  ");
    println!("    ██║╚██╔╝██║██║     ██╔══██╗    ██╔═══╝ ██╔══╝  ██╔══██╗██╔══╝  ");
    println!("    ██║ ╚═╝ ██║╚██████╗██║  ██║    ██║     ███████╗██║  ██║██║     ");
    println!("    ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ");
    println!();
}

pub(crate) fn helper_setup(device_path: String) -> HsmResult<()> {
    helper_cleanup(device_path.clone())?;

    let device = HsmDevice::open(&device_path)?;
    let api_rev = device.get_api_revision_range().max;

    let _ = device.establish_credential(api_rev, TEST_APP_CREDENTIALS);

    Ok(())
}

pub(crate) fn helper_open_session(
    device: &HsmDevice,
    api_rev: HsmApiRevision,
    credentials: HsmAppCredentials,
) -> HsmSession {
    loop {
        let resp = device.open_session(api_rev, credentials);

        if let Err(error) = resp.as_ref() {
            // Retry if the error is HsmError::NonceMismatch, fail otherwise.
            assert!(
                matches!(error, HsmError::NonceMismatch),
                "Only NonceMismatch error is allowed but received different error: {:?}",
                error
            );
        } else {
            return resp.unwrap();
        }
    }
}

pub(crate) fn helper_cleanup(device_path: String) -> HsmResult<()> {
    let device = HsmDevice::open(&device_path)?;
    let api_rev = device.get_api_revision_range().max;

    let _ = device.establish_credential(api_rev, TEST_APP_CREDENTIALS);

    let app_session = helper_open_session(
        &device,
        device.get_api_revision_range().max,
        TEST_APP_CREDENTIALS,
    );

    let keys_to_delete = [
        KEY_TAG_RSA_SIGN_2K,
        KEY_TAG_RSA_SIGN_3K,
        KEY_TAG_RSA_SIGN_4K,
        KEY_TAG_RSA_SIGN_CRT_2K,
        KEY_TAG_RSA_SIGN_CRT_3K,
        KEY_TAG_RSA_SIGN_CRT_4K,
    ];

    for key_to_delete in keys_to_delete {
        let result = app_session.open_key(key_to_delete);
        if let Ok(key_handle) = result {
            let _ = app_session.delete_key(&key_handle);
        }
    }

    Ok(())
}

pub(crate) fn helper_create_keys_for_mix(app_session: &HsmSession) -> HsmResult<PerfMixKeys> {
    let key_id_rsa_sign_2k = helper_create_rsa_key(
        app_session,
        2048,
        Some(KEY_TAG_RSA_SIGN_2K),
        KeyUsage::SignVerify,
    )?;
    let key_id_rsa_sign_3k = helper_create_rsa_key(
        app_session,
        3072,
        Some(KEY_TAG_RSA_SIGN_3K),
        KeyUsage::SignVerify,
    )?;
    let key_id_rsa_sign_4k = helper_create_rsa_key(
        app_session,
        4096,
        Some(KEY_TAG_RSA_SIGN_4K),
        KeyUsage::SignVerify,
    )?;

    let key_id_rsa_sign_crt_2k = helper_create_rsa_crt_key(
        app_session,
        2048,
        Some(KEY_TAG_RSA_SIGN_CRT_2K),
        KeyUsage::SignVerify,
    )?;
    let key_id_rsa_sign_crt_3k = helper_create_rsa_crt_key(
        app_session,
        3072,
        Some(KEY_TAG_RSA_SIGN_CRT_3K),
        KeyUsage::SignVerify,
    )?;
    let key_id_rsa_sign_crt_4k = helper_create_rsa_crt_key(
        app_session,
        4096,
        Some(KEY_TAG_RSA_SIGN_CRT_4K),
        KeyUsage::SignVerify,
    )?;

    Ok(PerfMixKeys {
        key_id_rsa_sign_2k: Arc::new(RwLock::new(key_id_rsa_sign_2k)),
        key_id_rsa_sign_3k: Arc::new(RwLock::new(key_id_rsa_sign_3k)),
        key_id_rsa_sign_4k: Arc::new(RwLock::new(key_id_rsa_sign_4k)),
        key_id_rsa_sign_crt_2k: Arc::new(RwLock::new(key_id_rsa_sign_crt_2k)),
        key_id_rsa_sign_crt_3k: Arc::new(RwLock::new(key_id_rsa_sign_crt_3k)),
        key_id_rsa_sign_crt_4k: Arc::new(RwLock::new(key_id_rsa_sign_crt_4k)),
    })
}

pub(crate) fn helper_create_rsa_key(
    app_session: &HsmSession,
    rsa_size: u16,
    key_tag: Option<u16>,
    key_usage: KeyUsage,
) -> HsmResult<HsmKeyHandle> {
    let der: Vec<u8>;

    if rsa_size == 2048 {
        der = TEST_RSA_2K_PRIVATE_KEY.to_vec();
    } else if rsa_size == 3072 {
        der = TEST_RSA_3K_PRIVATE_KEY.to_vec();
    } else if rsa_size == 4096 {
        der = TEST_RSA_4K_PRIVATE_KEY.to_vec();
    } else {
        panic!("Invalid RSA key size");
    }

    app_session.import_key(
        der,
        KeyClass::Rsa,
        key_tag,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    )
}

pub(crate) fn helper_create_rsa_crt_key(
    app_session: &HsmSession,
    rsa_size: u16,
    key_tag: Option<u16>,
    key_usage: KeyUsage,
) -> HsmResult<HsmKeyHandle> {
    let der: Vec<u8>;

    if rsa_size == 2048 {
        der = TEST_RSA_2K_PRIVATE_KEY.to_vec();
    } else if rsa_size == 3072 {
        der = TEST_RSA_3K_PRIVATE_KEY.to_vec();
    } else if rsa_size == 4096 {
        der = TEST_RSA_4K_PRIVATE_KEY.to_vec();
    } else {
        panic!("Invalid RSA key size");
    }

    app_session.import_key(
        der,
        KeyClass::RsaCrt,
        key_tag,
        KeyProperties {
            key_usage,
            key_availability: KeyAvailability::App,
        },
    )
}

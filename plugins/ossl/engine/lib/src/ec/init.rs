// Copyright (C) Microsoft Corporation. All rights reserved.

use openssl_rust::safeapi::ec::method::EcKeyMethod;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::error::OpenSSLResult;

use crate::ec::callback::compute_key_cb;
use crate::ec::callback::copy_cb;
use crate::ec::callback::finish_cb;
use crate::ec::callback::keygen_cb;
use crate::ec::callback::sign_cb;
use crate::ec::callback::sign_setup_cb;
use crate::ec::callback::sign_sig_cb;
use crate::ec::callback::verify_cb;
use crate::ec::callback::verify_sig_cb;

/// Initialize EC functions
pub(crate) fn init_ec(engine: &Engine) -> OpenSSLResult<()> {
    // We need to map the error as we get a &Result
    let meth = EcKeyMethod::get_or_init().as_ref().map_err(|e| e.clone())?;

    meth.set_init(None, Some(finish_cb), Some(copy_cb), None, None, None)
        .set_keygen(Some(keygen_cb))
        .set_verify(Some(verify_cb), Some(verify_sig_cb))
        .set_sign(Some(sign_cb), Some(sign_setup_cb), Some(sign_sig_cb))
        .set_compute_key(Some(compute_key_cb));

    engine.set_ec(meth)?;

    Ok(())
}

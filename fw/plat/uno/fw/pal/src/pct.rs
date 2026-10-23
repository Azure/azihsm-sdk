// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pairwise consistency tests (PCTs) that the Uno PAL runs on RSA private
//! keys.
//!
//! [`UnoHsmPal::rsa_key_pct`] runs the PCT for:
//!
//! - An imported RSA key, in `rsa_priv_der_to_vault`. A key that fails is
//!   rejected.
//! - The partition's RSA unwrapping key, both when the SP publishes it and
//!   when `EstablishCredential` restores it (see [`crate::unwrapping_key`]).
//!   A key that fails sends the module to the FIPS error state.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsa;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmRsaPct;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_pct::rsa_pct;

use crate::UnoHsmPal;

impl UnoHsmPal {
    /// Runs the PCT that `pct` selects on `key`, an RSA private key in the
    /// PAL's vault format whose size and layout `key_size` gives.
    ///
    /// The PCT's public key is the `n ‖ e` that the private key stores.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — the key pair passed, or `pct` is [`HsmRsaPct::None`].
    /// - `Ok(false)` — the key pair is inconsistent.
    /// - `Err(_)` — an allocation or a PAL operation failed, so the test
    ///   didn't finish.
    pub(crate) async fn rsa_key_pct(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        key_size: HsmRsaKey,
        pct: HsmRsaPct,
    ) -> HsmResult<bool> {
        self.alloc_scoped_async(io, async |alloc| -> HsmResult<bool> {
            let pub_len = self.rsa_priv_pub_key(io, key, None)?;
            let pub_key = alloc.dma_alloc(pub_len)?;
            self.rsa_priv_pub_key(io, key, Some(&mut *pub_key))?;
            rsa_pct(self, io, alloc, key_size, &pct, key, pub_key).await
        })
        .await
    }
}

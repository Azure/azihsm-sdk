// Copyright (C) Microsoft Corporation. All rights reserved.

#[macro_export]
macro_rules! get_or_create_keydata {
    ($ctx:expr, $keydata_type:ty) => {{
        if let Some(keydata) = $ctx.get_data() {
            Ok(keydata)
        } else {
            let keydata = <$keydata_type>::new();
            $ctx.set_data(keydata);
            $ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)
        }
    }};
}

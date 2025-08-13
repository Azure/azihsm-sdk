// Copyright (C) Microsoft Corporation. All rights reserved.
use crate::openssl_log;
use crate::safeapi::error::*;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_get_size;
#[cfg(feature = "openssl_111")]
use crate::EVP_MD_size;
use crate::EVP_sha1;
use crate::EVP_sha256;
use crate::EVP_sha384;
use crate::EVP_sha512;
use crate::NID_sha1;
use crate::NID_sha256;
use crate::NID_sha384;
use crate::NID_sha512;
use crate::EVP_MD;

#[derive(Copy, Clone, Debug)]
pub enum EvpMdType {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

pub struct EvpMd(*const EVP_MD);

impl EvpMd {
    pub fn new(hash_type: EvpMdType) -> Self {
        let md = match hash_type {
            EvpMdType::Sha1 => unsafe { EVP_sha1() },
            EvpMdType::Sha256 => unsafe { EVP_sha256() },
            EvpMdType::Sha384 => unsafe { EVP_sha384() },
            EvpMdType::Sha512 => unsafe { EVP_sha512() },
        };
        Self(md)
    }

    pub fn md_size(nid: u32) -> OpenSSLResult<usize> {
        let md = match nid {
            NID_sha1 => unsafe { EVP_sha1() },
            NID_sha256 => unsafe { EVP_sha256() },
            NID_sha384 => unsafe { EVP_sha384() },
            NID_sha512 => unsafe { EVP_sha512() },
            _ => {
                openssl_log!(
                    OpenSSLError::HashNotSupported,
                    tracing::Level::ERROR,
                    "EvpMd::md_size: unknown NID {nid} from MD type",
                );
                return Err(OpenSSLError::HashNotSupported);
            }
        };

        let size = {
            #[cfg(feature = "openssl_3")]
            {
                unsafe { EVP_MD_get_size(md) }
            }
            #[cfg(feature = "openssl_111")]
            {
                unsafe { EVP_MD_size(md) }
            }
        };

        if size < 0 {
            openssl_log!(
                OpenSSLError::HashNotSupported,
                tracing::Level::ERROR,
                "EvpMd::md_size: unknown NID {nid} from MD type",
            );
            return Err(OpenSSLError::HashNotSupported);
        }
        Ok(size as usize)
    }

    pub fn as_ptr(&self) -> *const EVP_MD {
        self.0
    }
}

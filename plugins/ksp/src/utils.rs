// Copyright (C) Microsoft Corporation. All rights reserved.

use std::mem::size_of;
use std::panic::UnwindSafe;
use std::slice;

use mcr_api_resilient::DigestKind;
use mcr_api_resilient::ManticoreCertificate;
use widestring::*;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::*;

pub(crate) mod dll {
    use super::*;

    pub(crate) fn boundary<F: FnOnce() -> HRESULT + UnwindSafe>(f: F) -> HRESULT {
        match std::panic::catch_unwind(f) {
            Ok(hr) => hr,
            Err(_) => E_FAIL,
        }
    }
}

pub(crate) mod pcwstr {
    use super::*;

    pub(crate) fn equals(lhs: PCWSTR, rhs: PCWSTR) -> bool {
        let (lhs, rhs) = unsafe {
            (
                WideCString::from_ptr_str(lhs.as_ptr()),
                WideCString::from_ptr_str(rhs.as_ptr()),
            )
        };
        lhs == rhs
    }

    pub(crate) fn copy_pcwstr_to_slice(
        pcwstr: PCWSTR,
        slice: &mut [u8],
        out_size: &mut u32,
    ) -> u32 {
        let output = pcwstr.as_ptr().cast::<u8>();
        let result = unsafe { pcwstr.to_string() };
        let unwrapped_result = match result {
            Ok(r) => r,
            Err(_) => {
                return 0;
            }
        };
        let output_size = ((unwrapped_result.len() + 1) * size_of::<u16>()) as u32;

        if slice.is_empty() {
            *out_size = output_size;
            return 1;
        }

        slice[..output_size as usize]
            .copy_from_slice(unsafe { std::slice::from_raw_parts(output, output_size as usize) });
        *out_size = output_size;
        1
    }

    pub(crate) fn byte_slice_to_pcwstr(byte_slice: &[u8]) -> Option<PCWSTR> {
        if byte_slice.len() % 2 != 0 {
            return None; // The byte slice length must be even
        }

        let wide_slice: &[u16] = unsafe {
            slice::from_raw_parts(byte_slice.as_ptr() as *const u16, byte_slice.len() / 2)
        };

        Some(PCWSTR(wide_slice.as_ptr()))
    }

    pub(crate) fn digest_kind(alg_id: PCWSTR) -> Option<DigestKind> {
        if pcwstr::equals(alg_id, NCRYPT_SHA1_ALGORITHM) {
            Some(DigestKind::Sha1)
        } else if pcwstr::equals(alg_id, NCRYPT_SHA256_ALGORITHM) {
            Some(DigestKind::Sha256)
        } else if pcwstr::equals(alg_id, NCRYPT_SHA384_ALGORITHM) {
            Some(DigestKind::Sha384)
        } else if pcwstr::equals(alg_id, NCRYPT_SHA512_ALGORITHM) {
            Some(DigestKind::Sha512)
        } else {
            None
        }
    }
}

pub(crate) mod rsa_unwrap {
    use super::*;

    pub(crate) fn extract_algorithm_id(parameter_list: *const BCryptBufferDesc) -> Option<PCWSTR> {
        let buffer_desc: &BCryptBufferDesc = unsafe { &*(parameter_list as *const _) };
        tracing::debug!(
            "BCryptBufferDesc version: {}, count: {}",
            buffer_desc.ulVersion,
            buffer_desc.cBuffers
        );

        if buffer_desc.ulVersion != BCRYPTBUFFER_VERSION {
            tracing::error!("Invalid BCryptBufferDesc version");
            return None;
        }

        for buffer_index in 0..buffer_desc.cBuffers {
            let buffer = unsafe { &*buffer_desc.pBuffers.add(buffer_index as usize) };
            let buffer_type = buffer.BufferType;
            let buffer_size = buffer.cbBuffer;
            let buffer_data = unsafe {
                std::slice::from_raw_parts(buffer.pvBuffer as *const u8, buffer_size as usize)
            };

            tracing::debug!(
                "BCryptBufferDesc buffer[{}]: type: {}, size: {}",
                buffer_index,
                buffer_type,
                buffer_size
            );

            if buffer_type == NCRYPTBUFFER_PKCS_ALG_ID {
                match pcwstr::byte_slice_to_pcwstr(buffer_data) {
                    Some(algo_id) => return Some(algo_id),
                    None => {
                        tracing::error!("Invalid byte slice for PCWSTR conversion");
                        return None;
                    }
                };
            }
        }

        None
    }
}

pub(crate) mod bcrypt_util {
    use crypto::ecc::CryptoEccCurve;
    use crypto::ecc::EccOp;
    use crypto::rsa::RsaOp;
    use crypto::CryptoKeyKind;

    use super::*;

    pub(crate) fn ecdsa_der_to_bcrypt(der: &[u8]) -> Result<Vec<u8>, HRESULT> {
        let public_key = crypto::ecc::EccPublicKey::from_der(der, None).map_err(|_err| {
            tracing::error!("Bad ECDSA der format");
            E_UNEXPECTED
        })?;

        let curve = public_key.curve().map_err(|_err| {
            tracing::error!("Unexpected curve type");
            E_UNEXPECTED
        })?;
        let magic = match curve {
            CryptoEccCurve::P256 => BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            CryptoEccCurve::P384 => BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
            CryptoEccCurve::P521 => BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
        };

        let (x, y) = public_key.coordinates().map_err(|_err| {
            tracing::error!("Bad ECDSA der format");
            E_UNEXPECTED
        })?;

        //let key_bytes = export_cert_info.PublicKey.cbData;
        let mut ecc_public_blob_vec = vec![0u8; 0];

        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
        // ULONG MAGIC
        ecc_public_blob_vec.extend_from_slice(&magic.to_le_bytes());
        // ULONG cbKey
        ecc_public_blob_vec.extend_from_slice(&(x.len() as u32).to_le_bytes());
        // X[cbKey]
        ecc_public_blob_vec.extend_from_slice(&x);
        // Y[cbKey]
        ecc_public_blob_vec.extend_from_slice(&y);

        Ok(ecc_public_blob_vec)
    }

    pub(crate) fn ecdh_bcrypt_to_der(blob: &[u8]) -> Result<Vec<u8>, HRESULT> {
        let magic_bytes = blob[0..4].try_into().map_err(|_err| {
            tracing::error!("Bad MAGIC blob bytes");
            E_UNEXPECTED
        })?;
        let key_kind = match u32::from_le_bytes(magic_bytes) {
            BCRYPT_ECDH_PUBLIC_P256_MAGIC => CryptoKeyKind::Ecc256Public,
            BCRYPT_ECDH_PUBLIC_P384_MAGIC => CryptoKeyKind::Ecc384Public,
            BCRYPT_ECDH_PUBLIC_P521_MAGIC => CryptoKeyKind::Ecc521Public,
            _ => Err(NTE_INVALID_PARAMETER)?,
        };

        // ULONG cbKey
        let key_size_bytes = blob[4..8].try_into().map_err(|_err| {
            tracing::error!("Bad cbKey bytes");
            E_UNEXPECTED
        })?;
        let key_size = u32::from_le_bytes(key_size_bytes) as usize;

        let mut ecc_public_raw_vec = vec![0u8; 0];
        ecc_public_raw_vec.extend_from_slice(&blob[8..8 + key_size]);
        ecc_public_raw_vec.extend_from_slice(&blob[8 + key_size..8 + 2 * key_size]);

        let public_key = crypto::ecc::EccPublicKey::from_raw(&ecc_public_raw_vec, key_kind)
            .map_err(|_err| {
                tracing::error!("Bad raw key bytes");
                E_UNEXPECTED
            })?;

        public_key.to_der().map_err(|_err| {
            tracing::error!("Bad ECDSA der format");
            E_UNEXPECTED
        })
    }

    pub(crate) fn ecdh_der_to_bcrypt(der: &[u8]) -> Result<Vec<u8>, HRESULT> {
        let public_key = crypto::ecc::EccPublicKey::from_der(der, None).map_err(|_err| {
            tracing::error!("Bad ECDH der format");
            E_UNEXPECTED
        })?;

        let curve = public_key.curve().map_err(|_err| {
            tracing::error!("Unexpected curve type");
            E_UNEXPECTED
        })?;
        let magic = match curve {
            CryptoEccCurve::P256 => BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            CryptoEccCurve::P384 => BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            CryptoEccCurve::P521 => BCRYPT_ECDH_PUBLIC_P521_MAGIC,
        };

        let (x, y) = public_key.coordinates().map_err(|_err| {
            tracing::error!("Unexpected coordinates");
            E_UNEXPECTED
        })?;

        //let key_bytes = export_cert_info.PublicKey.cbData;
        let mut ecc_public_blob_vec = vec![0u8; 0];

        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
        // ULONG MAGIC
        ecc_public_blob_vec.extend_from_slice(&magic.to_le_bytes());
        // ULONG cbKey
        ecc_public_blob_vec.extend_from_slice(&(x.len() as u32).to_le_bytes());
        // X[cbKey]
        ecc_public_blob_vec.extend_from_slice(&x);
        // Y[cbKey]
        ecc_public_blob_vec.extend_from_slice(&y);

        Ok(ecc_public_blob_vec)
    }

    pub(crate) fn rsa_der_to_bcrypt(der: &[u8], key_bits: u32) -> Result<Vec<u8>, HRESULT> {
        let public_key = crypto::rsa::RsaPublicKey::from_der(der, None).map_err(|_err| {
            tracing::error!("Bad RSA der format");
            E_UNEXPECTED
        })?;

        let exp = public_key.public_exponent().map_err(|_err| {
            tracing::error!("Unexpected RSA exponent");
            E_UNEXPECTED
        })?;
        let modulus = public_key.modulus().map_err(|_err| {
            tracing::error!("Unexpected RSA modulus");
            E_UNEXPECTED
        })?;

        let mut rsa_public_blob_vec = vec![0u8; 0];
        let magic: u32 = BCRYPT_RSAPUBLIC_MAGIC.0;

        // ULONG MAGIC value
        rsa_public_blob_vec.extend_from_slice(&magic.to_le_bytes());
        // ULONG BitLength
        //rsa_public_blob_vec.extend_from_slice(&(exp.len() as u32 + modulus.len() as u32).to_le_bytes());
        rsa_public_blob_vec.extend_from_slice(&(key_bits).to_le_bytes());
        // ULONG cbPublicExp
        rsa_public_blob_vec.extend_from_slice(&(exp.len() as u32).to_le_bytes());
        // ULONG cbModulus
        rsa_public_blob_vec.extend_from_slice(&(modulus.len() as u32).to_le_bytes());
        // ULONG cbPrime1 (unused for public keys)
        rsa_public_blob_vec.extend_from_slice(&0u32.to_le_bytes());
        // ULONG cbPrime2 (unused for public keys)
        rsa_public_blob_vec.extend_from_slice(&0u32.to_le_bytes());

        // PublicExponent
        rsa_public_blob_vec.extend_from_slice(&exp);
        rsa_public_blob_vec.extend_from_slice(&modulus);

        Ok(rsa_public_blob_vec)
    }
}

pub(crate) mod helpers {
    macro_rules! validate_output_buffer {
        ($output:expr, $output_size:expr, $required_size:expr) => {
            if $output.len() == 0 {
                tracing::warn!(
                    "Output buffer is empty, returning required buffer size: [{}] bytes",
                    $required_size
                );
                *$output_size = $required_size;
                return Ok(());
            }
            if $output.len() < $required_size as usize {
                tracing::error!(
                    "Output buffer is [{}] bytes, expected at least [{}] bytes",
                    $output.len(),
                    $required_size
                );
                Err(HRESULT(NTE_BUFFER_TOO_SMALL))?
            }
        };
    }

    macro_rules! app_session_ref {
        ($self:ident) => {
            $self.inner.read().app_session.as_ref().ok_or_else(|| {
                tracing::error!("Unexpected: App session not found");
                HRESULT(E_UNEXPECTED)
            })?
        };
    }

    macro_rules! key_obj {
        ($self:ident, $key_handle:ident) => {
            $self.inner.read().keys.get($key_handle)
        };
    }

    macro_rules! key_func_call {
        // Example: key.delete_key(arg1, arg2);
        ($key:ident, $method:ident $(, $args:expr)*) => {
            match $key {
                Key::Aes($key) => $key.$method($($args),*),
                Key::Ecdsa($key) => $key.$method($($args),*),
                Key::Rsa($key) => $key.$method($($args),*),
                Key::Ecdh($key) => $key.$method($($args),*),
            }
        };

        // Example: key.delete_key(arg1, arg2); key is mutable.
        (mut $key:ident, $method:ident $(, $args:expr)* $(,)?) => {
            match $key {
                Key::Aes(mut $key) => $key.$method($($args),*),
                Key::Ecdsa(mut $key) => $key.$method($($args),*),
                Key::Rsa(mut $key) => $key.$method($($args),*),
                Key::Ecdh(mut $key) => $key.$method($($args),*),
            }
        };

        // Example: key.delete_key(arg1, arg2)?; key is mutable.
        (mut $key:ident, $method:ident $(, $args:expr)*, ?) => {
            match $key {
                Key::Aes(mut $key) => $key.$method($($args),*)?,
                Key::Ecdsa(mut $key) => $key.$method($($args),*)?,
                Key::Rsa(mut $key) => $key.$method($($args),*)?,
                Key::Ecdh(mut $key) => $key.$method($($args),*)?,
            }
        };
    }

    macro_rules! create_mut_slice_from_raw_parts {
        ($ptr:expr, $len:expr) => {
            unsafe { std::slice::from_raw_parts_mut($ptr, $len) }
        };
    }

    macro_rules! create_slice_from_raw_parts {
        ($ptr:expr, $len:expr) => {
            unsafe { std::slice::from_raw_parts($ptr, $len) }
        };
    }

    macro_rules! cast_void_ptr {
        ($ptr:expr) => {{
            unsafe { &*($ptr as *const _) }
        }};
    }

    macro_rules! cast_ptr {
        ($blob:expr, $type:ty) => {{
            unsafe {
                let ptr = $blob.as_ptr() as *const $type;
                &*ptr
            }
        }};
    }

    pub(crate) use app_session_ref;
    pub(crate) use cast_ptr;
    pub(crate) use cast_void_ptr;
    pub(crate) use create_mut_slice_from_raw_parts;
    pub(crate) use create_slice_from_raw_parts;
    pub(crate) use key_func_call;
    pub(crate) use key_obj;
    pub(crate) use validate_output_buffer;
}

/// Encode attestation report and certificate into a single binary buffer.
/// Output buffer format (all numbers are little-endian):
/// - Header
/// - 4 bytes: version, currently 1
/// - 4 bytes: buffer total length, including header
/// - metadata
/// - 4 bytes: length of attestation report in bytes
/// - 4 bytes: length of certificate in bytes
/// - payload
/// - N bytes: attestation report
/// - M bytes: certificate
pub fn encode_attestation_claim(report: &[u8], cert: &ManticoreCertificate) -> Vec<u8> {
    // Header version, only 1 is supported for now
    const VERSION: u32 = 1;

    // Extract certificate chain based on certificate type
    let cert_chain = match cert {
        ManticoreCertificate::PhysicalManticore(cert_chain) => cert_chain,
        ManticoreCertificate::VirtualManticore {
            ak_cert,
            tee_cert_chain: _,
            tee_report: _,
        } => ak_cert,
    };

    let len_report = report.len() as u32;
    let len_cert_chain = cert_chain.len() as u32;

    // Calculate total buffer length including header
    let len_buffer = 4 + // version
                      4 + // total length
                      4 + // report length
                      4 + // cert length
                      len_report + // report data
                      len_cert_chain; // cert data

    let mut buffer = Vec::with_capacity(len_buffer as usize);

    // Header: version (4 bytes)
    buffer.extend_from_slice(&VERSION.to_le_bytes());

    // Header: buffer total length (4 bytes)
    buffer.extend_from_slice(&len_buffer.to_le_bytes());

    // Metadata: length of attestation report (4 bytes)
    buffer.extend_from_slice(&len_report.to_le_bytes());

    // Metadata: length of certificate (4 bytes)
    buffer.extend_from_slice(&len_cert_chain.to_le_bytes());

    // Payload: attestation report
    buffer.extend_from_slice(report);

    // Payload: certificate
    buffer.extend_from_slice(cert_chain);

    buffer
}

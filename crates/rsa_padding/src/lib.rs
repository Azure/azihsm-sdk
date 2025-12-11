// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Library module for RSA encryption and signature schemes.
//! Signature encodings - PKCS1 v1.5 and PSS
//! Encryption encoding - OAEP
//!
//! Key size supported - RSA 2k, 3k, 4k.
//! Digest algorithms supported - SHA1, SHA2-256, SHA2-384, SHA2-512

use thiserror::Error;

/// Digest algorithm used internally by padding schemes
#[derive(Clone, Copy, Debug)]
pub enum RsaDigestKind {
    /// SHA1
    Sha1,

    /// SHA256
    Sha256,

    /// SHA384
    Sha384,

    /// SHA512
    Sha512,
}

/// Error type enum for RSA padding functions
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RsaError {
    /// Invalid parameter
    #[error("invalid parameter")]
    InvalidParameter,

    /// Index out of bounds
    #[error("RNG failure")]
    RngFailure,
}

/// Result type for RSA padding functions
pub type RsaResult<T> = Result<T, RsaError>;

/// RSA encoding struct
pub struct RsaEncoding {}

impl RsaEncoding {
    const SHA1_ALGO_ID: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];

    const SHA256_ALGO_ID: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    const SHA384_ALGO_ID: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];

    const SHA512_ALGO_ID: [u8; 19] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    // OID values from RFC 8017 Section 9.2 notes
    fn get_oid(digest: RsaDigestKind) -> &'static [u8] {
        match digest {
            RsaDigestKind::Sha1 => &Self::SHA1_ALGO_ID,
            RsaDigestKind::Sha256 => &Self::SHA256_ALGO_ID,
            RsaDigestKind::Sha384 => &Self::SHA384_ALGO_ID,
            RsaDigestKind::Sha512 => &Self::SHA512_ALGO_ID,
        }
    }

    fn hash_len(digest: RsaDigestKind) -> usize {
        match digest {
            RsaDigestKind::Sha1 => 20,
            RsaDigestKind::Sha256 => 32,
            RsaDigestKind::Sha384 => 48,
            RsaDigestKind::Sha512 => 64,
        }
    }

    /*
    byte-wise Xor of two vectors of same size.
    Result is stored in-place in the left operand.
     */
    fn xor_slices(a: &mut [u8], b: &[u8]) {
        assert_eq!(a.len(), b.len());

        for (a_elem, b_elem) in a.iter_mut().zip(b.iter()) {
            *a_elem ^= *b_elem;
        }
    }

    fn zero_leftmost_x_bits(v: &mut [u8], x: usize) {
        let x_bytes = x / 8;
        let x_bits = x % 8;

        let mut idx = 0;
        while idx < x_bytes && idx < v.len() {
            v[idx] = 0;
            idx += 1;
        }

        if idx < v.len() && x_bits != 0 {
            v[idx] &= 0xff >> x_bits
        }
    }

    fn leftmost_x_bits_are_zero(v: &[u8], x: usize) -> bool {
        let x_bytes = x / 8; // number of bytes to check
        let x_bits = x % 8; // number of remaining bits after checking whole bytes

        // Check the bytes up to x_bytes
        for &byte in v.iter().take(x_bytes) {
            if byte != 0 {
                return false;
            }
        }

        // Check the remaining bits in the last byte
        if x_bits > 0 {
            let last_byte = v.get(x_bytes).unwrap_or(&0);
            let mask = !((1 << (8 - x_bits)) - 1);
            if last_byte & mask != 0 {
                return false;
            }
        }

        true
    }

    fn mgf1(
        seed: &[u8],
        length: usize,
        digest_kind: RsaDigestKind,
        hash_func: fn(&[u8]) -> Vec<u8>,
    ) -> RsaResult<Vec<u8>> {
        let h_len = Self::hash_len(digest_kind);

        if length > (1 << 32) * h_len {
            tracing::error!("Mask too long");
            return Err(RsaError::InvalidParameter);
        }

        // over-allocate by h_len for boundary case
        let mut t = vec![0; length + h_len];
        let mut counter: i32 = 0;
        let mut t_idx: usize = 0;
        while t_idx < length {
            let c: &[u8] = &counter.to_be_bytes();
            let d = [seed, c].concat();
            let d_hash = hash_func(&d);
            t[t_idx..t_idx + h_len].copy_from_slice(&d_hash);
            t_idx += h_len;
            counter += 1;
        }
        t.truncate(length);
        assert_eq!(t.len(), length);
        Ok(t)
    }

    /// Encode message with PKCS#1 v1.5 encoding
    /// Params:
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// em_len: intended size of encoded message in bytes. Caller should set
    ///      this to byte length of key size. Refer RFC 8017 Sec 8.2.1 Step 1
    ///      for more.
    ///
    /// Errors:
    /// RsaError::InvalidParameter if em_len is smaller than 3 fixed bytes
    ///  + atleast 8 padding bytes + length required to store DER encoding of the hash
    pub fn encode_pkcs_v15(
        digest: &[u8],
        em_len: usize,
        digest_kind: RsaDigestKind,
    ) -> RsaResult<Vec<u8>> {
        let h_len = Self::hash_len(digest_kind);
        let hash_oid = Self::get_oid(digest_kind);

        let t_len: usize = hash_oid.len() + h_len;
        if em_len < t_len + 11 {
            tracing::error!(em_len = em_len, "Intended encoded message length too short");
            return Err(RsaError::InvalidParameter);
        }

        /*
            EM = 0x00 || 0x01 || PS(0xff) || 0x00 || T
        */
        let mut result_vector: Vec<u8> = vec![0; em_len];
        result_vector[1] = 0x01;
        for value in result_vector.iter_mut().skip(2).take(em_len - t_len - 3) {
            *value = 0xff;
        }
        result_vector[em_len - t_len..em_len - h_len].copy_from_slice(hash_oid);
        result_vector[em_len - h_len..em_len].copy_from_slice(digest);

        Ok(result_vector)
    }

    /// Verify message with PKCS#1 v1.5 encoding
    /// Params:
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// em_len: length of encoded message. Caller should set this
    ///      it to byte length of key size. Refer RFC 8017 Sec 8.2.2 Step 3
    ///      for more.
    pub fn verify_pkcs_v15(
        digest: &[u8],
        encoded_message: &Vec<u8>,
        em_len: usize,
        digest_kind: RsaDigestKind,
    ) -> RsaResult<bool> {
        let em_dash = RsaEncoding::encode_pkcs_v15(digest, em_len, digest_kind)?;
        if encoded_message == &em_dash {
            return Ok(true);
        }
        Ok(false)
    }

    /// Encode message with Probabilistic Signature Scheme (PSS)
    ///
    /// Params:
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// em_bits: intended bit length of encoded message. Caller should set
    ///      this to key_size_in_bits - 1. Refer RFC 8017 Section 8.1.1
    ///      Step 1 for more.
    /// salt_len: intented length in octets of salt. If None, salt length
    ///      is chosen to be maximum allowable (equal to digest length).
    pub fn encode_pss(
        digest: &[u8],
        em_bits: usize,
        digest_kind: RsaDigestKind,
        hash_func: fn(&[u8]) -> Vec<u8>,
        salt_len: u16,
        rng: fn(&mut [u8]) -> Result<(), ()>,
    ) -> RsaResult<Vec<u8>> {
        // em_len = ceil(em_bits/8)
        let em_len = em_bits.div_ceil(8);
        let h_len = Self::hash_len(digest_kind);
        let s_len = salt_len as usize;

        // Check salt length according to NIST.FIPS.186-5 Section 5.4 (g)
        // 0 <= s_len <= h_len
        if s_len > h_len {
            tracing::error!("Encoding error: salt length should be less than hash length");
            return Err(RsaError::InvalidParameter);
        }

        if em_len < h_len + s_len + 2 {
            tracing::error!(
                em_len = em_len,
                h_len = h_len,
                s_len = s_len,
                "Encoding error: em_len < h_len + s_len + 2 ",
            );
            return Err(RsaError::InvalidParameter);
        }

        let mut salt: Vec<u8> = vec![0; s_len];
        rng(&mut salt).map_err(|()| RsaError::RngFailure)?;
        let mut encoded_message: Vec<u8> = vec![0; em_len];

        // Hash the message
        let m_hash = digest.to_vec();

        let mut m_dash: Vec<u8> = vec![0; 8 + m_hash.len() + s_len];
        m_dash[8..8 + m_hash.len()].copy_from_slice(&m_hash);
        m_dash[8 + m_hash.len()..].copy_from_slice(&salt);
        let h = hash_func(&m_dash);

        let db_size = em_len - h_len - 1;
        let db = &mut encoded_message[0..db_size];
        db[db_size - s_len - 1] = 0x1;
        if s_len != 0 {
            db[db_size - s_len..].copy_from_slice(&salt);
        }
        let db_mask = Self::mgf1(&h, db_size, digest_kind, hash_func)?;
        Self::xor_slices(db, &db_mask);

        let n_zero_bits = 8 * em_len - em_bits;
        Self::zero_leftmost_x_bits(db, n_zero_bits);

        encoded_message[db_size..em_len - 1].copy_from_slice(&h);
        encoded_message[em_len - 1] = 0xbc;

        assert!(encoded_message.len() == em_len);
        Ok(encoded_message)
    }

    /// Verify whether encoded message matches the message under PSS encoding
    ///
    /// Params:
    /// em_bits: intended bit length of encoded message. Caller should set
    ///      this to key_size_in_bits - 1. Refer RFC 8017 Section 8.1.1
    ///      Step 1 for more.
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// salt_len: expected length in octets of salt. If None is passed,
    ///      salt length is auto detected based on fixed byte marker.
    pub fn verify_pss(
        digest: &[u8],
        encoded_message: &mut [u8],
        em_bits: usize,
        digest_kind: RsaDigestKind,
        hash_func: fn(&[u8]) -> Vec<u8>,
        salt_len: u16,
    ) -> RsaResult<bool> {
        // em_len = ceil(em_bits/8)
        let em_len = em_bits.div_ceil(8);
        let h_len = Self::hash_len(digest_kind);

        if encoded_message[encoded_message.len() - 1] != 0xbc {
            tracing::error!("Fixed byte 0xbc not found");
            return Err(RsaError::InvalidParameter);
        }

        let s_len;
        // Unmask DB
        {
            let h: &[u8] = &encoded_message[em_len - h_len - 1..em_len - 1];
            let db_mask = Self::mgf1(h, em_len - h_len - 1, digest_kind, hash_func)?;
            let db_size = em_len - h_len - 1;
            let n_zero_bits = 8 * em_len - em_bits;
            let masked_db = &mut encoded_message[0..db_size];
            if !Self::leftmost_x_bits_are_zero(masked_db, n_zero_bits) {
                return Err(RsaError::InvalidParameter);
            }
            Self::xor_slices(masked_db, &db_mask);
            let db = masked_db;

            Self::zero_leftmost_x_bits(db, n_zero_bits);

            // find salt in DB
            let fixed_db_byte_idx = db
                .iter()
                .position(|&x| x == 0x01)
                .ok_or(RsaError::InvalidParameter)?;

            if !db.iter().take(fixed_db_byte_idx).all(|&byte| byte == 0) {
                tracing::error!("Invalid padding: Padding string contains non-zero octets");
                return Err(RsaError::InvalidParameter);
            }

            let actual_salt_len = db_size - fixed_db_byte_idx - 1;
            // if salt was specified and is different from actual salt

            if salt_len as usize != actual_salt_len {
                tracing::error!("Actual salt differs from expected salt");
                return Err(RsaError::InvalidParameter);
            }

            s_len = actual_salt_len;

            if em_len < h_len + s_len + 2 {
                tracing::error!("Length of encoded message is too short");
                return Err(RsaError::InvalidParameter);
            }
        }

        let salt = &encoded_message[em_len - h_len - s_len - 1..em_len - h_len - 1];
        let m_hash = digest.to_vec();
        let mut m_dash: Vec<u8> = vec![0; 8 + m_hash.len() + s_len];
        m_dash[8..8 + m_hash.len()].copy_from_slice(&m_hash);
        m_dash[8 + m_hash.len()..].copy_from_slice(salt);
        let h2 = hash_func(&m_dash);
        let h1 = &encoded_message[em_len - h_len - 1..em_len - 1];
        Ok(h1 == h2)
    }

    /// Encode message with Optimal Asymmetric Encryption Padding (OAEP)
    ///
    /// Params:
    ///
    /// message: message to encrypt. mLen <= key_size - 2h_len - 2
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// label: label to be associated with message. If label is None,
    ///      empty string is used as label.
    /// rng: random bytes generator function of type fn(&mut [u8]) -> Result<(), ()>.
    ///
    /// Errors: RsaError::{InvalidParameter, RngFailure}
    ///
    pub fn encode_oaep(
        message: &[u8],
        label: Option<&[u8]>,
        key_size: usize,
        digest_kind: RsaDigestKind,
        hash_func: fn(&[u8]) -> Vec<u8>,
        rng: fn(&mut [u8]) -> Result<(), ()>,
    ) -> RsaResult<Vec<u8>> {
        let h_len = Self::hash_len(digest_kind);
        let m_len = message.len();
        if m_len > key_size - 2 * h_len - 2 {
            return Err(RsaError::InvalidParameter);
        }

        let l_hash = label
            .as_ref()
            .map_or_else(|| hash_func(b""), |l| hash_func(l));

        // construct decryption block (DB)
        let db_size = key_size - h_len - 1;
        let mut db = vec![0u8; db_size];
        db[0..h_len].copy_from_slice(&l_hash);
        db[db_size - m_len - 1] = 0x01;
        db[db_size - m_len..].copy_from_slice(message);

        let mut seed: Vec<u8> = vec![0; h_len];
        rng(&mut seed).map_err(|()| RsaError::RngFailure)?;
        let db_mask = Self::mgf1(&seed, db_size, digest_kind, hash_func)?;
        Self::xor_slices(&mut db, &db_mask);

        let seed_mask = Self::mgf1(&db, h_len, digest_kind, hash_func)?;
        Self::xor_slices(&mut seed, &seed_mask);

        let mut em = vec![0; key_size];
        em[1..h_len + 1].copy_from_slice(&seed);
        em[h_len + 1..].copy_from_slice(&db);
        Ok(em)
    }

    /// Decode message with Optimal Asymmetric Encryption Padding (OAEP)
    ///
    /// Params:
    ///
    /// encoded_message: encoded_message
    /// key_size: size of RSA key in bytes
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// label: label to be associated with message. If label is None,
    ///      empty string is used as label.
    ///
    /// Errors: RsaError::InvalidParameter
    ///
    pub fn decode_oaep(
        encoded_message: &mut [u8],
        label: Option<&[u8]>,
        key_size: usize,
        digest_kind: RsaDigestKind,
        hash_func: fn(&[u8]) -> Vec<u8>,
    ) -> RsaResult<Vec<u8>> {
        let h_len = Self::hash_len(digest_kind);
        let l_hash = label
            .as_ref()
            .map_or_else(|| hash_func(b""), |l| hash_func(l));

        {
            let masked_db = &encoded_message[h_len + 1..];
            let seed_mask = &Self::mgf1(masked_db, h_len, digest_kind, hash_func)?;
            let masked_seed = &mut encoded_message[1..h_len + 1];
            Self::xor_slices(masked_seed, seed_mask);
        }

        {
            let seed = &encoded_message[1..h_len + 1];
            let db_mask = &Self::mgf1(seed, key_size - h_len - 1, digest_kind, hash_func)?;
            let masked_db = &mut encoded_message[h_len + 1..];
            Self::xor_slices(masked_db, db_mask);
        }

        let db = &encoded_message[h_len + 1..];
        let _db_size = key_size - h_len - 1;
        let l_hash_em = &db[0..h_len];
        let label_mismatch = l_hash_em != l_hash;
        let em_msb_not_zero = encoded_message[0] != 0;
        let fixed_db_byte_idx = db.iter().skip(h_len).position(|&x| x == 0x01);
        let fixed_db_byte_not_found = fixed_db_byte_idx.is_none();

        // From RFC 8017 7.1.2: Care must be taken to ensure that an opponent cannot distinguish
        // the different error conditions in, whether by error message or timing..
        if label_mismatch || fixed_db_byte_not_found || em_msb_not_zero {
            return Err(RsaError::InvalidParameter);
        }
        let fixed_db_byte_idx = fixed_db_byte_idx.ok_or(RsaError::InvalidParameter)?;
        let m = db[fixed_db_byte_idx + h_len + 1..].to_vec();
        Ok(m)
    }
}

// TODO: Currently restricting tests to Linux as openssl use is disallowed on Windows
// and causes S360 issues. Need to find a good way to run these tests on Windows.
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rand::rand_bytes;
    use openssl::rsa::Padding;
    use openssl::rsa::Rsa;
    use openssl::sha::sha1;
    use openssl::sha::sha256;
    use openssl::sha::sha384;
    use openssl::sha::sha512;
    use openssl::sign::RsaPssSaltlen;
    use openssl::sign::Signer;
    use openssl::sign::Verifier;

    use super::*;

    const NLOOPS: u32 = 10;
    const KEYSZS: [u32; 3] = [2048, 3072, 4096];

    fn generate_key_pair(bits: u32) -> (Vec<u8>, Vec<u8>) {
        let rsa = Rsa::generate(bits).unwrap();

        let private_key_pem = rsa.private_key_to_pem().unwrap();
        let public_key_pem = rsa.public_key_to_pem().unwrap();

        (private_key_pem, public_key_pem)
    }

    fn ossl_sha1(data: &[u8]) -> Vec<u8> {
        sha1(data).to_vec()
    }
    fn ossl_sha256(data: &[u8]) -> Vec<u8> {
        sha256(data).to_vec()
    }

    fn ossl_sha384(data: &[u8]) -> Vec<u8> {
        sha384(data).to_vec()
    }

    fn ossl_sha512(data: &[u8]) -> Vec<u8> {
        sha512(data).to_vec()
    }

    fn hash_fn(digest: RsaDigestKind) -> fn(&[u8]) -> Vec<u8> {
        match digest {
            RsaDigestKind::Sha1 => ossl_sha1,
            RsaDigestKind::Sha256 => ossl_sha256,
            RsaDigestKind::Sha384 => ossl_sha384,
            RsaDigestKind::Sha512 => ossl_sha512,
        }
    }

    fn ossl_rand_bytes(buf: &mut [u8]) -> Result<(), ()> {
        rand_bytes(buf).map_err(|_| ())
    }

    fn rsa_pkcs1_sign(
        message: &[u8],
        private_key: &[u8],
        digest_kind: RsaDigestKind,
    ) -> RsaResult<Vec<u8>> {
        let digest = match digest_kind {
            RsaDigestKind::Sha1 => openssl::sha::sha1(message).to_vec(),
            RsaDigestKind::Sha256 => openssl::sha::sha256(message).to_vec(),
            RsaDigestKind::Sha384 => openssl::sha::sha384(message).to_vec(),
            RsaDigestKind::Sha512 => openssl::sha::sha512(message).to_vec(),
        };

        let rsa = Rsa::private_key_from_pem(private_key).unwrap();
        let em = RsaEncoding::encode_pkcs_v15(&digest, rsa.size() as usize, digest_kind)?;
        let mut buf = vec![0; rsa.size() as usize];
        // println!("emLen={} em={:?}", em.len(), em);
        let _sig_len = rsa.private_encrypt(&em, &mut buf, Padding::NONE).unwrap();
        Ok(buf)
    }

    fn rsa_pkcs1_verify(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        digest_kind: RsaDigestKind,
    ) -> RsaResult<bool> {
        let digest = match digest_kind {
            RsaDigestKind::Sha1 => openssl::sha::sha1(message).to_vec(),
            RsaDigestKind::Sha256 => openssl::sha::sha256(message).to_vec(),
            RsaDigestKind::Sha384 => openssl::sha::sha384(message).to_vec(),
            RsaDigestKind::Sha512 => openssl::sha::sha512(message).to_vec(),
        };

        let rsa = Rsa::public_key_from_pem(public_key).unwrap();
        let mut em = vec![0; rsa.size() as usize];
        let _verify_res = rsa
            .public_decrypt(signature, &mut em, Padding::NONE)
            .unwrap();
        RsaEncoding::verify_pkcs_v15(&digest, &em, rsa.size() as usize, digest_kind)
    }

    fn rsa_pss_sign(
        message: &[u8],
        private_key: &[u8],
        digest_kind: RsaDigestKind,
        salt_len: u16,
    ) -> RsaResult<Vec<u8>> {
        let digest = match digest_kind {
            RsaDigestKind::Sha1 => openssl::sha::sha1(message).to_vec(),
            RsaDigestKind::Sha256 => openssl::sha::sha256(message).to_vec(),
            RsaDigestKind::Sha384 => openssl::sha::sha384(message).to_vec(),
            RsaDigestKind::Sha512 => openssl::sha::sha512(message).to_vec(),
        };

        let rsa = Rsa::private_key_from_pem(private_key).unwrap();
        let mod_bits = (rsa.size() * 8 - 1) as usize;
        let em = RsaEncoding::encode_pss(
            &digest,
            mod_bits,
            digest_kind,
            hash_fn(digest_kind),
            salt_len,
            ossl_rand_bytes,
        )?;
        // println!("sign side encoded_message={:?}", em);
        let mut buf = vec![0; rsa.size() as usize];
        let _sig_len = rsa.private_encrypt(&em, &mut buf, Padding::NONE).unwrap();
        Ok(buf)
    }

    fn rsa_pss_verify(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        digest_kind: RsaDigestKind,
        salt_len: u16,
    ) -> RsaResult<bool> {
        let digest = match digest_kind {
            RsaDigestKind::Sha1 => openssl::sha::sha1(message).to_vec(),
            RsaDigestKind::Sha256 => openssl::sha::sha256(message).to_vec(),
            RsaDigestKind::Sha384 => openssl::sha::sha384(message).to_vec(),
            RsaDigestKind::Sha512 => openssl::sha::sha512(message).to_vec(),
        };

        // println!("rsa_pss_verify({:?}, {:?})", digest, salt_len);
        let rsa = Rsa::public_key_from_pem(public_key).unwrap();
        let mod_bits = (rsa.size() * 8 - 1) as usize;
        let mut em = vec![0; rsa.size() as usize];
        rsa.public_decrypt(signature, &mut em, Padding::NONE)
            .unwrap();
        // println!("verify side encoded_message={:?}", em);
        RsaEncoding::verify_pss(
            &digest,
            &mut em,
            mod_bits,
            digest_kind,
            hash_fn(digest_kind),
            salt_len,
        )
    }

    // Useful for debugging PSS implementation
    // fn rsa_private_encrypt(message: &[u8], private_key: &[u8]) -> Vec<u8> {
    //     let rsa = Rsa::private_key_from_pem(private_key).unwrap();
    //     let mod_bits = (rsa.size() * 8 - 1) as usize;
    //     let em = RsaEncoding::encode_pss(message, mod_bits);
    //     let mut buf = vec![0; rsa.size() as usize];
    //     let sig_len = rsa.private_encrypt(&em, &mut buf, Padding::NONE).unwrap();
    //     return buf;
    // }

    // fn rsa_public_decrypt(message: &[u8], public_key: &[u8]) -> Vec<u8> {
    //     let rsa = Rsa::public_key_from_pem(public_key).unwrap();
    //     let mod_bits = (rsa.size() * 8 - 1) as usize;
    //     let mut em = vec![0; rsa.size() as usize];
    //     let verify_res = rsa
    //         .public_decrypt(&message, &mut em, Padding::NONE)
    //         .unwrap();
    //     return em;
    // }

    fn rsa_oaep_public_encrypt(
        message: &[u8],
        public_key: &[u8],
        digest_kind: RsaDigestKind,
    ) -> RsaResult<Vec<u8>> {
        let rsa = Rsa::public_key_from_pem(public_key).unwrap();
        let key_size = rsa.size() as usize;
        let m_len = message.len();
        let h_len = RsaEncoding::hash_len(digest_kind);

        if m_len > key_size - 2 * h_len - 2 {
            return Err(RsaError::InvalidParameter);
        }

        let em = RsaEncoding::encode_oaep(
            message,
            None,
            key_size,
            digest_kind,
            hash_fn(digest_kind),
            ossl_rand_bytes,
        )?;
        let mut ct = vec![0u8; key_size];
        rsa.public_encrypt(&em, &mut ct, Padding::NONE).unwrap();
        Ok(ct)
    }

    fn rsa_oaep_private_decrypt(
        ciphertext: &[u8],
        private_key: &[u8],
        digest_kind: RsaDigestKind,
    ) -> RsaResult<Vec<u8>> {
        let rsa = Rsa::private_key_from_pem(private_key).unwrap();
        let key_size = rsa.size() as usize;
        let c_len = ciphertext.len();
        let h_len = RsaEncoding::hash_len(digest_kind);

        if c_len != key_size || key_size < 2 * h_len + 2 {
            return Err(RsaError::InvalidParameter);
        }

        let mut em = vec![0u8; key_size];
        rsa.private_decrypt(ciphertext, &mut em, Padding::NONE)
            .unwrap();

        RsaEncoding::decode_oaep(&mut em, None, key_size, digest_kind, hash_fn(digest_kind))
    }

    fn test_runner_sign<TC>(testcase: TC)
    where
        TC: Fn(usize, &[u8], &[u8], &[u8], RsaDigestKind, u16),
    {
        let message = b"euclid fermat euler lagrange";
        let test_salt_lens = [0u16, 5u16, 16u16, 32u16, 48u16, 64u16, 512u16];
        let hash_funcs = [
            RsaDigestKind::Sha1,
            RsaDigestKind::Sha256,
            RsaDigestKind::Sha384,
            RsaDigestKind::Sha512,
        ];
        for _iter in 0..NLOOPS {
            for keysize in KEYSZS {
                let (private_key, public_key) = generate_key_pair(keysize);
                for hf in hash_funcs {
                    let digest = match hf {
                        RsaDigestKind::Sha1 => openssl::sha::sha1(message).to_vec(),
                        RsaDigestKind::Sha256 => openssl::sha::sha256(message).to_vec(),
                        RsaDigestKind::Sha384 => openssl::sha::sha384(message).to_vec(),
                        RsaDigestKind::Sha512 => openssl::sha::sha512(message).to_vec(),
                    };

                    for salt_len in test_salt_lens {
                        println!(
                            "keysz={} salt_len={:?} digest_kind={:?}",
                            keysize, salt_len, hf
                        );
                        testcase(
                            keysize as usize,
                            &digest,
                            &private_key,
                            &public_key,
                            hf,
                            salt_len,
                        );
                    }
                }
            }
        }
    }

    fn test_runner_oaep<TC>(testcase: TC)
    where
        TC: Fn(usize, &[u8], &[u8], &[u8], RsaDigestKind),
    {
        let message = b"euclid fermat euler lagrange";
        let hash_funcs = [
            RsaDigestKind::Sha1,
            RsaDigestKind::Sha256,
            RsaDigestKind::Sha384,
            RsaDigestKind::Sha512,
        ];
        for _iter in 0..NLOOPS {
            for keysize in KEYSZS {
                let (private_key, public_key) = generate_key_pair(keysize);
                for hf in hash_funcs {
                    testcase(keysize as usize, message, &private_key, &public_key, hf);
                }
            }
        }
    }

    fn ossl_hash_equivalent(digest_kind: RsaDigestKind) -> MessageDigest {
        match digest_kind {
            RsaDigestKind::Sha1 => MessageDigest::sha1(),
            RsaDigestKind::Sha256 => MessageDigest::sha256(),
            RsaDigestKind::Sha384 => MessageDigest::sha384(),
            RsaDigestKind::Sha512 => MessageDigest::sha512(),
        }
    }

    fn hash_len(digest: RsaDigestKind) -> usize {
        match digest {
            RsaDigestKind::Sha1 => 20,
            RsaDigestKind::Sha256 => 32,
            RsaDigestKind::Sha384 => 48,
            RsaDigestKind::Sha512 => 64,
        }
    }

    #[test]
    fn test_rsassa_pkcs_roundtrip_sanity() {
        test_runner_sign(
            |_keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind,
             _salt_len: u16| {
                let signature = rsa_pkcs1_sign(message, private_key, digest_kind).unwrap();
                let is_consistent =
                    rsa_pkcs1_verify(message, &signature, public_key, digest_kind).unwrap();
                assert!(is_consistent);
            },
        );
    }

    #[test]
    fn test_rsassa_pkcs_openssl_verify() {
        test_runner_sign(
            |_keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind,
             _salt_len: u16| {
                let signature = rsa_pkcs1_sign(message, private_key, digest_kind).unwrap();

                let rsa_pubkey =
                    PKey::from_rsa(Rsa::public_key_from_pem(public_key).unwrap()).unwrap();
                let mut verifier =
                    Verifier::new(ossl_hash_equivalent(digest_kind), &rsa_pubkey).unwrap();
                verifier.set_rsa_padding(Padding::PKCS1).unwrap();
                verifier.update(message).unwrap();
                assert!(verifier.verify(&signature).unwrap());
            },
        );
    }

    #[test]
    fn test_rsassa_pkcs_openssl_sign() {
        test_runner_sign(
            |_keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind,
             _salt_len: u16| {
                let rsa_privkey =
                    PKey::from_rsa(Rsa::private_key_from_pem(private_key).unwrap()).unwrap();
                let mut signer =
                    Signer::new(ossl_hash_equivalent(digest_kind), &rsa_privkey).unwrap();
                signer.set_rsa_padding(Padding::PKCS1).unwrap();
                signer.update(message).unwrap();
                let signature = signer.sign_to_vec().unwrap();

                let is_consistent =
                    rsa_pkcs1_verify(message, &signature, public_key, digest_kind).unwrap();
                assert!(is_consistent);
            },
        );
    }

    #[test]
    fn test_rsassa_pss_roundtrip_sanity() {
        test_runner_sign(
            |_keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind,
             salt_len: u16| {
                let signature = rsa_pss_sign(message, private_key, digest_kind, salt_len);
                if salt_len as usize > hash_len(digest_kind) {
                    assert!(signature.is_err());
                    return;
                }
                let signature = signature.unwrap();
                let is_consistent =
                    rsa_pss_verify(message, &signature, public_key, digest_kind, salt_len);
                if let Ok(inner) = is_consistent {
                    if inner {
                        return;
                    }
                }
                panic!("pss verify failed");
            },
        );
    }

    #[test]
    fn test_rsassa_pss_openssl_verify() {
        test_runner_sign(
            |_keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind,
             salt_len: u16| {
                let signature = rsa_pss_sign(message, private_key, digest_kind, salt_len);
                if salt_len as usize > hash_len(digest_kind) {
                    assert!(signature.is_err());
                    return;
                }
                let signature = signature.unwrap();
                let rsa_pubkey =
                    PKey::from_rsa(Rsa::public_key_from_pem(public_key).unwrap()).unwrap();
                let mut verifier =
                    Verifier::new(ossl_hash_equivalent(digest_kind), &rsa_pubkey).unwrap();
                verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                verifier
                    .set_rsa_mgf1_md(ossl_hash_equivalent(digest_kind))
                    .unwrap();
                verifier
                    .set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len as i32))
                    .unwrap();

                verifier.update(message).unwrap();
                assert!(verifier.verify(&signature).unwrap());
            },
        );
    }

    #[test]
    fn test_rsassa_pss_openssl_sign() {
        test_runner_sign(
            |keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind,
             salt_len: u16| {
                let rsa_privkey =
                    PKey::from_rsa(Rsa::private_key_from_pem(private_key).unwrap()).unwrap();

                let mut signer =
                    Signer::new(ossl_hash_equivalent(digest_kind), &rsa_privkey).unwrap();
                signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                signer
                    .set_rsa_mgf1_md(ossl_hash_equivalent(digest_kind))
                    .unwrap();
                signer
                    .set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len as i32))
                    .unwrap();
                signer.update(message).unwrap();
                let signature = signer.sign_to_vec();
                if salt_len as usize >= keysize / 8 {
                    assert!(signature.is_err());
                    // TODO test verify_pss for this negative case
                    return;
                }

                let signature = signature.unwrap();
                let is_consistent =
                    rsa_pss_verify(message, &signature, public_key, digest_kind, salt_len);
                if let Ok(inner) = is_consistent {
                    if inner {
                        return;
                    }
                }
                panic!("pss verify failed");
            },
        );
    }

    #[test]
    fn test_rsassa_oaep_roundtrip_sanity() {
        test_runner_oaep(
            |_keysize: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind| {
                let ciphertext = rsa_oaep_public_encrypt(message, public_key, digest_kind).unwrap();
                let plaintext =
                    rsa_oaep_private_decrypt(&ciphertext, private_key, digest_kind).unwrap();
                //println!("ciphertext={:?} \nplaintext={:?}", ciphertext, plaintext);
                assert!(message == plaintext);
            },
        );
    }

    #[test]
    fn test_rsassa_oaep_openssl_decrypt() {
        test_runner_oaep(
            |_key_size: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind| {
                let ciphertext = rsa_oaep_public_encrypt(message, public_key, digest_kind).unwrap();

                // decrypt with Openssl
                let rsa_privkey =
                    PKey::from_rsa(Rsa::private_key_from_pem(private_key).unwrap()).unwrap();
                use openssl::encrypt::Decrypter;
                let mut decrypter = Decrypter::new(&rsa_privkey).unwrap();
                decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
                decrypter
                    .set_rsa_mgf1_md(ossl_hash_equivalent(digest_kind))
                    .unwrap();
                decrypter
                    .set_rsa_oaep_md(ossl_hash_equivalent(digest_kind))
                    .unwrap();
                let buffer_len = decrypter.decrypt_len(&ciphertext).unwrap();
                let mut decrypted = vec![0; buffer_len];
                let decrypted_len = decrypter.decrypt(&ciphertext, &mut decrypted).unwrap();
                decrypted.truncate(decrypted_len);
                assert!(message == &*decrypted);
            },
        );
    }

    #[test]
    fn test_rsassa_oaep_openssl_encrypt() {
        test_runner_oaep(
            |_key_size: usize,
             message: &[u8],
             private_key: &[u8],
             public_key: &[u8],
             digest_kind: RsaDigestKind| {
                let rsa_pubkey =
                    PKey::from_rsa(Rsa::public_key_from_pem(public_key).unwrap()).unwrap();
                use openssl::encrypt::Encrypter;
                let mut encrypter = Encrypter::new(&rsa_pubkey).unwrap();
                encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
                encrypter
                    .set_rsa_mgf1_md(ossl_hash_equivalent(digest_kind))
                    .unwrap();
                encrypter
                    .set_rsa_oaep_md(ossl_hash_equivalent(digest_kind))
                    .unwrap();
                let buffer_len = encrypter.encrypt_len(message).unwrap();
                let mut encrypted = vec![0; buffer_len];
                let encrypted_len = encrypter.encrypt(message, &mut encrypted).unwrap();
                encrypted.truncate(encrypted_len);

                let plaintext =
                    rsa_oaep_private_decrypt(&encrypted, private_key, digest_kind).unwrap();
                //println!("ciphertext={:?} \nplaintext={:?}", ciphertext, plaintext);
                assert!(message == &*plaintext);
            },
        );
    }
}

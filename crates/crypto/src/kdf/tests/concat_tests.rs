// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Known-answer tests for the single-step concatenation KDFs
//! ([`ConcatKdfAlgo`]) — ANSI X9.63 and NIST SP 800-56A r3 one-step.
//!
//! The expected outputs were generated independently with Python's
//! `hashlib` (`Hash(Z || counter || Info)` for X9.63, `Hash(counter || Z
//! || Info)` for SP 800-56A, 4-byte big-endian counter from 1), so they
//! validate the concatenation order, counter encoding, and multi-block
//! truncation on both the OpenSSL and CNG backends.

use super::*;

/// One KDF known-answer vector: the same `(Z, info, len)` produces
/// distinct X9.63 and SP 800-56A outputs (the variants differ only in
/// counter/`Z` ordering).
struct ConcatVector {
    hash: fn() -> HashAlgo,
    z: &'static str,
    info: &'static str,
    len: usize,
    x963: &'static str,
    sp800_56a: &'static str,
}

const VECTORS: &[ConcatVector] = &[
    // SHA-256, single hash block (16 B < 32 B digest).
    ConcatVector {
        hash: HashAlgo::sha256,
        z: "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
        info: "75eef81aa3041e33b80971203d2c8c52",
        len: 16,
        x963: "b401793cf16db8b33e9823365548acc8",
        sp800_56a: "cf4872839942d9ac07363e62cc562798",
    },
    // SHA-256, four hash blocks (128 B > 32 B digest) — exercises the
    // counter increment and concatenation.
    ConcatVector {
        hash: HashAlgo::sha256,
        z: "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
        info: "75eef81aa3041e33b80971203d2c8c52",
        len: 128,
        x963: "5b31a9cbf1b0b1738fc6c422267d9696b6d820e682f2cb0d75b0bd6db50ac18f254aa9d940bd45ea51e2a4d1a377e53ffc5273f1fb4e360effa982e3eb1e8668b73b027694fece0f12fd67d199179460022fde2cea161d4dbf7e41f5802a33341675fffa6f5a6f5661c5188992ba07e5978dfd1749fb624b1af4712d9370688c",
        sp800_56a: "d68779fa59aaf660779c6bc37f99de6d92dc19a6f9380d497a2e114b244d3c6be373260e22747e3ecf02dea16f07e1b4a992c133c0e11639350a9242426a91f0b606f6dd4cf74a12a6078bf0806cdd019ccadf56abad15ef0d3b0114394f67eeedb5ae1e8ca8068a6e75ede590c6e74c16da07d7e56d84031d75c718148096e1",
    },
    // SHA-384, two hash blocks (96 B > 48 B digest).
    ConcatVector {
        hash: HashAlgo::sha384,
        z: "d38bdbe5c4fc164cdd2c4b6ba18db26f6c9f0f8f1a9f4d70",
        info: "5eef81aa3041e33b80971203d2c8c527",
        len: 96,
        x963: "9b72a41068953b242b761a3c5c6d328824569a7006c6fe497e2994c5dc701642619e6ec6f281787184df8c1c61c80404906d2d5d99a06514590a65fc8e836dbf6178a540eb10e868897bebec313b033c8ca7c32e76690d75312c82204791e66b",
        sp800_56a: "61293e102901a6720ecd6ead480ccce13953d196aed2b97899a53cffa130ff1b50b9a176dc18984b496d7d96fed14b0c0b061f20dadd9859aa7d79ad89f7ea1202313aac143d350fc7494f4a78381d3a6c5628caec442f3420078cd265b4a0cd",
    },
    // SHA-512, three hash blocks (128 B > 64 B digest).
    ConcatVector {
        hash: HashAlgo::sha512,
        z: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
        info: "00112233445566778899aabbccddeeff",
        len: 128,
        x963: "1088e49964b56f79d850bf76406fec1670fead744cd06c0389f52d0f5e5da635a3bfce7ae4e9f6f03c63c910bd2a264081497265c4c01ef2c963d1fa3a10a3a4bce8773b837a15098302e320c4dd48eeb549c0d4f11afdb6b27de5c1c954a1308885cde29c83b463a461cb63a95e45fa256069e878259a6c2f234cfe35cafbc3",
        sp800_56a: "e94703684c134300514d52cf4d45f954ebdf71b1b96e788544f6992e229c359a60f10481e9edccde97d28245310e083aebe19a8e62f09cb7dd66bdb8304437962ebeb0b50b7334a753966e2d4a85d9c526f7720e23071d7ee20abd752856d27af5dc562ee3a05b079c23f7059e17a3a63339d94484fc92bdc5a6581db8c8dcb5",
    },
    // SHA-256, absent info (empty SharedInfo / OtherInfo), single block.
    ConcatVector {
        hash: HashAlgo::sha256,
        z: "0102030405060708090a0b0c0d0e0f10",
        info: "",
        len: 32,
        x963: "067c2a589276f095268c8333f2d83e26e7422a8029f400ca65b300d21b4b9b8b",
        sp800_56a: "50361466915fce78eff64887e7d2e0540905993388d432436be513c48143033f",
    },
];

/// Run `mode` for one vector and return the derived-key bytes.
fn derive(v: &ConcatVector, mode: ConcatKdfMode) -> Vec<u8> {
    let z = hex::decode(v.z).expect("z hex");
    let info = hex::decode(v.info).expect("info hex");
    let info = (!info.is_empty()).then_some(info);
    let key = GenericSecretKey::from_bytes(&z).expect("z key");
    let algo = ConcatKdfAlgo::new((v.hash)(), mode, info);
    algo.derive(&key, v.len)
        .expect("derive")
        .to_vec()
        .expect("export")
}

#[test]
fn x963_known_answer_vectors() {
    for v in VECTORS {
        let got = derive(v, ConcatKdfMode::X963);
        assert_eq!(
            hex::encode(&got),
            v.x963,
            "X9.63 mismatch for z={} len={}",
            v.z,
            v.len,
        );
    }
}

#[test]
fn sp800_56a_known_answer_vectors() {
    for v in VECTORS {
        let got = derive(v, ConcatKdfMode::Sp800_56a);
        assert_eq!(
            hex::encode(&got),
            v.sp800_56a,
            "SP 800-56A mismatch for z={} len={}",
            v.z,
            v.len,
        );
    }
}

#[test]
fn x963_and_sp800_56a_differ() {
    // The two variants must not collide for the same inputs (they place
    // the counter on opposite sides of Z).
    for v in VECTORS {
        assert_ne!(
            derive(v, ConcatKdfMode::X963),
            derive(v, ConcatKdfMode::Sp800_56a),
            "variants must differ for z={}",
            v.z,
        );
    }
}

#[test]
fn empty_secret_rejected() {
    let key = GenericSecretKey::from_bytes(&[]).expect("empty key");
    let algo = ConcatKdfAlgo::new(HashAlgo::sha256(), ConcatKdfMode::X963, None);
    assert!(matches!(
        algo.derive(&key, 32),
        Err(CryptoError::ConcatKdfInvalidSecretLength)
    ));
}

#[test]
fn zero_length_rejected() {
    let key = GenericSecretKey::from_bytes(&[0x11u8; 32]).expect("key");
    let algo = ConcatKdfAlgo::new(HashAlgo::sha256(), ConcatKdfMode::Sp800_56a, None);
    assert!(matches!(
        algo.derive(&key, 0),
        Err(CryptoError::ConcatKdfInvalidDerivedKeyLength)
    ));
}

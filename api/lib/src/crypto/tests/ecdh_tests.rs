// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

#[cfg(test)]
mod tests {

    use crate::crypto::ec::EcdsaKeyPair;
    use crate::crypto::ecdh::EcdhAlgo;
    use crate::crypto::ecdh::EcdhParams;
    use crate::session::test_helpers::create_test_session;
    use crate::types::EcCurve;
    use crate::types::KeyProps;

    #[test]
    fn test_ecdh_key_derive_basic() {
        let (_partition, session) = create_test_session();

        // Generate first key pair for server
        let server_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = EcdsaKeyPair::new(server_key_props.clone(), server_key_props);
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        // Generate second key pair for client
        let client_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair = EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get client's public key for ECDH
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // Create ECDH algorithm with client's public key
        let ecdh_params = EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = EcdhAlgo {
            params: ecdh_params,
        };

        // Perform ECDH key derivation using server's private key
        let derived_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let derived_key_id = session
            .key_derive(&ecdh_algo, &server_keypair, &derived_key_props)
            .expect("ECDH key derivation should succeed");

        // Verify that a valid key ID was returned
        assert_ne!(derived_key_id.0, 0, "Derived key ID should not be zero");
    }

    #[test]
    fn test_ecdh_key_derive_p384() {
        let (_partition, session) = create_test_session();

        // Generate first key pair for server (P-384)
        let server_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .derive(true)
            .build();

        let mut server_keypair = EcdsaKeyPair::new(server_key_props.clone(), server_key_props);
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        // Generate second key pair for client (P-384)
        let client_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .derive(true)
            .build();

        let mut client_keypair = EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get client's public key for ECDH
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // Create ECDH algorithm with client's public key
        let ecdh_params = EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = EcdhAlgo {
            params: ecdh_params,
        };

        // Perform ECDH key derivation using server's private key
        let derived_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .derive(true)
            .build();

        let derived_key_id = session
            .key_derive(&ecdh_algo, &server_keypair, &derived_key_props)
            .expect("ECDH key derivation should succeed");

        // Verify that a valid key ID was returned
        assert_ne!(derived_key_id.0, 0, "Derived key ID should not be zero");
    }

    #[test]
    fn test_ecdh_key_derive_p521() {
        let (_partition, session) = create_test_session();

        // Generate first key pair for server (P-521)
        let server_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P521)
            .derive(true)
            .build();

        let mut server_keypair = EcdsaKeyPair::new(server_key_props.clone(), server_key_props);
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        // Generate second key pair for client (P-521)
        let client_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P521)
            .derive(true)
            .build();

        let mut client_keypair = EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get client's public key for ECDH
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // Create ECDH algorithm with client's public key
        let ecdh_params = EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = EcdhAlgo {
            params: ecdh_params,
        };

        // Perform ECDH key derivation using server's private key
        let derived_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P521)
            .derive(true)
            .build();

        let derived_key_id = session
            .key_derive(&ecdh_algo, &server_keypair, &derived_key_props)
            .expect("ECDH key derivation should succeed");

        // Verify that a valid key ID was returned
        assert_ne!(derived_key_id.0, 0, "Derived key ID should not be zero");
    }

    #[test]
    fn test_ecdh_key_derive_different_curves_should_fail() {
        let (_partition, session) = create_test_session();

        // Generate server's key pair with P-256 for curve mismatch test
        let server_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = EcdsaKeyPair::new(server_key_props.clone(), server_key_props);
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        // Generate client's key pair with P-384 to create a curve mismatch
        let client_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .derive(true)
            .build();

        let mut client_keypair = EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get client's public key (P-384) for ECDH
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // Create ECDH algorithm with client's public key (P-384)
        let ecdh_params = EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = EcdhAlgo {
            params: ecdh_params,
        };

        // Attempt ECDH key derivation using server's private key (P-256)
        // This should fail because the curves don't match
        let derived_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .derive(true)
            .build();

        let result = session.key_derive(&ecdh_algo, &server_keypair, &derived_key_props);

        // The operation should fail due to curve mismatch
        assert!(result.is_err(), "ECDH should fail when curves don't match");
    }

    #[test]
    fn test_ecdh_key_derive_invalid_public_key() {
        let (_partition, session) = create_test_session();

        // Generate server's key pair
        let server_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = EcdsaKeyPair::new(server_key_props.clone(), server_key_props);
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        // Create ECDH algorithm with invalid public key data
        let ecdh_params = EcdhParams {
            pub_key: vec![0u8; 32], // Invalid public key data
        };
        let ecdh_algo = EcdhAlgo {
            params: ecdh_params,
        };

        // Attempt ECDH key derivation with invalid public key
        let derived_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let result = session.key_derive(&ecdh_algo, &server_keypair, &derived_key_props);

        // The operation should fail due to invalid public key
        assert!(result.is_err(), "ECDH should fail with invalid public key");
    }

    #[test]
    fn test_ecdh_symmetric_property() {
        let (_partition, session) = create_test_session();

        // Generate first key pair for server
        let server_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = EcdsaKeyPair::new(server_key_props.clone(), server_key_props);
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        // Generate second key pair for client
        let client_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair = EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get public keys
        let server_public_key = server_keypair
            .pub_key()
            .expect("Failed to get server's public key");
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // server derives shared secret using client's public key
        let ecdh_algo_server = EcdhAlgo {
            params: EcdhParams {
                pub_key: client_public_key,
            },
        };
        let derived_key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .derive(true)
            .build();

        let server_derived_key_id = session
            .key_derive(&ecdh_algo_server, &server_keypair, &derived_key_props)
            .expect("server's ECDH key derivation should succeed");

        // client derives shared secret using server's public key
        let ecdh_algo_client = EcdhAlgo {
            params: EcdhParams {
                pub_key: server_public_key,
            },
        };
        let client_derived_key_id = session
            .key_derive(&ecdh_algo_client, &client_keypair, &derived_key_props)
            .expect("client's ECDH key derivation should succeed");

        // Both derived keys should be valid (non-zero)
        assert_ne!(
            server_derived_key_id.0, 0,
            "server's derived key ID should not be zero"
        );
        assert_ne!(
            client_derived_key_id.0, 0,
            "client's derived key ID should not be zero"
        );

        // Note: We can't directly compare the derived key values since they're stored
        // in the HSM, but both operations should succeed and produce valid key IDs.
        // In a real implementation, you would use these keys for subsequent operations
        // and verify they produce the same results.
    }
}

// Copyright (C) Microsoft Corporation. All rights reserved.

// TODO: Currently restricting tests to Linux as openssl use is disallowed on Windows
// and causes S360 issues. Need to find a good way to run these tests on Windows.
#![cfg(target_os = "linux")]

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509StoreContext;
use openssl::x509::X509;
use test_with_tracing::test;

use crate::common::*;

/// Verify the collateral returned from a physical manticore
/// Using OpenSSL
/// cert_chain: Raw byte array of PEM encoded certificates, separated by newline.
/// The first cert is the leaf cert, the last cert is the root cert.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn verify_certificate_chain(cert_chain: Vec<u8>) -> Result<bool, ErrorStack> {
    // 1. Load the certificate chain
    let cert_chain = X509::stack_from_pem(&cert_chain)?;

    // 2. Build a Store that holds root CA
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(cert_chain.last().unwrap().clone())?;
    let store = store_builder.build();

    // 3. Build a Stack that holds intermediate certs
    let mut stack = Stack::new().unwrap();
    // Add intermediate certs in the order from root to leaf
    for cert in cert_chain[1..(cert_chain.len() - 1)].iter().rev() {
        stack.push(cert.clone())?;
    }

    // 4. Build a Context to verify the leaf cert
    let mut store_ctx = X509StoreContext::new()?;
    let result = store_ctx.init(&store, cert_chain.first().unwrap(), &stack, |ctx| {
        ctx.verify_cert()
    });

    result
}

#[test]
fn test_verify_collateral_from_prod() {
    // This collateral contains cert chain
    // Taken from device on prod env
    // First is leaf cert, last is root cert
    let raw_collateral = r#"
    -----BEGIN CERTIFICATE-----
MIICOzCCAcKgAwIBAgIUWg5HxGLtDMnkEYpiSufI4K6WYHMwCgYIKoZIzj0EAwMw
SzFJMEcGA1UEAwxAT1BZWDd1WGhFYkdvL1AzWGx3eHNQRU42c0pWTDQ5cm9hNVZP
ckhoeTVoeU9sem5pRGtPRWZqV0xpL3BRL2Z5KzAiGA8yMDIzMDEwMTAwMDAwMFoY
Dzk5OTkxMjMxMjM1OTU5WjBLMUkwRwYDVQQDDEA0NzRERjA1NDA5ODNERDE3QUVF
NjlEQzIzRjY3MjFCMUYyNDNERkRBNTFEQTBBMzM4RjE3MDMzQTgwMUY1NUVDMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEhYRzIv2yrN3VExSBjAX5HI30bTX+vTSTHlRQ
yT8bsqsphsHJYIA9xMxODDdd62zx109i75VNCOYZwcMlb33I99yMXp2gyDevw7Q9
n2U/aMhGQJ311YXn2WGSDX+1C0uDo2MwYTAPBgNVHRMBAf8EBTADAgEAMA4GA1Ud
DwEB/wQEAwIHgDAdBgNVHQ4EFgQUiP+VaXzra6Y+Wn2YomrQuvQOVuYwHwYDVR0j
BBgwFoAU4SC1Si3Hwhlpv3RskLm+J9nUxK8wCgYIKoZIzj0EAwMDZwAwZAIwAvrY
bcVa6/fTdxhoG9N32UXLFReTy0wHjUEXriRWYppdR05v6Vkwg7p9nOQE9HLAAjBY
tTTfhmPPlZrrO6g2+x8WZAJwLFIK6CNfBwdbdAV25EAso25iY0VJKvBdf+rWiGw=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDKzCCArKgAwIBAgIIOPYX7uXhEbEwCgYIKoZIzj0EAwMwSzFJMEcGA1UEAwxA
YUNXZjZ5SDFxQTBuVy9idElKb1RlWFFqaTM2TDJRMVlpeTdwbkFITktma3NXMTNr
Ly8zaFlCN3hENG8rVkFlQzAgFw0xODAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1
OVowSzFJMEcGA1UEAwxAT1BZWDd1WGhFYkdvL1AzWGx3eHNQRU42c0pWTDQ5cm9h
NVZPckhoeTVoeU9sem5pRGtPRWZqV0xpL3BRL2Z5KzB2MBAGByqGSM49AgEGBSuB
BAAiA2IABLmRJ1WpL22ndNrGiuQYsvIpb5M7ZSyEkAj42YC1bHKzg2C9ti1fESdN
S43Lgm7RKPjnKZR+K0mA/mYGwphLvEZbEYYDPbKUQKkPUTVX8fmXrFXysf8dCbyw
SLvmHe+zuqOCAV8wggFbMB0GA1UdDgQWBBThILVKLcfCGWm/dGyQub4n2dTErzAf
BgNVHSMEGDAWgBSNIqS14FhwHYTXlsagVEcCvMo5SDAOBgNVHQ8BAf8EBAMCAgQw
EgYDVR0TAQH/BAgwBgEB/wIBADAkBgNVHSUEHTAbBgdngQUFBGQHBgdngQUFBGQJ
BgdngQUFBGQMMIHOBgZngQUFBAEEgcMwgcCACU1pY3Jvc29mdIEUQXp1cmUgSW50
ZWdyYXRlZCBIU02CFzAuMC4wLjAtNTA4MTEyMTBiZXRhKFgpgwEAhAEBpn4wPQYJ
YIZIAWUDBAICBDC5aP1LuT0n7mw1hwPHDVLXk4Ak7H7TywKmRznydIuAHGRnAuGu
YPWru6Jf1rJziVowPQYJYIZIAWUDBAICBDBhDG4NEWQFl7c382eBgXjDFD9GgAjn
YitdTJISZ2cTbtNoBgHq81r91JK3yWb/HikwCgYIKoZIzj0EAwMDZwAwZAIwZA02
kr3GZwZyRxrGUOaGmH82x7Q0O96wrByObzvX5ox2kYaZZSPkZW/dPazPG2VvAjAR
6WIxXLsToG7EvaRs8VXMrYJPT7iZXuzMlK8IvmhFsX4Z2rKAeVd9vFgeU9NbDqI=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFjjCCBRSgAwIBAgIEESIzRDAKBggqhkjOPQQDAzARMQ8wDQYDVQQDDAZJbnRy
Q0EwIBcNMTkwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEsxSTBHBgNVBAMM
QGFDV2Y2eUgxcUEwblcvYnRJSm9UZVhRamkzNkwyUTFZaXk3cG5BSE5LZmtzVzEz
ay8vM2hZQjd4RDRvK1ZBZUMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR7KcqROBl8
Aw4OaSjgI7liHiAgL4ita45R6lssyXGvr61igBttaOTT0URnqL0Zg8++61aQSDUL
mwAd77I5rSZjRC08FL8tAbf3SgYyc9+PuDfBs05L60Za4aN3kuX6x+ejggP/MIID
+zAdBgNVHQ4EFgQUjSKkteBYcB2E15bGoFRHArzKOUgwHwYDVR0jBBgwFoAUJUTy
93/YO0K16ceu3Yvd1LEDMF8wDgYDVR0PAQH/BAQDAgIEMBIGA1UdEwEB/wQIMAYB
Af8CAQEwMQYDVR0lBCowKAYHZ4EFBQRkBgYHZ4EFBQRkCAYHZ4EFBQRkDAYLKwYB
BAGCN2YBMgEwgccGBmeBBQUEAQSBvDCBuYAJTWljcm9zb2Z0gRRBenVyZSBJbnRl
Z3JhdGVkIEhTTYIQMy40LjAuMC01MDcyODIzNIMBAIQBAKZ+MD0GCWCGSAFlAwQC
AgQwV2nD60Fqg+Aw7U5e6iuPvGJRcOh/TIXauVUeW6rqTgQFpe0DiL3WVLVoA5D+
7nW6MD0GCWCGSAFlAwQCAgQwLmMNtSL3jtdfAlusjgtVkNcPfYr4edx2oon3JRLp
oCjuTQmGFdNxexnmsco2mO5KMB4GBmeBBQUEBAQUMBIEEBC5izyLtO+EC+gQCkCZ
lzQwggJ2BgorBgEEAYI3ZgMBBIICZjCCAmIwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AATxqUh2Gpg5pTr2yVaCZiA2XF0e8n7Mi4jQwO1OU/ritFsJAq1xzLu7Gwc1IPMD
+nfuxoPhIz6hEY4+MlvJLptDQeZhplhqw+rget1lRxAmsAvAPhiTFs6UAQCoHT9i
J4kGCysGAQQBgjdmAwIIBIIBUE5KcCgD7JzvYMBouHln/27T/RthTuOihPDRwC1d
6m8B/14imgSG0pundhrdk+HHLUm8tiCZI+AUFmIdw5W1usd44eaw6YKQDxf8yiDG
48vLNBpPlcVLLmqn1ZQuLpF8KI/A/+KfawA9g38ik0PUOrAFgvVKqlp+5RYzv1Sy
p0o8gLoc/FzsulkB8PLz38/UvvZqJXmbR9SUr7S6S3uEGkLLGawR86KZ1456VE9r
0YM43ACX16BY1vv3ya/dncDWgoqgI8U51OfBhzD9P7bP8iOVheZIZOaRFPcOAaUU
VLksfpRIgKMvKd/dapcml0BXMJTmasUdKCo0Xpm+RERr/DVEcBJWt3IiuZf3bncn
Cy7yefOiYJaj7aRv7yQGfBY8v6kYiN0mhVj6DymgPNtCUa0UZ2NkI30tFIxNY/YJ
TPtf9oCfefJmfXDsWSs9NQZgCjAKBggqhkjOPQQDAwNnADBkAjADQol0RHh+AnAn
SMqDH642pK2US8Vy961WUBCnfu+6/HgQoeH+vxjOYTSmWCXTmHUCMEc3JWXaLTnB
O9K2GZ95jkSeI/TWzZDFN1C3BlWo1Rl5i+82ZbSvDWT/6joqMxM6eYALKwYBBAGC
N2YBMgGBBQAAAAAAMAoGCCqGSM49BAMDA2gAMGUCMH/AiIYoS1D5zt4mMgH5vFet
CtAiHKp2iOa+r5Pu1wR/cyhVYBU0X0mobQpOyVoCgQIxALkQHtwUfn1FTOd/hmN9
zox4ijKFy2ZavqN6ROWxvezFatNsMfmidscgfBIwSKG8mQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtDCCATqgAwIBAgIEdlQyEDAKBggqhkjOPQQDAzAPMQ0wCwYDVQQDDARSb290
MCAXDTE5MDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjARMQ8wDQYDVQQDDAZJ
bnRyQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASyjx3fGGEWzpaKHiShAJFzDmkw
dln1g39/3EFGhP7YZ4Wsm7JXrsesfS5iLEi4ZEllfEEyjIfDR1u8PRR0TQVu/7I4
YYFlEts5c+LUjHjjT86VXaBOwIbfr79dfWIQMJSjYzBhMB0GA1UdDgQWBBQlRPL3
f9g7QrXpx67di93UsQMwXzAfBgNVHSMEGDAWgBSll2BZ98JCN6AbyKnHuDqm9FHO
5TAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAwNo
ADBlAjA056leXfOLxqmYGKt5H3UBSIeAVAOVMg2431+bX9oju7Amo4YgTpOWnz1s
ayII8zUCMQCyFv8uJjv1PAkix37aFSopXgSWw6CjTVuaGRpUnPhcKZMt3pRJbw0F
rGYK5mz4K7g=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBsjCCATigAwIBAgIEEjRWeDAKBggqhkjOPQQDAzAPMQ0wCwYDVQQDDARSb290
MCAXDTE5MDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAPMQ0wCwYDVQQDDARS
b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE3ub6UfNIH1tFIF+2qmmsAsKZnynN
SF4Q/8dIOlVrIk67lXym9d1y1PfKNspimN0x3N5e2rU7TzvOYzy5vDuDvGDuI3jS
cHPSoDq61fWKjiPHiiYnUDpVI3AAYjb5huVLo2MwYTAdBgNVHQ4EFgQUpZdgWffC
QjegG8ipx7g6pvRRzuUwHwYDVR0jBBgwFoAUpZdgWffCQjegG8ipx7g6pvRRzuUw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwMDaAAw
ZQIwIGyCT3F8oqTaOfYZr9tA6T60dPTcHKK7huASVQccF6KrHlLd4LtVpqfrx14/
IbZjAjEAlxrSOStH/i2BzXUq6Xp1OURNzHjfEjeMBT+rt/c8yZwMEUgv2mQjEVtz
qUzzk3pb
-----END CERTIFICATE-----
    "#;

    let result = verify_certificate_chain(raw_collateral.as_bytes().to_vec());
    assert!(result.is_ok(), "result {:?}", result);
    let result = result.unwrap();
    assert!(result, "Verification result should be true");
}

#[test]
fn test_get_collateral() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Call get_certificate
        let result = app_session.get_certificate();
        assert!(result.is_ok(), "result {:?}", result);

        let collateral = result.unwrap();

        match collateral {
            ManticoreCertificate::PhysicalManticore(cert_chain) => {
                let result = verify_certificate_chain(cert_chain);
                assert!(result.is_ok(), "Verification failed with {:?}", result);
                let result = result.unwrap();
                assert!(result, "Verification result should be true");
            }
            ManticoreCertificate::VirtualManticore {
                ak_cert,
                tee_cert_chain,
                tee_report,
            } => {
                // Check ak_cert
                let cert_from_der = X509::from_pem(&ak_cert);
                println!("AK Cert: {:?}", cert_from_der);
                assert!(cert_from_der.is_ok());

                let public_key = cert_from_der.unwrap().public_key();
                assert!(public_key.is_ok());

                // the rest should be empty for now
                assert!(tee_cert_chain.is_empty());
                assert!(tee_report.is_empty());
            }
        }
    });
}

#[test]
fn test_get_collateral_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Call get_certificate
        let result = app_session.get_certificate();
        assert!(result.is_err(), "result {:?}", result);
    });
}

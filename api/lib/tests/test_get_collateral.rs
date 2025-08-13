// Copyright (C) Microsoft Corporation. All rights reserved.

// TODO: Currently restricting tests to Linux as openssl use is disallowed on Windows
// and causes S360 issues. Need to find a good way to run these tests on Windows.
#![cfg(target_os = "linux")]

mod common;

use mcr_api::*;
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509StoreContext;
use openssl::x509::X509;
use test_with_tracing::test;

use crate::common::*;

/// Verify the collateral returned from GetCollateral call to a physical manticore
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
MIICmzCCAiGgAwIBAgIIW4bWzoJl4zIwCgYIKoZIzj0EAwMwSzFJMEcGA1UEAwxA
UVh3Mzk4a20xWWZDN3BZQ0NTNmVwMlNqLzVXYi9iUlVrRDJxa1RYZk4yb1A4NHJT
ZzljeUI3ejNzWGVzUFNHQTAgFw0xODAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1
OVowSzFJMEcGA1UEAwxAVzRiV3pvSmw0ekxQUlJUUXRkZ3FLV0ZRL1FMYjA0QzJs
TGtKWFBSbllOWERXMDhTUUt6S1NTT1lWd0c1WE9vUzB2MBAGByqGSM49AgEGBSuB
BAAiA2IABKAB7fwHsVqaapgFJ58jzXd2VG9IMBjZcYrXzu/l/r5PFvNACncRCp1l
W0u/vGg2Xhjc4JonyD2/N1XahzSwIrnMPsgVU/hjL9ecWL+fasaWxuYQRcEOULpf
0Nd/DQz0AaOBzzCBzDAdBgNVHQ4EFgQUDq43q9OCwn6vO2rHS1A7TnhFVRowHwYD
VR0jBBgwFoAUlVvQOSrea0DAcQMCSc2njWy5hh4wDgYDVR0PAQH/BAQDAgOIMBYG
A1UdJQEB/wQMMAoGCCsGAQUFBwMCMGIGBmeBBQUEAQRYMFaCEDMuMi41LjUtNTAz
MTkyMDGDAQCmPzA9BglghkgBZQMEAgIEMMNrXsx4CfCfK3NISqN7H3d47PEhViff
3ti3tZmyen7OcA6IuFaJtc5FHOF5uBjF/TAKBggqhkjOPQQDAwNoADBlAjEAp1xZ
UZwoEBN1mp/vYXZj7PVYmR1rm15JHTbnErfIa1LlofrKhzqAv2se/7Cnff0UAjAU
P+n/3x5CRsK0j3bneqdkd0ATAnzN6ttddpnChtNpTSSD4R9OTbgxxKb41WIOA0A=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEGTCCA5+gAwIBAgITMwAAZDVh5vCS3n4g1QAAAABkNTAKBggqhkjOPQQDAzBY
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkw
JwYDVQQDEyBNaWNyb3NvZnQgQ2xvdWQgU2VydmVyIEVPQyBDQSAwMTAeFw0yNTAz
MzExNjU4MjhaFw0zNTAzMjkxNjU4MjhaMEsxSTBHBgNVBAMTQFFYdzM5OGttMVlm
QzdwWUNDUzZlcDJTai81V2IvYlJVa0QycWtUWGZOMm9QODRyU2c5Y3lCN3ozc1hl
c1BTR0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQHHEg4ggrMCL3jJR66C8gfKzNK
UHs3eSWmBMyQe1yyHW4Dh/prTwvVgmB/VJVw4jshzeqrIdzZeol0FwLo8Ey6b9g9
b8mn627beFwQ7fvOa+u1WDtY2Zsm1rFfijh6OJmjggI2MIICMjAOBgNVHQ8BAf8E
BAMCAgQwFgYDVR0lBA8wDQYLKwYBBAGCN2YBMgEwDwYDVR0TAQH/BAUwAwEB/zBi
BgZngQUFBAEEWDBWghAzLjIuNS4wLTUwMzEzMjMzgwEApj8wPQYJYIZIAWUDBAIC
BDDiKrLWsXXXIDVAbZMUQUNch3Ys3h/sv1s10CyUw40QQNFvwIGg0C4b2iHUcXcW
c98wHgYGZ4EFBQQEBBQwEgQQEFyuB8J/fAOiB8OwUJyMtjAdBgNVHQ4EFgQUlVvQ
OSrea0DAcQMCSc2njWy5hh4wHwYDVR0jBBgwFoAUrZ/G0eZ5CqFH8tCWdwPqyA2l
++4wYwYDVR0fBFwwWjBYoFagVIZSaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
aW9wcy9jcmwvTWljcm9zb2Z0JTIwQ2xvdWQlMjBTZXJ2ZXIlMjBFT0MlMjBDQSUy
MDAxLmNybDBwBggrBgEFBQcBAQRkMGIwYAYIKwYBBQUHMAKGVGh0dHA6Ly93d3cu
bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwQ2xvdWQlMjBT
ZXJ2ZXIlMjBFT0MlMjBDQSUyMDAxLmNydDA8BgkrBgEEAYI3FQcELzAtBiUrBgEE
AYI3FQiHvdcbgefrRoKBnS6O0AyH8NodXazb7VyOyug6AgFkAgEDMB4GCSsGAQQB
gjcVCgQRMA8wDQYLKwYBBAGCN2YBMgEwCgYIKoZIzj0EAwMDaAAwZQIwItCodQ8m
kxq3eg9dUu+goh7BINACeO5JCYKVFajVzDKZHryJHQNKJlyW1qT9byRkAjEAsowt
z2l1qciIHBBn6x1FGJ5vOkHAcXHIF48/2f/Tw/Wbh69oR/cjtKB8YphjIgsy
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE2jCCBGCgAwIBAgITMwAAABzDWbbsSKCeQQAAAAAAHDAKBggqhkjOPQQDAzCB
jTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE3MDUGA1UEAxMu
QXp1cmUgSGFyZHdhcmUgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxOTAe
Fw0yMzA0MTMxOTE5MTVaFw0zNjA0MTQxOTE5MTVaMFgxCzAJBgNVBAYTAlVTMR4w
HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAMTIE1pY3Jvc29m
dCBDbG91ZCBTZXJ2ZXIgRU9DIENBIDAxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE
z97GcVaDRoieWwwaMxe6v+Gk3nUKzAthf69cFtCUfsS5oDj49h/0poEMxKv/6+0i
CzMZ02Yvx5Pk8dhNNz2/Eoa52wvdwNFUVNb2G60GruBUhMLAHwyIso6AAJTixY3L
o4ICtDCCArAwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1Ud
DgQWBBStn8bR5nkKoUfy0JZ3A+rIDaX77jARBgNVHSAECjAIMAYGBFUdIAAwggEY
BgNVHSUEggEPMIIBCwYLKwYBBAGCN2YBAAEGDCsGAQQBgjdmAQCHZwYLKwYBBAGC
N2YBAQEGDCsGAQQBgjdmAQGHZwYLKwYBBAGCN2YBHgEGCysGAQQBgjdmAR8BBgwr
BgEEAYI3ZgEfh2cGCysGAQQBgjdmASABBgsrBgEEAYI3ZgEhAQYMKwYBBAGCN2YB
IYdnBgsrBgEEAYI3ZgEiAQYMKwYBBAGCN2YBIodnBgsrBgEEAYI3ZgEjAQYMKwYB
BAGCN2YBI4dnBgsrBgEEAYI3ZgEkAQYLKwYBBAGCN2YBJQEGCysGAQQBgjdmASYB
BgsrBgEEAYI3ZgEnAQYLKwYBBAGCN2YBMgEGDCsGAQQBgjdmATKHZzAZBgkrBgEE
AYI3FAIEDB4KAFMAdQBiAEMAQTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaA
FAo26kVq3ohh76KHT5Pp6PYxUatgMHEGA1UdHwRqMGgwZqBkoGKGYGh0dHA6Ly93
d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL0F6dXJlJTIwSGFyZHdhcmUlMjBS
b290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE5LmNybDB+BggrBgEF
BQcBAQRyMHAwbgYIKwYBBQUHMAKGYmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
a2lvcHMvY2VydHMvQXp1cmUlMjBIYXJkd2FyZSUyMFJvb3QlMjBDZXJ0aWZpY2F0
ZSUyMEF1dGhvcml0eSUyMDIwMTkuY3J0MAoGCCqGSM49BAMDA2gAMGUCMFeZ9Y/d
BQhzPEokRlx/ptWgUkGkM4TNaHzFZ4ndKPnrgNerqMZD9clYrLl9gO9MxgIxAI4C
ROVjdWrEWZNSIWRsy/+K3LUR2rTFvt4C1vu3AYjZRQdoV4jILaUx57smLFVfrg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDAzCCAomgAwIBAgIQHMAA2LmDGYhM3PIXwcdC2TAKBggqhkjOPQQDAzCBjTEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE3MDUGA1UEAxMuQXp1
cmUgSGFyZHdhcmUgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxOTAeFw0x
OTA3MDMxODQ3MTFaFw00NDA3MDMxODU1MzRaMIGNMQswCQYDVQQGEwJVUzETMBEG
A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
cm9zb2Z0IENvcnBvcmF0aW9uMTcwNQYDVQQDEy5BenVyZSBIYXJkd2FyZSBSb290
IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE5MHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEVs8NIaBW12Tz9eszEkZOSCtFy3QJGtkmvC84Lr5B4wGC4R52Me+CmqgNS1Bu
0ppLBlDO7Psnbb3HNxxTdOzeYoZvttlZ/qRvklR1Xnrxn0+N8JdtWVuumRA5BBfq
MLgPo4GrMIGoMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBQKNupFat6IYe+ih0+T6ej2MVGrYDAQBgkrBgEEAYI3FQEEAwIBADBUBgNV
HSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMAoGCCqGSM49BAMDA2gA
MGUCMBqjQdOFS+lhO+FsC9/ey2Ig/u0XA64dwpo26mnkIT1qIGtHCEO8RAdxbsyY
OsIi/gIxAIcSSL1aCTK1oEykCFYtgPRtaqoKQ5T6285VZzW9yx00fXcwHbJvjFCg
qx2BKpSsEg==
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

        // Call get_collateral
        let result = app_session.get_collateral();
        assert!(result.is_ok(), "result {:?}", result);

        let collateral = result.unwrap();

        match collateral {
            ManticoreCollateral::PhysicalManticore(cert_chain) => {
                let result = verify_certificate_chain(cert_chain);
                assert!(result.is_ok(), "verification failed with {:?}", result);
                let result = result.unwrap();
                assert!(result, "Verification result should be true");
            }
            ManticoreCollateral::VirtualManticore {
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

        // Call get_collateral
        let result = app_session.get_collateral();
        assert!(result.is_err(), "result {:?}", result);
    });
}

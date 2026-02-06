// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_types::*;

#[test]
fn test_ddiop_to_sessioncontrolkind() {
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetApiRev),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetDeviceInfo),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetEstablishCredEncryptionKey),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::EstablishCredential),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetSessionEncryptionKey),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetCertChainInfo),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetCertificate),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::InitBk3),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetSealedBk3),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::SetSealedBk3),
        SessionControlKind::NoSession
    );

    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::OpenSession),
        SessionControlKind::Open
    );

    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::CloseSession),
        SessionControlKind::Close
    );

    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::Invalid),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::DeleteKey),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::OpenKey),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::AttestKey),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::RsaModExp),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::RsaUnwrap),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::GetUnwrappingKey),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::EccGenerateKeyPair),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::EccSign),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::AesGenerateKey),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::AesEncryptDecrypt),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::EcdhKeyExchange),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::HkdfDerive),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::KbkdfCounterHmacDerive),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::ChangePin),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(DdiOp::ProvisionPart),
        SessionControlKind::InSession
    );
}

#[test]
fn test_sessioncontrolkind_to_u8() {
    assert_eq!(Into::<u8>::into(SessionControlKind::NoSession), 0);
    assert_eq!(Into::<u8>::into(SessionControlKind::Open), 1);
    assert_eq!(Into::<u8>::into(SessionControlKind::Close), 2);
    assert_eq!(Into::<u8>::into(SessionControlKind::InSession), 3);
}

#[test]
fn test_u8_to_sessioncontrolkind() {
    assert_eq!(
        Into::<SessionControlKind>::into(0),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(1),
        SessionControlKind::Open
    );
    assert_eq!(
        Into::<SessionControlKind>::into(2),
        SessionControlKind::Close
    );
    assert_eq!(
        Into::<SessionControlKind>::into(3),
        SessionControlKind::InSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(4),
        SessionControlKind::NoSession
    );
    assert_eq!(
        Into::<SessionControlKind>::into(u8::MAX),
        SessionControlKind::NoSession
    );
}

#[test]
fn test_sessioninforequest_default() {
    let sir = SessionInfoRequest::default();

    assert_eq!(sir.session_control_kind, SessionControlKind::NoSession);
    assert_eq!(sir.session_id, None);
}

#[test]
fn test_sessioninforesponse_default() {
    let sir = SessionInfoResponse::default();

    assert_eq!(sir.response_length, 0);
    assert_eq!(sir.session_control_kind, SessionControlKind::NoSession);
    assert_eq!(sir.session_id, None);
    assert_eq!(sir.short_app_id, None);
}

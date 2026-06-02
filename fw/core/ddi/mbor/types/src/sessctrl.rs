// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Session control kind for DDI operations.
pub enum SessionControlKind {
    NoSession = 0,
    Open = 1,
    Close = 2,
    InSession = 3,
}

/// Session info carried with a DDI request.
#[derive(Default)]
pub struct SessionInfoRequest {
    pub session_control_kind: SessionControlKindDefault,
    pub session_id: Option<u16>,
}

/// Wrapper to allow Default on SessionControlKind.
pub struct SessionControlKindDefault(pub SessionControlKind);

impl Default for SessionControlKindDefault {
    fn default() -> Self {
        Self(SessionControlKind::NoSession)
    }
}

/// Session info carried with a DDI response.
pub struct SessionInfoResponse {
    pub response_length: u16,
    pub session_control_kind: SessionControlKind,
    pub session_id: Option<u16>,
    pub short_app_id: Option<u8>,
}

impl Default for SessionInfoResponse {
    fn default() -> Self {
        Self {
            response_length: 0,
            session_control_kind: SessionControlKind::NoSession,
            session_id: None,
            short_app_id: None,
        }
    }
}

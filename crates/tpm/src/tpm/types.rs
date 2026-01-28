// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal TPM2 type definitions with binary (un)marshalling helpers.
//! These are intentionally partial and only cover what current code paths need.

// Command structs now mirror the TPM wire format as (header, handles, parameters)
// to make command construction and parsing more explicit.
use std::cell::RefCell;
use std::convert::TryInto;
use std::io;

use bitfield_struct::bitfield;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_RSAES: u16 = 0x0005;
pub const TPMA_NV_OWNERWRITE: u32 = 1 << 1;
pub const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
pub const TPMA_NV_OWNERREAD: u32 = 1 << 17;
pub const TPMA_NV_AUTHREAD: u32 = 1 << 18;

#[derive(Copy, Clone, Debug)]
pub enum Hierarchy {
    Null,
    Owner,
    Endorsement,
}

impl Hierarchy {
    pub fn handle(self) -> u32 {
        match self {
            Hierarchy::Owner => 0x4000_0001,
            Hierarchy::Null => 0x4000_0007,
            Hierarchy::Endorsement => 0x4000_000B,
        }
    }
}

#[bitfield(u32)]
pub struct TpmaNvBits {
    pub nv_ppwrite: bool,
    pub nv_ownerwrite: bool,
    pub nv_authwrite: bool,
    pub nv_policywrite: bool,
    // bits 7:4: `TPM_NT`
    // 0001 - `tpm_nt_counter`
    pub nt_counter: bool,
    // 0010 - `tpm_nt_bits`
    pub nt_bits: bool,
    // 0100 - `tpm_nt_extend`
    pub nt_extend: bool,
    _unused0: bool,
    // bits 9:8 are reserved
    #[bits(2)]
    _reserved1: u8,
    pub nv_policy_delete: bool,
    pub nv_writelocked: bool,
    pub nv_writeall: bool,
    pub nv_writedefine: bool,
    pub nv_write_stclear: bool,
    pub nv_globallock: bool,
    pub nv_ppread: bool,
    pub nv_ownerread: bool,
    pub nv_authread: bool,
    pub nv_policyread: bool,
    // bits 24:20 are reserved
    #[bits(5)]
    _reserved2: u8,
    pub nv_no_da: bool,
    pub nv_orderly: bool,
    pub nv_clear_stclear: bool,
    pub nv_readlocked: bool,
    pub nv_written: bool,
    pub nv_platformcreate: bool,
    pub nv_read_stclear: bool,
}

#[bitfield(u32)]
pub struct TpmaObjectBits {
    _reserved0: bool,
    pub fixed_tpm: bool,
    pub st_clear: bool,
    _reserved1: bool,
    pub fixed_parent: bool,
    pub sensitive_data_origin: bool,
    pub user_with_auth: bool,
    pub admin_with_policy: bool,
    #[bits(2)]
    _reserved2: u8,
    pub no_da: bool,
    pub encrypted_duplication: bool,
    #[bits(4)]
    _reserved3: u8,
    pub restricted: bool,
    pub decrypt: bool,
    pub sign_encrypt: bool,
    #[bits(13)]
    _reserved4: u16,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum TpmAlgId {
    Rsa = 0x0001,
    Aes = 0x0006,
    KeyedHash = 0x0008,
    Sha256 = 0x000b,
    Null = 0x0010,
    RsaSsa = 0x0014,
    Cfb = 0x0043,
}

impl From<TpmAlgId> for u16 {
    fn from(value: TpmAlgId) -> Self {
        value as u16
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmCommandCode {
    CreatePrimary = 0x00000131,
    Create = 0x00000153,
    Load = 0x00000157,
    Quote = 0x00000158,
    RsaDecrypt = 0x00000159,
    FlushContext = 0x00000165,
    Unseal = 0x0000015E,
    ReadPublic = 0x00000173,
    PcrRead = 0x0000017E,
    PolicyPCR = 0x0000017F,
    Certify = 0x00000148,
    StartAuthSession = 0x00000176,
    PolicyGetDigest = 0x00000189,
    NvReadPublic = 0x00000169,
    NvRead = 0x0000014E,
    NvWrite = 0x00000137,
    NvDefineSpace = 0x0000012A,
    NvUndefineSpace = 0x00000122,
    EvictControl = 0x00000120,
    Hmac = 0x00000155,
}

#[derive(Debug, Clone, Copy)]
pub struct TpmCommandHeader {
    pub tag: u16,
    pub size: u32,
    pub command_code: TpmCommandCode,
}

impl TpmCommandHeader {
    pub fn no_sessions(command_code: TpmCommandCode) -> Self {
        Self {
            tag: TPM_ST_NO_SESSIONS,
            size: 0,
            command_code,
        }
    }

    pub fn sessions(command_code: TpmCommandCode) -> Self {
        Self {
            tag: TPM_ST_SESSIONS,
            size: 0,
            command_code,
        }
    }

    pub fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    pub fn marshal_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.tag.to_be_bytes());
        buf.extend_from_slice(&self.size.to_be_bytes());
        buf.extend_from_slice(&(self.command_code as u32).to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TpmResponseHeader {
    pub tag: u16,
    pub size: u32,
    pub return_code: u32,
}

impl TpmResponseHeader {
    pub fn parse(bytes: &[u8]) -> io::Result<(Self, usize)> {
        if bytes.len() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TPM response header truncated",
            ));
        }
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        if size as usize > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TPM response size larger than buffer",
            ));
        }
        let return_code = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        Ok((
            TpmResponseHeader {
                tag,
                size,
                return_code,
            },
            10,
        ))
    }

    pub fn has_sessions(&self) -> bool {
        self.tag == TPM_ST_SESSIONS
    }
}

macro_rules! count_fields {
    ($($field:ident),+ $(,)?) => {
        <[()]>::len(&[$(count_fields!(@sub $field)),*])
    };
    (@sub $field:ident) => {
        {
            let _ = stringify!($field);
        }
    };
}

macro_rules! define_handle_struct {
    ($(#[$meta:meta])* $name:ident { $($field:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            $(pub $field: u32,)*
        }

        impl $name {
            pub fn to_array(&self) -> [u32; count_fields!($($field),+)] {
                [$(self.$field),*]
            }
        }
    };
    ($(#[$meta:meta])* $name:ident;) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name;

        impl $name {
            pub fn to_array(&self) -> [u32; 0] {
                []
            }
        }
    };
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryCommandHandles {
    pub hierarchy: Hierarchy,
}

impl CreatePrimaryCommandHandles {
    pub fn to_array(&self) -> [u32; 1] {
        [self.hierarchy.handle()]
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryCommandParameters {
    pub in_sensitive: Tpm2bSensitiveCreate,
    pub in_public: Tpm2bPublic,
    pub outside_info: Tpm2bBytes,
    pub creation_pcr: PcrSelectionList,
}

impl TpmMarshal for CreatePrimaryCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.in_sensitive.marshal(buf);
        self.in_public.marshal(buf);
        self.outside_info.marshal(buf);
        self.creation_pcr.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryCommand {
    pub header: TpmCommandHeader,
    pub handles: CreatePrimaryCommandHandles,
    pub parameters: CreatePrimaryCommandParameters,
}

impl CreatePrimaryCommand {
    pub fn new(hierarchy: Hierarchy, parameters: CreatePrimaryCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::CreatePrimary),
            handles: CreatePrimaryCommandHandles { hierarchy },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryResponseHandles {
    pub object_handle: u32,
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryResponseParameters {
    pub out_public: Tpm2bPublic,
    pub creation_data: Tpm2bBytes,
    pub creation_hash: Tpm2bBytes,
    pub creation_ticket: Vec<u8>,
    pub name: Tpm2bBytes,
    pub qualified_name: Tpm2bBytes,
}

impl CreatePrimaryResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let _param_size = u32::unmarshal(d, c)?;

        let out_public = Tpm2bPublic::unmarshal(d, c)?;
        let creation_data = Tpm2bBytes::unmarshal(d, c)?;
        let creation_hash = Tpm2bBytes::unmarshal(d, c)?;
        if *c + 2 + 4 > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ticket header",
            ));
        }
        let start = *c;
        *c += 2 + 4;
        let digest = Tpm2bBytes::unmarshal(d, c)?;
        let ticket_slice = &d[start..start + 2 + 4 + 2 + digest.0.len()];
        let creation_ticket = ticket_slice.to_vec();
        let name = Tpm2bBytes::unmarshal(d, c)?;
        let qualified_name = Tpm2bBytes::unmarshal(d, c)?;
        Ok(CreatePrimaryResponseParameters {
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
            name,
            qualified_name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryResponse {
    pub header: TpmResponseHeader,
    pub handles: CreatePrimaryResponseHandles,
    pub parameters: CreatePrimaryResponseParameters,
}

impl CreatePrimaryResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "CreatePrimary returned error 0x{:08x}",
                header.return_code
            )));
        }
        if cursor + 4 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "CreatePrimary response missing object handle",
            ));
        }
        let object_handle = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let mut param_cursor = cursor;
        let parameters = CreatePrimaryResponseParameters::unmarshal(bytes, &mut param_cursor)?;

        Ok(CreatePrimaryResponse {
            header,
            handles: CreatePrimaryResponseHandles { object_handle },
            parameters,
        })
    }
}

// TPM2_Load --------------------------------------------------------------
define_handle_struct!(LoadCommandHandles { parent_handle });

#[derive(Debug, Clone)]
pub struct LoadCommandParameters {
    pub in_private: Tpm2bPrivate,
    pub in_public: Tpm2bBytes,
}

impl TpmMarshal for LoadCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.in_private.marshal(buf);
        self.in_public.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand {
    pub header: TpmCommandHeader,
    pub handles: LoadCommandHandles,
    pub parameters: LoadCommandParameters,
}

impl LoadCommand {
    pub fn new(parent_handle: u32, parameters: LoadCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Load),
            handles: LoadCommandHandles { parent_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

define_handle_struct!(LoadResponseHandles { object_handle });

#[derive(Debug, Clone)]
pub struct LoadResponseParameters {
    pub name: Tpm2bBytes,
}

impl TpmUnmarshal for LoadResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let name = Tpm2bBytes::unmarshal(d, c)?;
        Ok(LoadResponseParameters { name })
    }
}

#[derive(Debug, Clone)]
pub struct LoadResponse {
    pub header: TpmResponseHeader,
    pub handles: LoadResponseHandles,
    pub parameters: LoadResponseParameters,
}

impl LoadResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Load returned error 0x{:08x}",
                header.return_code
            )));
        }

        if cursor + 4 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Load response missing object handle",
            ));
        }
        let object_handle = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Load response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = LoadResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Load response parameter size mismatch",
                ));
            }
        }

        Ok(LoadResponse {
            header,
            handles: LoadResponseHandles { object_handle },
            parameters,
        })
    }
}

// TPM2_Unseal ------------------------------------------------------------
define_handle_struct!(UnsealCommandHandles { item_handle });

#[derive(Debug, Clone, Default)]
pub struct UnsealCommandParameters;

impl TpmMarshal for UnsealCommandParameters {
    fn marshal(&self, _buf: &mut Vec<u8>) {}
}

#[derive(Debug, Clone)]
pub struct UnsealCommand {
    pub header: TpmCommandHeader,
    pub handles: UnsealCommandHandles,
    pub parameters: UnsealCommandParameters,
}

impl UnsealCommand {
    pub fn new(item_handle: u32) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Unseal),
            handles: UnsealCommandHandles { item_handle },
            parameters: UnsealCommandParameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct UnsealResponseParameters {
    pub out_data: Tpm2bSensitiveData,
}

impl TpmUnmarshal for UnsealResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let data = Tpm2bBytes::unmarshal(d, c)?;
        Ok(UnsealResponseParameters { out_data: data })
    }
}

#[derive(Debug, Clone)]
pub struct UnsealResponse {
    pub header: TpmResponseHeader,
    pub parameters: UnsealResponseParameters,
}

impl UnsealResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Unseal returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unseal response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = UnsealResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unseal response parameter size mismatch",
                ));
            }
        }

        Ok(UnsealResponse { header, parameters })
    }
}

// TPM2_Create (Seal) ----------------------------------------------------
define_handle_struct!(CreateCommandHandles { parent_handle });

#[derive(Debug, Clone)]
pub struct CreateCommandParameters {
    pub in_sensitive: Tpm2bSensitiveCreate,
    pub in_public: Tpm2bPublic,
    pub outside_info: Tpm2bBytes,
    pub creation_pcr: PcrSelectionList,
}

impl TpmMarshal for CreateCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.in_sensitive.marshal(buf);
        self.in_public.marshal(buf);
        self.outside_info.marshal(buf);
        self.creation_pcr.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct CreateCommand {
    pub header: TpmCommandHeader,
    pub handles: CreateCommandHandles,
    pub parameters: CreateCommandParameters,
}

impl CreateCommand {
    pub fn new(parent_handle: u32, parameters: CreateCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Create),
            handles: CreateCommandHandles { parent_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct CreateResponseParameters {
    pub out_private: Tpm2bPrivate,
    pub out_public: Tpm2bBytes,
    pub creation_data: Tpm2bBytes,
    pub creation_hash: Tpm2bBytes,
    pub creation_ticket: Vec<u8>,
}

impl TpmUnmarshal for CreateResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let out_private = Tpm2bPrivate::unmarshal(d, c)?;
        let out_public = Tpm2bBytes::unmarshal(d, c)?;
        let creation_data = Tpm2bBytes::unmarshal(d, c)?;
        let creation_hash = Tpm2bBytes::unmarshal(d, c)?;

        // Parse creation ticket properly: tag (2 bytes) + hierarchy (4 bytes) + digest (TPM2B)
        if *c + 2 + 4 > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Create response missing creation ticket header",
            ));
        }
        let start = *c;
        *c += 2 + 4; // skip tag and hierarchy
        let digest = Tpm2bBytes::unmarshal(d, c)?;
        let ticket_slice = &d[start..start + 2 + 4 + 2 + digest.0.len()];
        let creation_ticket = ticket_slice.to_vec();

        Ok(CreateResponseParameters {
            out_private,
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CreateResponse {
    pub header: TpmResponseHeader,
    pub parameters: CreateResponseParameters,
}

impl CreateResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Create returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Create response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = match param_size {
            Some(size) => CreateResponseParameters::unmarshal(
                &bytes[..param_cursor + size],
                &mut param_cursor,
            )?,
            None => CreateResponseParameters::unmarshal(bytes, &mut param_cursor)?,
        };
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Create response parameter size mismatch",
                ));
            }
        }

        Ok(CreateResponse { header, parameters })
    }
}

pub trait TpmMarshal {
    fn marshal(&self, buf: &mut Vec<u8>);
}

pub trait TpmUnmarshal: Sized {
    fn unmarshal(data: &[u8], cursor: &mut usize) -> io::Result<Self>;
}

// Primitive helpers
impl TpmMarshal for u8 {
    fn marshal(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}
impl TpmMarshal for u16 {
    fn marshal(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}
impl TpmMarshal for u32 {
    fn marshal(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl TpmUnmarshal for u8 {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        if *c + 1 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u8"));
        }
        let v = d[*c];
        *c += 1;
        Ok(v)
    }
}
impl TpmUnmarshal for u16 {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        if *c + 2 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u16"));
        }
        let v = u16::from_be_bytes([d[*c], d[*c + 1]]);
        *c += 2;
        Ok(v)
    }
}
impl TpmUnmarshal for u32 {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        if *c + 4 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u32"));
        }
        let v = u32::from_be_bytes(d[*c..*c + 4].try_into().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse u32 from bytes {}-{}: {}", *c, *c + 4, err),
            )
        })?);
        *c += 4;
        Ok(v)
    }
}

// Sized buffer wrapper for TPM2B_* style structures.
// Layout on the wire: 2-byte big-endian length (u16) followed by the raw marshaled bytes of `inner`.
// Many TPM commands need the length-prefixed encoding multiple times (e.g. size calculations
// before final command assembly). Recomputing the inner marshaling each time adds avoidable
// allocations and length math, so we lazily cache the complete length-prefixed byte vector the
// first time it is produced.
//
// Why RefCell<Option<Vec<u8>>> instead of precomputing eagerly:
//   * Not every constructed value is marshaled (some are only inspected); lazy avoids wasted work.
//   * We want to cache while taking only &self in marshal(); RefCell provides interior mutability.
//   * Option distinguishes "not yet built" vs "cached".
// Safety / invariants:
//   * `inner` is never exposed mutably after construction, so cached bytes stay valid.
//   * If mutation were ever added, the cache would need invalidation (not currently required).
// Threading:
//   * RefCell is !Sync; this wrapper is intended for single-threaded command construction paths.
//     If Sync use is needed later, a different interior type (e.g. OnceLock) can be substituted.
#[derive(Debug, Clone)]
pub struct Tpm2b<T: TpmMarshal + Clone> {
    pub inner: T,
    /* cached length-prefixed bytes */ cached: RefCell<Option<Vec<u8>>>,
}

impl<T: TpmMarshal + Clone> Tpm2b<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cached: RefCell::new(None),
        }
    }

    /// Return the full TPM2B encoding (length prefix + payload) as an owned Vec.
    /// This clones the cached Vec if already built; otherwise it marshals `inner`,
    /// constructs the prefixed form, stores it, then returns it.
    pub fn bytes(&self) -> Vec<u8> {
        // Fast path: already have cached length-prefixed bytes.
        if let Some(c) = self.cached.borrow().as_ref() {
            return c.clone();
        }
        // Marshal the inner structure (without size) into a temporary buffer.
        let mut tmp = Vec::new();
        self.inner.marshal(&mut tmp);
        // Allocate the final buffer with exact capacity (2 bytes length + payload).
        let mut full = Vec::with_capacity(2 + tmp.len());
        (tmp.len() as u16).marshal(&mut full); // write length prefix
        full.extend_from_slice(&tmp); // append payload
                                      // Store for subsequent reuse.
        *self.cached.borrow_mut() = Some(full.clone());
        full
    }
}

impl<T: TpmMarshal + Clone> TpmMarshal for Tpm2b<T> {
    fn marshal(&self, buf: &mut Vec<u8>) {
        let b = self.bytes();
        buf.extend_from_slice(&b);
    }
}

// TPM2B with raw bytes
#[derive(Debug, Clone)]
pub struct Tpm2bBytes(pub Vec<u8>);

impl TpmMarshal for Tpm2bBytes {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.0.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.0);
    }
}

/// TPM2B_PRIVATE wrapper (alias to raw TPM2B bytes container).
pub type Tpm2bPrivate = Tpm2bBytes;

/// TPM2B_SENSITIVE_DATA wrapper (alias to raw TPM2B bytes container).
pub type Tpm2bSensitiveData = Tpm2bBytes;
impl TpmUnmarshal for Tpm2bBytes {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let sz = u16::unmarshal(d, c)? as usize;
        if *c + sz > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "insufficient data to unmarshal TPM2B bytes",
            ));
        }
        let v = d[*c..*c + sz].to_vec();
        *c += sz;
        Ok(Tpm2bBytes(v))
    }
}

// TPML_PCR_SELECTION (only single-bank usage is needed now but we generalize)
#[derive(Debug, Clone)]
pub struct PcrSelectionList(pub Vec<PcrSelection>);

impl PcrSelectionList {
    pub fn from_pcrs(pcrs: &[u32]) -> Self {
        if pcrs.is_empty() {
            return Self(Vec::new());
        }

        let mut bitmap = [0u8; 3];
        for &p in pcrs {
            if p <= 23 {
                let byte = (p / 8) as usize;
                let bit = p % 8;
                bitmap[byte] |= 1u8 << bit;
            }
        }

        Self(vec![PcrSelection {
            hash_alg: ALG_SHA256,
            size_of_select: 3,
            select: bitmap,
        }])
    }
}

#[derive(Debug, Clone)]
pub struct PcrSelection {
    pub hash_alg: u16,
    pub size_of_select: u8,
    pub select: [u8; 3],
}

impl TpmMarshal for PcrSelectionList {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.0.len() as u32).marshal(buf);
        for s in &self.0 {
            s.marshal(buf);
        }
    }
}
impl TpmMarshal for PcrSelection {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.hash_alg.marshal(buf);
        self.size_of_select.marshal(buf);
        buf.extend_from_slice(&self.select[..self.size_of_select as usize]);
    }
}

impl TpmUnmarshal for PcrSelectionList {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let count = u32::unmarshal(d, c)? as usize;
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            let hash_alg = u16::unmarshal(d, c)?;
            let size = u8::unmarshal(d, c)?;
            if size as usize > 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pcr select size>3",
                ));
            }
            if *c + size as usize > d.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "pcr select bytes",
                ));
            }
            let mut arr = [0u8; 3];
            for i in 0..size as usize {
                arr[i] = d[*c + i];
            }
            *c += size as usize;
            v.push(PcrSelection {
                hash_alg,
                size_of_select: size,
                select: arr,
            });
        }
        Ok(PcrSelectionList(v))
    }
}

// Minimal TPMT_RSA_SCHEME (only RSASSA and NULL supported)
#[derive(Debug, Clone)]
pub enum RsaScheme {
    Null,
    Rsassa(u16),
    Other(u16, Vec<u8>), // preserve raw scheme id + remaining bytes (if any)
}
impl TpmMarshal for RsaScheme {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            RsaScheme::Null => {
                0x0010u16.marshal(buf); /* details omitted */
            }
            RsaScheme::Rsassa(hash) => {
                0x0014u16.marshal(buf);
                hash.marshal(buf);
            }
            RsaScheme::Other(id, rest) => {
                id.marshal(buf);
                buf.extend_from_slice(rest);
            }
        }
    }
}

// Minimal KeyedHash Scheme
#[derive(Debug, Clone, PartialEq)]
pub enum KeyedHashScheme {
    Null,
}
impl TpmMarshal for KeyedHashScheme {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            KeyedHashScheme::Null => {
                0x0010u16.marshal(buf); /* details omitted */
            }
        }
    }
}

// TPMT_SYM_DEF_OBJECT (only NULL)
#[derive(Debug, Clone)]
pub struct SymDefObject {
    pub alg: u16,
    pub key_bits: u16,
    pub mode: u16,
}
impl TpmMarshal for SymDefObject {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.alg.marshal(buf);
        if self.alg != TpmAlgId::Null.into() {
            self.key_bits.marshal(buf);
            self.mode.marshal(buf);
        }
    }
}

impl TpmUnmarshal for SymDefObject {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let alg = u16::unmarshal(d, c)?;
        if alg == TpmAlgId::Null.into() {
            return Ok(Self {
                alg,
                key_bits: 0,
                mode: 0,
            });
        }

        let key_bits = u16::unmarshal(d, c)?;
        let mode = u16::unmarshal(d, c)?;

        Ok(Self {
            alg,
            key_bits,
            mode,
        })
    }
}

// TPMT_PUBLIC (RSA, KeyedHash limited subset)
#[derive(Debug, Clone)]
pub struct TpmtPublic {
    pub type_alg: u16, // 0x0001 RSA
    pub name_alg: u16, // typically 0x000B SHA256
    pub object_attributes: u32,
    pub auth_policy: Tpm2bBytes,
    pub detail: TpmtPublicDetail,
    pub unique: Tpm2bBytes,
}
impl TpmMarshal for TpmtPublic {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.type_alg.marshal(buf);
        self.name_alg.marshal(buf);
        self.object_attributes.marshal(buf);
        self.auth_policy.marshal(buf);
        self.detail.marshal(buf);
        self.unique.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub enum TpmtPublicDetail {
    RsaDetail(RsaDetail),
    KeyedHashDetail(KeyedHashDetail),
}
impl TpmMarshal for TpmtPublicDetail {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            TpmtPublicDetail::RsaDetail(rsa_detail) => rsa_detail.marshal(buf),
            TpmtPublicDetail::KeyedHashDetail(keyed_hash_detail) => keyed_hash_detail.marshal(buf),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RsaDetail {
    pub symmetric: SymDefObject,
    pub scheme: RsaScheme,
    pub key_bits: u16,
    pub exponent: u32,
}
impl TpmMarshal for RsaDetail {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.symmetric.marshal(buf);
        self.scheme.marshal(buf);
        self.key_bits.marshal(buf);
        self.exponent.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct KeyedHashDetail {
    pub scheme: KeyedHashScheme,
    pub hash_alg: TpmAlgId,
}
impl TpmMarshal for KeyedHashDetail {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.scheme.marshal(buf);
        if self.scheme != KeyedHashScheme::Null {
            (self.hash_alg as u16).marshal(buf);
        }
    }
}

pub type Tpm2bPublic = Tpm2b<TpmtPublic>;

impl TpmUnmarshal for TpmtPublic {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let type_alg = u16::unmarshal(d, c)?;
        let name_alg = u16::unmarshal(d, c)?;
        let object_attributes = u32::unmarshal(d, c)?;
        let auth_policy = Tpm2bBytes::unmarshal(d, c)?;
        let symmetric = SymDefObject::unmarshal(d, c)?;
        // scheme
        let scheme_id = u16::unmarshal(d, c)?;
        let scheme = match scheme_id {
            0x0010 => RsaScheme::Null,
            0x0014 => {
                let hash = u16::unmarshal(d, c)?;
                RsaScheme::Rsassa(hash)
            }
            other => {
                // Capture remaining bytes for unique parsing stability: for RSA public template, after scheme comes key_bits (u16), exponent (u32), unique (TPM2B)
                // We don't know internal layout for unknown scheme; treat as opaque (no extra bytes consumed beyond id).
                RsaScheme::Other(other, Vec::new())
            }
        };
        let key_bits = u16::unmarshal(d, c)?;
        let exponent = u32::unmarshal(d, c)?;
        let unique = Tpm2bBytes::unmarshal(d, c)?;
        Ok(TpmtPublic {
            type_alg,
            name_alg,
            object_attributes,
            auth_policy,
            detail: TpmtPublicDetail::RsaDetail(RsaDetail {
                symmetric,
                scheme,
                key_bits,
                exponent,
            }),
            unique,
        })
    }
}

impl TpmUnmarshal for Tpm2bPublic {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let sz = u16::unmarshal(d, c)? as usize;
        if *c + sz > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "public size"));
        }
        let start = *c;
        let mut inner_cursor = *c;
        let inner = TpmtPublic::unmarshal(d, &mut inner_cursor)?;
        *c = start + sz;
        Ok(Tpm2b {
            inner,
            cached: std::cell::RefCell::new(None),
        })
    }
}

// TPMS_SENSITIVE_CREATE (only empty usage)
#[derive(Debug, Clone)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bBytes,
    pub data: Tpm2bBytes,
}

impl TpmMarshal for TpmsSensitiveCreate {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.user_auth.marshal(buf);
        self.data.marshal(buf);
    }
}

pub type Tpm2bSensitiveCreate = Tpm2b<TpmsSensitiveCreate>;

pub fn empty_sensitive_create() -> Tpm2bSensitiveCreate {
    Tpm2b::new(TpmsSensitiveCreate {
        user_auth: Tpm2bBytes(Vec::new()),
        data: Tpm2bBytes(Vec::new()),
    })
}

pub fn empty_public_unique() -> Tpm2bBytes {
    Tpm2bBytes(Vec::new())
}

pub fn rsa_unrestricted_sign_decrypt_public_with_policy(policy: Vec<u8>) -> Tpm2bPublic {
    let object_attributes = TpmaObjectBits::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_no_da(true)
        .with_decrypt(true);

    Tpm2b::new(TpmtPublic {
        type_alg: TpmAlgId::Rsa.into(),
        name_alg: TpmAlgId::Sha256.into(),
        object_attributes: object_attributes.into(),
        auth_policy: Tpm2bBytes(policy),
        detail: TpmtPublicDetail::RsaDetail(RsaDetail {
            symmetric: SymDefObject {
                alg: TpmAlgId::Null.into(),
                key_bits: 0,
                mode: 0,
            },
            scheme: RsaScheme::Null,
            key_bits: 2048,
            exponent: 0,
        }),
        unique: empty_public_unique(),
    })
}

pub fn rsa_unrestricted_sign_decrypt_public() -> Tpm2bPublic {
    rsa_unrestricted_sign_decrypt_public_with_policy(Vec::new())
}

/// Restricted signing (AK-like) RSA template: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|sign
pub fn rsa_restricted_signing_public() -> Tpm2bPublic {
    let object_attributes = TpmaObjectBits::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_sign_encrypt(true);

    Tpm2b::new(TpmtPublic {
        type_alg: TpmAlgId::Rsa.into(),
        name_alg: TpmAlgId::Sha256.into(),
        object_attributes: object_attributes.into(),
        auth_policy: Tpm2bBytes(Vec::new()),
        detail: TpmtPublicDetail::RsaDetail(RsaDetail {
            symmetric: SymDefObject {
                alg: TpmAlgId::Null.into(),
                key_bits: 0,
                mode: 0,
            },
            scheme: RsaScheme::Null,
            key_bits: 2048,
            exponent: 0,
        }),
        unique: Tpm2bBytes(vec![0u8; 256]),
    })
}

/// Data sealing object template: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth
/// This creates a keyedHashObject suitable for sealing data
pub fn data_sealing_public() -> Tpm2bPublic {
    let object_attributes = TpmaObjectBits::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true);

    Tpm2b::new(TpmtPublic {
        type_alg: TpmAlgId::KeyedHash.into(),
        name_alg: TpmAlgId::Sha256.into(),
        object_attributes: object_attributes.into(),
        auth_policy: Tpm2bBytes(Vec::new()),
        detail: TpmtPublicDetail::RsaDetail(RsaDetail {
            symmetric: SymDefObject {
                alg: TpmAlgId::Null.into(),
                key_bits: 0,
                mode: 0,
            },
            scheme: RsaScheme::Null,
            key_bits: 2048,
            exponent: 0,
        }),
        unique: Tpm2bBytes(Vec::new()),
    })
}

pub mod command_prelude {
    pub use super::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_response_unmarshal() {
        let object_handle: u32 = 0x8100_1001;
        let name = b"test-name";
        let mut params = Vec::new();
        (name.len() as u16).marshal(&mut params);
        params.extend_from_slice(name);
        let param_size = params.len() as u32;

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&object_handle.to_be_bytes());
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = LoadResponse::from_bytes(&response).expect("load resp");
        assert_eq!(parsed.handles.object_handle, object_handle);
        assert_eq!(parsed.parameters.name.0, name);
    }

    #[test]
    fn unseal_response_unmarshal() {
        let data = b"sealed-data";
        let mut params = Vec::new();
        (data.len() as u16).marshal(&mut params);
        params.extend_from_slice(data);
        let param_size = params.len() as u32;

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = UnsealResponse::from_bytes(&response).expect("unseal resp");
        assert_eq!(parsed.parameters.out_data.0, data);
    }

    #[test]
    fn create_primary_response_unmarshal() {
        // Synthesize a minimal CreatePrimaryResponse parameter section after header.
        // Layout: handle, paramSize, outPublic, creationData, creationHash, ticket, name, qualifiedName.
        let handle: u32 = 0x8100_0001;
        let pub_area = rsa_unrestricted_sign_decrypt_public();
        // Build the parameter area (excluding handle + paramSize) first so we can compute paramSize.
        let mut param_tail = Vec::new();
        pub_area.marshal(&mut param_tail); // TPM2B_PUBLIC
                                           // creationData (empty TPM2B -> size=0)
        (0u16).marshal(&mut param_tail);
        // creationHash (empty TPM2B)
        (0u16).marshal(&mut param_tail);
        // ticket: tag(u16)=0x8021 (TPM_ST_CREATION), hierarchy(u32)=0, digest(empty TPM2B_DIGEST)
        0x8021u16.marshal(&mut param_tail);
        0u32.marshal(&mut param_tail);
        (0u16).marshal(&mut param_tail); // digest size 0
                                         // name (empty TPM2B_NAME)
        (0u16).marshal(&mut param_tail);
        // qualifiedName (empty TPM2B_NAME)
        (0u16).marshal(&mut param_tail);

        let param_size = param_tail.len() as u32;
        let mut params = Vec::new();
        handle.marshal(&mut params);
        param_size.marshal(&mut params);
        params.extend_from_slice(&param_tail);

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes()); // SUCCESS
        response.extend_from_slice(&params);

        let parsed = CreatePrimaryResponse::from_bytes(&response).expect("create primary parse");
        assert_eq!(parsed.header.tag, TPM_ST_SESSIONS);
        assert_eq!(parsed.handles.object_handle, handle);

        let key_bits = match parsed.parameters.out_public.inner.detail {
            TpmtPublicDetail::RsaDetail(rsa_detail) => rsa_detail.key_bits,
            TpmtPublicDetail::KeyedHashDetail(_) => panic!("Unexpected KeyedHashDetail type"),
        };
        assert_eq!(key_bits, 2048);
        assert!(parsed.parameters.creation_data.0.is_empty());
        assert!(parsed.parameters.creation_hash.0.is_empty());
        assert!(parsed.parameters.name.0.is_empty());
        assert!(parsed.parameters.qualified_name.0.is_empty());
    }
}

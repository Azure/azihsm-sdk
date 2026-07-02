// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Schema model parsed from user-annotated structs and enums.

use syn::spanned::Spanned;

/// The kind of message this schema represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A request message with a specific opcode.
    Request { opcode: u8 },
    /// A response message (no opcode; carries status + flags).
    Response,
    /// A field group — no encoder/decoder/frame generated, just inner
    /// typestate chain + sub-view + validation + constants.
    Fields,
}

/// A parsed field from the schema struct.
#[derive(Debug, Clone)]
pub struct SchemaField {
    pub name: syn::Ident,
    pub wire_type: WireType,
    pub toc_type_id: u8,
    pub optional: bool,
    /// Alignment in bytes (power of 2). 0 means no alignment.
    pub align: usize,
    /// Fixed length for `[u8; N]` arrays. None for variable-length.
    pub fixed_len: Option<usize>,
    /// Minimum slice length (default 0). Only for Buffer/SealedKey.
    pub min_len: usize,
    /// Maximum slice length (default MAX_DATA_SIZE). Only for Buffer/SealedKey.
    pub max_len: usize,
    /// If this field is a `#[tbor(include)]`, the type name of the group.
    pub include_group: Option<syn::Ident>,
    /// Field opts into the mutable view (`#[tbor(mutable)]`). Only
    /// permitted on non-optional `Buffer` / `SealedKey` fields. When
    /// any field in the schema is `mutable`, the codegen emits a
    /// parallel `decode_mut` entry point and a `ViewMut` accessor
    /// type whose mut-marked fields hand out `&mut DmaBuf`.
    pub mutable: bool,
    /// For a typed-slice `Buffer` field declared as `&[T]` (T != u8),
    /// the element type `T`.  `None` for a plain `&[u8]` buffer.  The
    /// wire encoding is identical (raw bytes); `T` only drives the
    /// generated accessor/encoder typing, which zero-copy-cast the
    /// bytes to/from `&[T]`.  `T` MUST be `Unaligned` (alignment 1) so
    /// the cast is sound at any data-section offset — enforced at compile
    /// time via [`Schema::align_assertions`]. No padding entry is
    /// inserted for typed slices.
    pub elem_type: Option<syn::Type>,

    /// For a single typed-POD reference field declared as `&T` (T a
    /// fixed-size `Unaligned` zerocopy POD, e.g. `&ReportDescriptor`) with
    /// `#[tbor(buffer, len = size_of::<T>())]`, the referent type `T`.
    /// `None` otherwise.  The wire encoding is the raw little-endian
    /// `size_of::<T>()`-byte image; the generated accessor borrows it
    /// zero-copy as `&T` and the encoder takes `&T`.  `T` must be
    /// `Unaligned` (alignment 1) — enforced by [`Schema::align_assertions`].
    pub single_pod: Option<syn::Type>,

    /// For an inline scalar field declared with a non-primitive newtype
    /// (e.g. `#[tbor(U8)] suite_id: SuiteId`), the wrapper type `T`.
    /// `None` for plain `u8`/`u16`/… fields. The wire encoding is the
    /// underlying inline integer; `T` only drives the generated
    /// accessor (returns `T(raw)`) and encoder (writes `v.0`). `T` MUST
    /// be a single-field tuple newtype over the matching primitive
    /// (constructible as `T(int)` with a public `.0`), e.g. an
    /// `#[open_enum]` type or a plain `pub struct T(pub u8)`.
    pub scalar_newtype: Option<syn::Type>,

    /// For an inline scalar field whose Rust type is a `tbor_int`
    /// little-endian wrapper (`U16`/`U32`/`U64`, or the `U8` alias),
    /// the wrapper type `T`. `None` for plain `u8`/`u16`/… primitives
    /// or for `#[tbor(uN)]` tuple newtypes (see `scalar_newtype`). The
    /// wire encoding is the underlying inline integer; `T` drives the
    /// generated accessor (returns `T`) and encoder (takes `T`). For the
    /// multi-byte wrappers the bridge is `T::new(raw)` / `v.get()`; for
    /// the `U8` alias (which *is* `u8`) it is the identity (see
    /// `le_scalar_is_byte`).
    pub le_scalar: Option<syn::Type>,

    /// `true` when `le_scalar` is the `U8` alias (`== u8`): the accessor
    /// bridge is the identity (no `::new()` / `.get()` call) since the
    /// type already is the primitive.
    pub le_scalar_is_byte: bool,
}

impl SchemaField {
    /// Returns `true` if a padding TOC entry must precede this field.
    ///
    /// Padding is emitted only when alignment is requested explicitly via
    /// `#[tbor(align = N)]`. Typed slices `&[T]` do **not** auto-pad:
    /// their element `T` is required to be `Unaligned` (see
    /// [`Schema::align_assertions`]), so the zero-copy cast is sound at
    /// any offset. Keeping an explicit padding entry (rather than folding
    /// the offset into the field entry) lets the decoder validate every
    /// byte of the data section.
    pub fn has_padding(&self) -> bool {
        self.align > 0
    }

    /// Token expression yielding this field's alignment, evaluated at
    /// compile time in generated code.
    ///
    /// Only an explicit `#[tbor(align = N)]` produces an alignment
    /// requirement (emitting the literal `N`). Typed slices `&[T]` no
    /// longer auto-align: their element `T` must be `Unaligned`
    /// (alignment 1, enforced by [`Schema::align_assertions`]), so the
    /// zero-copy cast is sound at any offset without padding. Returns
    /// `None` when the field has no alignment requirement.
    pub fn align_expr(&self) -> Option<proc_macro2::TokenStream> {
        if self.align > 0 {
            let a = self.align;
            Some(quote::quote! { #a })
        } else {
            None
        }
    }
}

/// The wire encoding for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// 8-bit unsigned integer, TOC type 3, inline encoding.
    Uint8,
    /// 16-bit unsigned integer, TOC type 4, inline encoding.
    Uint16,
    /// 32-bit unsigned integer, TOC type 5, offset/length encoding.
    Uint32,
    /// 64-bit unsigned integer, TOC type 6, offset/length encoding.
    Uint64,
    /// Session identifier, TOC type 0, inline 16-bit encoding.
    SessionId,
    /// Key identifier, TOC type 1, inline 16-bit encoding.
    KeyId,
    /// Variable-length byte buffer, TOC type 7, offset/length encoding.
    Buffer,
    /// Sealed key blob, TOC type 2, offset/length encoding.
    SealedKey,
}

impl WireType {
    /// Return the 6-bit TOC entry type identifier for this wire type.
    pub fn toc_type_id(self) -> u8 {
        match self {
            WireType::SessionId => 0,
            WireType::KeyId => 1,
            WireType::SealedKey => 2,
            WireType::Uint8 => 3,
            WireType::Uint16 => 4,
            WireType::Uint32 => 5,
            WireType::Uint64 => 6,
            WireType::Buffer => 7,
        }
    }

    /// Whether this type uses the offset/length encoding (needs data_start).
    pub fn uses_data_section(self) -> bool {
        matches!(
            self,
            WireType::Uint32 | WireType::Uint64 | WireType::Buffer | WireType::SealedKey
        )
    }
}

/// A fully parsed schema for code generation.
#[derive(Debug, Clone)]
pub struct Schema {
    pub name: syn::Ident,
    pub vis: syn::Visibility,
    pub kind: MessageKind,
    pub fields: Vec<SchemaField>,
    pub needs_data_start: bool,
    /// Whether the message borrows variable-length data (reserved for
    /// potential future use in lifetime elision).
    #[allow(dead_code)]
    pub has_lifetime: bool,
}

/// Precomputed TOC layout accounting for padding entries.
#[derive(Debug, Clone)]
pub struct TocLayout {
    /// Effective TOC index for each schema field.
    pub field_toc_indices: Vec<usize>,
    /// Padding positions: (toc_index, schema_field_index) for each aligned field.
    pub padding_positions: Vec<(usize, usize)>,
    /// Total number of TOC entries (fields + padding entries).
    pub total_toc_count: usize,
}

impl TocLayout {
    /// Compute the TOC layout for a list of schema fields.
    /// Fields that require padding (see [`SchemaField::has_padding`]) —
    /// an explicit `#[tbor(align = N)]` — get a padding TOC entry before
    /// them. Typed slices `&[T]` (with `Unaligned` `T`) do not pad.
    ///
    /// For an empty schema (`fields.is_empty()`), the layout reserves
    /// a single synthetic `None` TOC entry. This satisfies the codec's
    /// `toc_count >= 1` requirement so empty-body messages can still be
    /// expressed via the derive. The encoder writes the placeholder in
    /// `new()`, and the decoder validates it in the generated
    /// validation block.
    pub fn compute(fields: &[SchemaField]) -> Self {
        if fields.is_empty() {
            return TocLayout {
                field_toc_indices: Vec::new(),
                padding_positions: Vec::new(),
                total_toc_count: 1,
            };
        }

        let mut field_toc_indices = Vec::with_capacity(fields.len());
        let mut padding_positions = Vec::new();
        let mut toc_index = 0;

        for (i, field) in fields.iter().enumerate() {
            if field.include_group.is_some() {
                // Include fields don't produce local TOC entries.
                // Their TOC offset is the current index (groups insert here).
                field_toc_indices.push(toc_index);
                // Don't increment toc_index — group's TOC_COUNT is added dynamically.
                continue;
            }
            if field.has_padding() {
                padding_positions.push((toc_index, i));
                toc_index += 1;
            }
            field_toc_indices.push(toc_index);
            toc_index += 1;
        }

        TocLayout {
            field_toc_indices,
            padding_positions,
            total_toc_count: toc_index,
        }
    }
}

impl Schema {
    /// Compute the worst-case data section size (all optional fields present,
    /// maximum-length slices, worst-case padding).
    pub fn worst_case_data_size(&self) -> usize {
        let mut size = 0usize;
        for f in &self.fields {
            // Worst-case padding before an explicitly aligned field: an
            // `align = N` needs up to `N - 1` pad bytes. Typed slices
            // `&[T]` are `Unaligned` and never pad.
            if f.align > 0 {
                size += f.align - 1;
            }
            // Field data size.
            match f.wire_type {
                WireType::Uint32 => size += 4,
                WireType::Uint64 => size += 8,
                WireType::Buffer | WireType::SealedKey => {
                    if let Some(n) = f.fixed_len {
                        size += n;
                    } else {
                        size += f.max_len;
                    }
                }
                _ => {} // inline types: no data section usage
            }
        }
        size
    }

    /// Returns `true` iff any field opts into `#[tbor(mutable)]`.
    /// When `true`, the derive emits a parallel `decode_mut` entry
    /// point and a `ViewMut` accessor type.
    pub fn has_mutable_fields(&self) -> bool {
        self.fields.iter().any(|f| f.mutable)
    }

    /// Emit compile-time assertions that every typed-slice element type
    /// is `Unaligned` (alignment 1). A typed slice `&[T]` is borrowed
    /// zero-copy from the data section at a byte offset that has no
    /// alignment guarantee; requiring `align_of::<T>() == 1` makes the
    /// cast sound at any offset without inserting padding. A `T` with
    /// stronger alignment is rejected at compile time — use the
    /// `little_endian` integer aliases (`tbor_int::U16`/`U32`/`U64`) to
    /// keep wire POD structs `Unaligned`.
    pub fn align_assertions(&self) -> proc_macro2::TokenStream {
        let slice_asserts = self.fields.iter().filter_map(|f| {
            f.elem_type.as_ref().map(|elem| {
                quote::quote! {
                    const _: () = assert!(
                        ::core::mem::align_of::<#elem>() == 1,
                        "TBOR typed-slice element must be Unaligned (alignment 1); use little-endian wire types (tbor_int::U16/U32/U64) instead of native integers"
                    );
                }
            })
        });
        let pod_asserts = self.fields.iter().filter_map(|f| {
            f.single_pod.as_ref().map(|ty| {
                quote::quote! {
                    const _: () = assert!(
                        ::core::mem::align_of::<#ty>() == 1,
                        "TBOR single typed-POD field (`&T`) must be Unaligned (alignment 1); use little-endian wire types (tbor_int::U16/U32/U64) for its fields"
                    );
                }
            })
        });
        quote::quote! { #(#slice_asserts)* #(#pod_asserts)* }
    }

    /// Compute MAX_ENCODED_SIZE (header + TOC + worst-case data).
    pub fn max_encoded_size(&self) -> usize {
        let header_len = match self.kind {
            MessageKind::Request { .. } => 4, // REQ_HEADER_LEN
            MessageKind::Response => 8,       // RESP_HEADER_LEN
            MessageKind::Fields => 0,         // no header
        };
        let layout = TocLayout::compute(&self.fields);
        header_len + layout.total_toc_count * 4 + self.worst_case_data_size()
    }
}

/// Parse the `#[tbor(opcode = 0x09)]`, `#[tbor(response)]`, or `#[tbor(fields)]`
/// attribute and all struct fields into a [`Schema`] for code generation.
///
/// # Errors
///
/// Returns a compile-time error if:
/// - The struct has no named fields
/// - A field type cannot be mapped to a wire type
/// - Alignment or length constraints are invalid
/// - The total TOC count exceeds the protocol limit (32)
/// - The worst-case data section exceeds `MAX_DATA_SIZE`
pub fn parse_struct_schema(
    attr: proc_macro2::TokenStream,
    input: &syn::ItemStruct,
) -> syn::Result<Schema> {
    let kind = parse_message_kind(attr)?;

    let mut fields = Vec::new();
    let mut needs_data_start = false;
    let mut has_lifetime = false;

    if let syn::Fields::Named(ref named) = input.fields {
        for field in &named.named {
            let parsed = parse_single_field(field)?;
            if parsed.wire_type.uses_data_section() && parsed.include_group.is_none() {
                needs_data_start = true;
            }
            if matches!(parsed.wire_type, WireType::Buffer | WireType::SealedKey)
                && parsed.fixed_len.is_none()
                && parsed.include_group.is_none()
            {
                has_lifetime = true;
            }
            fields.push(parsed);
        }
    } else if !matches!(input.fields, syn::Fields::Unit) {
        return Err(syn::Error::new(
            input.fields.span(),
            "#[tbor] structs must have named fields or be a unit struct",
        ));
    }

    // Empty schemas (no fields, including unit structs) are permitted for
    // commands whose body is intentionally empty (e.g. bootstrap
    // `GetApiRev`). The codec requires `toc_count >= 1`, so the
    // generated encoder/decoder synthesise a single `None` TOC entry
    // as a placeholder; see [`TocLayout::compute`] and the codegen
    // empty-schema branches in `codegen_enc::gen_new_fn` and
    // `codegen_view::gen_validation`.

    // Validate total TOC count doesn't exceed protocol limit.
    let layout = TocLayout::compute(&fields);
    if layout.total_toc_count > 32 {
        return Err(syn::Error::new(
            input.ident.span(),
            format!(
                "too many TOC entries: {} fields + {} padding = {} (max 32)",
                fields.len(),
                layout.padding_positions.len(),
                layout.total_toc_count
            ),
        ));
    }

    let schema = Schema {
        name: input.ident.clone(),
        vis: input.vis.clone(),
        kind,
        fields,
        needs_data_start,
        has_lifetime,
    };

    // Validate min_len <= max_len for each field.
    for f in &schema.fields {
        if f.min_len > f.max_len {
            return Err(syn::Error::new(
                f.name.span(),
                format!("min_len ({}) exceeds max_len ({})", f.min_len, f.max_len),
            ));
        }
        // max_len must not exceed MAX_DATA_SIZE.
        if f.max_len > 8191 {
            return Err(syn::Error::new(
                f.name.span(),
                format!("max_len ({}) exceeds MAX_DATA_SIZE (8191)", f.max_len),
            ));
        }
    }

    // Validate worst-case data section fits in protocol limits (messages only, not field groups).
    if !matches!(schema.kind, MessageKind::Fields) {
        let worst_data = schema.worst_case_data_size();
        if worst_data > 8191 {
            return Err(syn::Error::new(
                input.ident.span(),
                format!(
                    "worst-case data section ({} bytes) exceeds MAX_DATA_SIZE (8191); reduce max_len values",
                    worst_data
                ),
            ));
        }
    }

    Ok(schema)
}

/// Parse a single struct field into a [`SchemaField`].
///
/// Handles include fields, optional wrapping, fixed-size arrays, wire type
/// inference, alignment, and length constraints.
fn parse_single_field(field: &syn::Field) -> syn::Result<SchemaField> {
    let name = field.ident.clone().unwrap();

    // Check if this is an include field.
    if is_include_field(&field.attrs) {
        let (actual_ty, optional) = unwrap_option_type(&field.ty);
        let group_name = extract_type_ident(actual_ty).ok_or_else(|| {
            syn::Error::new(
                field.ident.as_ref().unwrap().span(),
                "#[tbor(include)] field type must be a named type",
            )
        })?;

        return Ok(SchemaField {
            name,
            wire_type: WireType::Uint8, // placeholder, unused for include
            toc_type_id: 0,
            optional,
            align: 0,
            fixed_len: None,
            min_len: 0,
            max_len: 0,
            include_group: Some(group_name),
            mutable: false,
            elem_type: None,
            single_pod: None,
            scalar_newtype: None,
            le_scalar: None,
            le_scalar_is_byte: false,
        });
    }

    // Check if the type is Option<T> — unwrap the inner type if so.
    let (actual_ty, optional) = unwrap_option_type(&field.ty);

    // Check if it's a fixed-size array [u8; N].
    let fixed_len = detect_fixed_array(actual_ty);

    let wire_type = infer_wire_type(actual_ty, &field.attrs)?;

    // Parse alignment attribute.
    let align = parse_align_attr(&field.attrs)?;
    if align > 0 {
        if !wire_type.uses_data_section() {
            return Err(syn::Error::new(
                field.ident.as_ref().unwrap().span(),
                "#[tbor(align = N)] can only be applied to data-section types (uint32, uint64, buffer, sealed_key)",
            ));
        }
        if !align.is_power_of_two() {
            return Err(syn::Error::new(
                field.ident.as_ref().unwrap().span(),
                "#[tbor(align = N)] requires N to be a power of two",
            ));
        }
    }

    // Parse min_len/max_len constraints.
    let (min_len, max_len) = parse_len_constraints(&field.attrs)?;
    if (min_len > 0 || max_len < 8191)
        && !matches!(wire_type, WireType::Buffer | WireType::SealedKey)
        && fixed_len.is_none()
    {
        return Err(syn::Error::new(
            field.ident.as_ref().unwrap().span(),
            "#[tbor(min_len/max_len)] can only be applied to buffer or sealed_key fields",
        ));
    }

    // Require max_len on variable-length slice fields.
    if matches!(wire_type, WireType::Buffer | WireType::SealedKey)
        && fixed_len.is_none()
        && max_len == 8191
    {
        return Err(syn::Error::new(
            field.ident.as_ref().unwrap().span(),
            "variable-length buffer/sealed_key fields require #[tbor(max_len = N)]",
        ));
    }

    // Parse `#[tbor(mutable)]`. Only allowed on non-optional
    // Buffer/SealedKey fields: scalar accessors return-by-value (no
    // mut surface needed) and optional fields would require
    // generating a fallible mut accessor that has no current
    // motivating handler.
    let mutable = parse_mutable_attr(&field.attrs)?;
    if mutable {
        if !matches!(wire_type, WireType::Buffer | WireType::SealedKey) {
            return Err(syn::Error::new(
                field.ident.as_ref().unwrap().span(),
                "#[tbor(mutable)] can only be applied to buffer or sealed_key fields",
            ));
        }
        if optional {
            return Err(syn::Error::new(
                field.ident.as_ref().unwrap().span(),
                "#[tbor(mutable)] cannot be applied to optional fields",
            ));
        }
    }

    // For a typed-slice buffer `&[T]`, capture the element type.
    let elem_type = if matches!(wire_type, WireType::Buffer) && fixed_len.is_none() {
        detect_typed_slice_elem(actual_ty)
    } else {
        None
    };

    // For a single typed-POD reference buffer `&T`, capture the referent
    // type so the accessor borrows it as `&T`.  (`&[u8]` / `&[T]` slice
    // references are handled above as buffers / typed slices.)
    let single_pod = if matches!(wire_type, WireType::Buffer) {
        detect_single_pod_ref(actual_ty)
    } else {
        None
    };

    // For an inline scalar field whose Rust type is a `tbor_int`
    // little-endian wrapper (`U16`/`U32`/`U64`, or `U8` which aliases the
    // native `u8`), capture the wrapper type so the generated accessors
    // bridge via `::new()` / `.get()` (identity for `U8`). This keeps the
    // wire format identical (inline `Uint*`) while the public API speaks
    // `tbor_int` types, mirroring the host value structs.
    let (le_scalar, le_scalar_is_byte) = if matches!(
        wire_type,
        WireType::Uint8 | WireType::Uint16 | WireType::Uint32 | WireType::Uint64
    ) && fixed_len.is_none()
        && (is_le_wrapper_type(actual_ty) || is_le_byte_type(actual_ty))
    {
        (Some(actual_ty.clone()), is_le_byte_type(actual_ty))
    } else {
        (None, false)
    };

    // For an inline scalar field whose Rust type is a non-primitive
    // newtype (e.g. `#[tbor(U8)] suite_id: SuiteId`), capture the
    // wrapper type. Inference alone would have errored on the
    // non-primitive path, so reaching an inline `Uint*` wire here means
    // an explicit `#[tbor(uN)]` attribute selected it; the type is the
    // newtype to construct/destructure around the raw integer.
    let scalar_newtype = if matches!(
        wire_type,
        WireType::Uint8 | WireType::Uint16 | WireType::Uint32 | WireType::Uint64
    ) && fixed_len.is_none()
        && !is_primitive_uint_type(actual_ty)
        && le_scalar.is_none()
    {
        Some(actual_ty.clone())
    } else {
        None
    };

    Ok(SchemaField {
        name,
        wire_type,
        toc_type_id: wire_type.toc_type_id(),
        optional,
        align,
        fixed_len,
        min_len,
        max_len,
        include_group: None,
        mutable,
        elem_type,
        single_pod,
        scalar_newtype,
        le_scalar,
        le_scalar_is_byte,
    })
}

/// Returns `true` iff `ty` is a bare primitive unsigned integer
/// (`u8`/`u16`/`u32`/`u64`) — i.e. an inline scalar carried as a raw
/// value rather than a typed newtype wrapper.
fn is_primitive_uint_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return matches!(seg.ident.to_string().as_str(), "u8" | "u16" | "u32" | "u64");
        }
    }
    false
}

/// Returns `true` iff `ty`'s last path segment is a multi-byte
/// `tbor_int` little-endian wrapper (`U16`/`U32`/`U64`) requiring
/// `::new()` / `.get()` bridging in the generated accessors.
fn is_le_wrapper_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return matches!(seg.ident.to_string().as_str(), "U16" | "U32" | "U64");
        }
    }
    false
}

/// Returns `true` iff `ty`'s last path segment is the `tbor_int` `U8`
/// alias (which *is* the native `u8`): bridged by the identity.
fn is_le_byte_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return seg.ident == "U8";
        }
    }
    false
}

/// Returns `true` iff the field carries `#[tbor(mutable)]`.
fn parse_mutable_attr(attrs: &[syn::Attribute]) -> syn::Result<bool> {
    let mut found = false;
    for attr in attrs {
        if attr.path().is_ident("tbor") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("mutable") {
                    found = true;
                } else if meta.path.is_ident("align")
                    || meta.path.is_ident("min_len")
                    || meta.path.is_ident("max_len")
                    || meta.path.is_ident("len")
                {
                    let _value = meta.value()?;
                    let _lit: syn::LitInt = _value.parse()?;
                }
                Ok(())
            })?;
        }
    }
    Ok(found)
}

/// Parse `opcode = 0x09`, `response`, or `fields` from the attribute token stream.
fn parse_message_kind(attr: proc_macro2::TokenStream) -> syn::Result<MessageKind> {
    let attr_str = attr.to_string();

    if attr_str.trim() == "response" {
        return Ok(MessageKind::Response);
    }

    if attr_str.trim() == "fields" {
        return Ok(MessageKind::Fields);
    }

    // Parse "opcode = <int>"
    if attr_str.contains("opcode") {
        // Parse as: opcode = LIT
        let parsed: syn::MetaNameValue = syn::parse2(attr)?;
        if parsed.path.is_ident("opcode") {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit),
                ..
            }) = &parsed.value
            {
                let opcode: u8 = lit.base10_parse()?;
                return Ok(MessageKind::Request { opcode });
            }
            return Err(syn::Error::new_spanned(
                &parsed.value,
                "opcode must be an integer literal",
            ));
        }
    }

    Err(syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[tbor] requires `opcode = N`, `response`, or `fields`",
    ))
}

/// Infer the wire type from a Rust field type.
///
/// Supports explicit `#[tbor(wire_type)]` override or automatic inference.
fn infer_wire_type(ty: &syn::Type, attrs: &[syn::Attribute]) -> syn::Result<WireType> {
    // Check for explicit #[tbor(...)] attribute on the field.
    for attr in attrs {
        if attr.path().is_ident("tbor") {
            let mut found = None;
            attr.parse_nested_meta(|meta| {
                // Wire-type selectors are the `tbor_int`-style
                // `U8`/`U16`/`U32`/`U64`.
                if meta.path.is_ident("U8") {
                    found = Some(WireType::Uint8);
                } else if meta.path.is_ident("U16") {
                    found = Some(WireType::Uint16);
                } else if meta.path.is_ident("U32") {
                    found = Some(WireType::Uint32);
                } else if meta.path.is_ident("U64") {
                    found = Some(WireType::Uint64);
                } else if meta.path.is_ident("session_id") {
                    found = Some(WireType::SessionId);
                } else if meta.path.is_ident("key_id") {
                    found = Some(WireType::KeyId);
                } else if meta.path.is_ident("buffer") {
                    found = Some(WireType::Buffer);
                } else if meta.path.is_ident("sealed_key") {
                    found = Some(WireType::SealedKey);
                } else if meta.path.is_ident("align") {
                    // Consume the `= N` value; alignment is parsed separately.
                    let _value = meta.value()?;
                    let _lit: syn::LitInt = _value.parse()?;
                } else if meta.path.is_ident("min_len")
                    || meta.path.is_ident("max_len")
                    || meta.path.is_ident("len")
                {
                    let _value = meta.value()?;
                    let _lit: syn::LitInt = _value.parse()?;
                } else if meta.path.is_ident("mutable") {
                    // Consumed by `parse_mutable_attr`.
                }
                Ok(())
            })?;
            if let Some(wt) = found {
                return Ok(wt);
            }
        }
    }

    // Auto-infer from Rust type.
    infer_wire_type_from_rust_type(ty)
}

fn infer_wire_type_from_rust_type(ty: &syn::Type) -> syn::Result<WireType> {
    match ty {
        syn::Type::Path(type_path) => {
            if let Some(seg) = type_path.path.segments.last() {
                let ident = seg.ident.to_string();
                match ident.as_str() {
                    "u8" => return Ok(WireType::Uint8),
                    "u16" => return Ok(WireType::Uint16),
                    "u32" => return Ok(WireType::Uint32),
                    "u64" => return Ok(WireType::Uint64),
                    // `tbor_int` little-endian wrappers. `U8` aliases the
                    // native `u8`; `U16`/`U32`/`U64` are zerocopy
                    // little-endian POD ints. All encode as the matching
                    // inline `Uint*` wire type.
                    "U8" => return Ok(WireType::Uint8),
                    "U16" => return Ok(WireType::Uint16),
                    "U32" => return Ok(WireType::Uint32),
                    "U64" => return Ok(WireType::Uint64),
                    "SessionId" => return Ok(WireType::SessionId),
                    "KeyId" => return Ok(WireType::KeyId),
                    _ => {}
                }
            }
            Err(syn::Error::new(
                ty.span(),
                "cannot infer wire type; use #[tbor(U8)], #[tbor(buffer)], etc.",
            ))
        }
        syn::Type::Reference(type_ref) => {
            // &[u8] → Buffer, &'a [u8] → Buffer; &[T] (T != u8) → typed
            // Buffer (same wire, typed accessor — see SchemaField::elem_type).
            if let syn::Type::Slice(_) = &*type_ref.elem {
                return Ok(WireType::Buffer);
            }
            Err(syn::Error::new(
                ty.span(),
                "only slice references (&[u8] or &[T]) are supported; use #[tbor(buffer)] explicitly",
            ))
        }
        syn::Type::Array(arr) => {
            // [u8; N] → Buffer (with fixed_len detected separately)
            if is_u8_type(&arr.elem) {
                return Ok(WireType::Buffer);
            }
            Err(syn::Error::new(
                ty.span(),
                "only [u8; N] arrays are supported",
            ))
        }
        _ => Err(syn::Error::new(
            ty.span(),
            "cannot infer wire type; use #[tbor(U8)], #[tbor(buffer)], etc.",
        )),
    }
}

fn is_u8_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return seg.ident == "u8";
        }
    }
    false
}

/// If `ty` is a slice reference `&[T]` with `T` *not* `u8`, returns the
/// element type `T`; otherwise `None` (plain `&[u8]` or non-slice).
fn detect_typed_slice_elem(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Reference(type_ref) = ty {
        if let syn::Type::Slice(slice) = &*type_ref.elem {
            if !is_u8_type(&slice.elem) {
                return Some((*slice.elem).clone());
            }
        }
    }
    None
}

/// Detect a single typed-POD reference field `&T` (a reference whose
/// referent is a non-slice path type, e.g. `&ReportDescriptor`).  Returns
/// the referent type `T`.  Plain `&[u8]` / `&[T]` (slice references) are
/// **not** matched (they are buffers / typed slices).
fn detect_single_pod_ref(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Reference(type_ref) = ty {
        if let syn::Type::Path(_) = &*type_ref.elem {
            return Some((*type_ref.elem).clone());
        }
    }
    None
}

/// Check if a field has `#[tbor(include)]`.
fn is_include_field(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("tbor") {
            let mut found = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("include") {
                    found = true;
                }
                // Consume key=value forms we don't care about.
                if meta.path.is_ident("align")
                    || meta.path.is_ident("min_len")
                    || meta.path.is_ident("max_len")
                    || meta.path.is_ident("len")
                {
                    let _value = meta.value()?;
                    let _lit: syn::LitInt = _value.parse()?;
                }
                // `mutable` is a bare keyword; just consume.
                let _ = meta.path.is_ident("mutable");
                Ok(())
            });
            if found {
                return true;
            }
        }
    }
    false
}

/// Extract the last segment ident from a type path (e.g., `CryptoHeader` from `crate::CryptoHeader`).
fn extract_type_ident(ty: &syn::Type) -> Option<syn::Ident> {
    if let syn::Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            return Some(seg.ident.clone());
        }
    }
    None
}

/// Parse `#[tbor(align = N)]` from field attributes. Returns 0 if not present.
fn parse_align_attr(attrs: &[syn::Attribute]) -> syn::Result<usize> {
    for attr in attrs {
        if attr.path().is_ident("tbor") {
            let mut align_val: Option<usize> = None;
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("align") {
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    align_val = Some(lit.base10_parse::<usize>()?);
                } else if meta.path.is_ident("min_len")
                    || meta.path.is_ident("max_len")
                    || meta.path.is_ident("len")
                {
                    let _value = meta.value()?;
                    let _lit: syn::LitInt = _value.parse()?;
                } else if meta.path.is_ident("mutable") {
                    // Bare keyword; consumed by `parse_mutable_attr`.
                }
                Ok(())
            })?;
            if let Some(v) = align_val {
                return Ok(v);
            }
        }
    }
    Ok(0)
}

/// Parse `#[tbor(min_len = M, max_len = N)]` from field attributes.
/// Returns (min_len, max_len) with defaults (0, 8191).
fn parse_len_constraints(attrs: &[syn::Attribute]) -> syn::Result<(usize, usize)> {
    let mut min_len: usize = 0;
    let mut max_len: usize = 8191; // MAX_DATA_SIZE
    for attr in attrs {
        if attr.path().is_ident("tbor") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("min_len") {
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    min_len = lit.base10_parse::<usize>()?;
                } else if meta.path.is_ident("max_len") {
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    max_len = lit.base10_parse::<usize>()?;
                } else if meta.path.is_ident("len") {
                    // `len = N` is shorthand for `min_len = N, max_len = N` —
                    // declares a fixed-length variable buffer/sealed_key
                    // field without separately repeating the bound.
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    let n = lit.base10_parse::<usize>()?;
                    min_len = n;
                    max_len = n;
                } else if meta.path.is_ident("align") {
                    let _value = meta.value()?;
                    let _lit: syn::LitInt = _value.parse()?;
                } else if meta.path.is_ident("mutable") {
                    // Bare keyword; consumed by `parse_mutable_attr`.
                }
                // Wire type idents (uint8, buffer, etc.) have no value — just consume.
                Ok(())
            })?;
        }
    }
    Ok((min_len, max_len))
}

/// Detect `[u8; N]` array type and return the length N.
fn detect_fixed_array(ty: &syn::Type) -> Option<usize> {
    if let syn::Type::Array(arr) = ty {
        if is_u8_type(&arr.elem) {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit),
                ..
            }) = &arr.len
            {
                return lit.base10_parse::<usize>().ok();
            }
        }
    }
    None
}

/// If `ty` is `Option<T>`, return `(T, true)`. Otherwise `(ty, false)`.
fn unwrap_option_type(ty: &syn::Type) -> (&syn::Type, bool) {
    if let syn::Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            if seg.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(ref args) = seg.arguments {
                    if args.args.len() == 1 {
                        if let syn::GenericArgument::Type(ref inner) = args.args[0] {
                            return (inner, true);
                        }
                    }
                }
            }
        }
    }
    (ty, false)
}

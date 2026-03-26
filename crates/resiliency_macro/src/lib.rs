// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Proc macro for `#[retry_with_backoff]` attribute.
//!
//! This attribute macro wraps a function returning `HsmResult<T>` with an
//! exponential-backoff retry loop.  The original function body is moved into
//! a nested inner function that is called repeatedly until either (a) the call
//! succeeds, (b) the error is not matched by the supplied `predicate`, or
//! (c) all retry attempts after the initial call have been exhausted.
//!
//! The initial invocation is always made.  If it fails and the predicate
//! matches, the function is retried up to `max_retries` *additional* times,
//! for a total of `max_retries + 1` attempts.
//!
//! # Attribute parameters
//!
//! | Parameter          | Required | Default                                | Description                                                                                  |
//! |--------------------|----------|----------------------------------------|----------------------------------------------------------------------------------------------|
//! | `predicate`        | **yes**  | —                                      | Path to a `fn(&HsmResult<T>) -> bool` predicate.                                             |
//! | `max_retries`      | no       | `crate::resiliency::MAX_RETRIES`       | Maximum number of *additional* retries after the initial attempt (total = `max_retries + 1`).|
//! | `backoff_base_ms`  | no       | `crate::resiliency::BACKOFF_BASE_MS`   | Base delay (ms) for exponential backoff.                                                     |
//! | `backoff_jitter_ms`| no       | `crate::resiliency::BACKOFF_JITTER_MS` | Max random jitter (ms) added to each delay.                                                  |
//! | `condition`        | no       | —                                      | Optional runtime expression (as string); if it evaluates to `false`, the body runs once.     |
//!
//! # Examples
//!
//! ```ignore
//! // Dedicated macro for open_partition (predicate baked in)
//! #[resiliency_open_part]
//! pub fn open_partition(path: &str) -> HsmResult<HsmPartition> { /* ... */ }
//!
//! // Dedicated macro for init_part (predicate + condition baked in)
//! #[resiliency_init_part]
//! pub(crate) fn init_part(..., resiliency_config: Option<&HsmResiliencyConfig>) -> HsmResult<InitPartResult> { /* ... */ }
//!
//! // Generic macro with explicit predicate
//! #[retry_with_backoff(predicate = is_io_abort_error)]
//! pub fn some_other_op() -> HsmResult<()> { /* ... */ }
//! ```

use darling::FromMeta;
use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::ItemFn;

/// Parsed attribute arguments for `#[retry_with_backoff(...)]`.
#[derive(Debug, FromMeta)]
struct RetryArgs {
    /// Path to a predicate function `fn(&HsmResult<T>) -> bool`.
    predicate: syn::Path,

    /// Maximum number of retry attempts.  When omitted the macro emits
    /// `crate::resiliency::MAX_RETRIES` so the default lives in one place.
    #[darling(default)]
    max_retries: Option<u32>,

    /// Base delay in milliseconds for exponential backoff.  When omitted the
    /// macro emits `crate::resiliency::BACKOFF_BASE_MS`.
    #[darling(default)]
    backoff_base_ms: Option<u64>,

    /// Maximum random jitter in milliseconds added to each backoff delay.
    /// When omitted the macro emits `crate::resiliency::BACKOFF_JITTER_MS`.
    #[darling(default)]
    backoff_jitter_ms: Option<u64>,

    /// Optional runtime condition expression.  When present, retry logic is
    /// only applied if this expression evaluates to `true`; otherwise the
    /// body runs exactly once.
    #[darling(default)]
    condition: Option<String>,
}

/// Attribute macro that wraps a function with retry-and-backoff logic.
///
/// See the [crate-level documentation](crate) for usage details.
#[proc_macro_attribute]
pub fn retry_with_backoff(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
    };
    let item = parse_macro_input!(item as ItemFn);

    let args = match RetryArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => return e.write_errors().into(),
    };

    expand_retry(args, item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Parsed attribute arguments for `#[resiliency_open_part(...)]`.
///
/// Same optional overrides as [`RetryArgs`] but with the predicate
/// hard-wired to `crate::resiliency::is_io_abort_error`.
#[derive(Debug, Default, FromMeta)]
struct OpenPartRetryArgs {
    /// Maximum number of retry attempts.
    #[darling(default)]
    max_retries: Option<u32>,

    /// Base delay in milliseconds for exponential backoff.
    #[darling(default)]
    backoff_base_ms: Option<u64>,

    /// Maximum random jitter in milliseconds added to each backoff delay.
    #[darling(default)]
    backoff_jitter_ms: Option<u64>,

    /// Optional runtime condition expression.
    #[darling(default)]
    condition: Option<String>,
}

/// Retry macro for `open_partition`.
///
/// Equivalent to `#[retry_with_backoff(predicate = crate::resiliency::is_io_abort_error)]`
/// but without requiring the caller to specify the predicate.
///
/// # Optional parameters
///
/// All parameters from [`retry_with_backoff`] except `predicate` are accepted
/// as optional overrides (e.g. `max_retries`, `backoff_base_ms`,
/// `backoff_jitter_ms`, `condition`).
///
/// # Example
///
/// ```ignore
/// #[resiliency_open_part]
/// pub fn open_partition(path: &str) -> HsmResult<HsmPartition> { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn resiliency_open_part(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);

    let args = if attr.is_empty() {
        OpenPartRetryArgs::default()
    } else {
        let attr_args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
            Ok(v) => v,
            Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
        };
        match OpenPartRetryArgs::from_list(&attr_args) {
            Ok(v) => v,
            Err(e) => return e.write_errors().into(),
        }
    };

    let full_args = RetryArgs {
        // Predicate for open_partition retries. Update this function if the
        // set of retryable errors changes (e.g., to include new transient
        // error variants beyond IoAborted / IoAbortInProgress).
        predicate: syn::parse_str("crate::resiliency::is_io_abort_error")
            .expect("hardcoded predicate path must parse"),
        max_retries: args.max_retries,
        backoff_base_ms: args.backoff_base_ms,
        backoff_jitter_ms: args.backoff_jitter_ms,
        condition: args.condition,
    };

    expand_retry(full_args, item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Parsed attribute arguments for `#[resiliency_init_part(...)]`.
///
/// Same optional overrides as [`RetryArgs`] but with the predicate
/// hard-wired to `crate::resiliency::is_init_retryable_error` and the
/// condition hard-wired to `resiliency_config.is_some()`.
#[derive(Debug, Default, FromMeta)]
struct InitPartRetryArgs {
    /// Maximum number of retry attempts.
    #[darling(default)]
    max_retries: Option<u32>,

    /// Base delay in milliseconds for exponential backoff.
    #[darling(default)]
    backoff_base_ms: Option<u64>,

    /// Maximum random jitter in milliseconds added to each backoff delay.
    #[darling(default)]
    backoff_jitter_ms: Option<u64>,
}

/// Retry macro for `init_part`.
///
/// Equivalent to:
/// ```ignore
/// #[retry_with_backoff(
///     predicate = crate::resiliency::is_init_retryable_error,
///     condition = "resiliency_config.is_some()",
/// )]
/// ```
///
/// The predicate covers the transient errors specific to partition
/// initialization (credential establishment, POTA endorsement, etc.)
/// and the condition gates retries on the caller having opted in to
/// resiliency.
///
/// The annotated function must have a parameter named
/// `resiliency_config: Option<&HsmResiliencyConfig>` for the baked-in
/// condition to compile.
///
/// # Optional parameters
///
/// `max_retries`, `backoff_base_ms`, and `backoff_jitter_ms` are
/// accepted as optional overrides.
///
/// # Example
///
/// ```ignore
/// #[resiliency_init_part]
/// pub(crate) fn init_part(
///     dev: &HsmDev,
///     ...,
///     resiliency_config: Option<&HsmResiliencyConfig>,
/// ) -> HsmResult<InitPartResult> { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn resiliency_init_part(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);

    let args = if attr.is_empty() {
        InitPartRetryArgs::default()
    } else {
        let attr_args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
            Ok(v) => v,
            Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
        };
        match InitPartRetryArgs::from_list(&attr_args) {
            Ok(v) => v,
            Err(e) => return e.write_errors().into(),
        }
    };

    let full_args = RetryArgs {
        // Predicate for init_part retries. Covers transient errors from
        // credential establishment and POTA endorsement (IoAborted,
        // IoAbortInProgress, CredentialsNotEstablished, NonceMismatch,
        // PartitionNotProvisioned, EccVerifyFailed).
        predicate: syn::parse_str("crate::resiliency::is_init_retryable_error")
            .expect("hardcoded predicate path must parse"),
        max_retries: args.max_retries,
        backoff_base_ms: args.backoff_base_ms,
        backoff_jitter_ms: args.backoff_jitter_ms,
        // Condition baked in: retries only when resiliency is enabled.
        // The annotated function must have a `resiliency_config` parameter.
        condition: Some("resiliency_config.is_some()".to_string()),
    };

    expand_retry(full_args, item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

fn expand_retry(args: RetryArgs, item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    // Validate: must not be async, must return HsmResult<T>, no by-value self.
    validate_retry_fn(&item)?;

    let vis = &item.vis;
    let sig = &item.sig;
    let attrs = &item.attrs;
    let body = &item.block;

    let predicate = &args.predicate;

    // When the caller omits max_retries / backoff_base_ms we emit a path to
    // the constant in crate::retry so the default is defined in one place.
    let max_retries: proc_macro2::TokenStream = match args.max_retries {
        Some(v) => quote! { #v },
        None => quote! { crate::resiliency::MAX_RETRIES },
    };
    let backoff_base_ms: proc_macro2::TokenStream = match args.backoff_base_ms {
        Some(v) => quote! { #v },
        None => quote! { crate::resiliency::BACKOFF_BASE_MS },
    };
    let backoff_jitter_ms: proc_macro2::TokenStream = match args.backoff_jitter_ms {
        Some(v) => quote! { #v },
        None => quote! { crate::resiliency::BACKOFF_JITTER_MS },
    };

    // Wrap the original body in a closure rather than a nested inner function.
    // This naturally handles methods with `&self`/`&mut self` receivers
    // (closures capture the receiver), whereas a nested `fn` cannot have a
    // receiver parameter.
    let retry_call = quote! {
        crate::resiliency::execute_with_backoff(
            |__prev_error: Option<&crate::HsmError>| #body,
            #predicate,
            #max_retries,
            #backoff_base_ms,
            #backoff_jitter_ms,
        )
    };

    // If a condition is specified, gate the retry on it.  The condition is
    // evaluated before creating the retry closure to avoid borrow conflicts
    // when the function takes `&mut self`.
    let body_expr = if let Some(ref cond_str) = args.condition {
        let cond_expr: syn::Expr = syn::parse_str(cond_str).map_err(|e| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("failed to parse `condition` expression: {e}"),
            )
        })?;
        quote! {
            let __should_retry = #cond_expr;
            if __should_retry {
                #retry_call
            } else {
                let __prev_error: Option<&crate::HsmError> = None;
                #body
            }
        }
    } else {
        // Unconditional retry.
        retry_call
    };

    Ok(quote! {
        #(#attrs)*
        #vis #sig {
            #body_expr
        }
    })
}

// ---------------------------
// Key-operation retry macros
// ---------------------------

/// Parsed attribute arguments for `#[resiliency_key_gen(...)]`.
#[derive(Debug, FromMeta)]
struct RetryKeyGenArgs {
    /// Name of the session parameter (e.g., `"session"`).
    session: String,

    /// Maximum number of retry attempts.
    #[darling(default)]
    max_retries: Option<u32>,

    /// Base delay in milliseconds for exponential backoff.
    #[darling(default)]
    backoff_base_ms: Option<u64>,
}

/// Attribute macro that wraps a key-generation function with
/// restore-partition + session-reopen recovery logic.
///
/// On a retryable error (as determined by `is_key_op_retryable_error`),
/// the macro restores the partition, reopens the session if stale, and
/// retries the operation.  No key unmasking is performed because the
/// key does not yet exist.
///
/// The macro is only active when resiliency is enabled on the partition
/// associated with the named `session` parameter.
///
/// # Attribute parameters
///
/// | Parameter        | Required | Default                         | Description                          |
/// |------------------|----------|---------------------------------|--------------------------------------|
/// | `session`        | **yes**  | —                               | Name of the `&HsmSession` parameter. |
/// | `max_retries`    | no       | `crate::resiliency::MAX_RETRIES`| Max additional retries.              |
/// | `backoff_base_ms`| no       | `crate::resiliency::BACKOFF_BASE_MS`| Base delay (ms).                |
///
/// # Example
///
/// ```ignore
/// #[resiliency_key_gen(session = "session")]
/// fn aes_generate_key(session: &HsmSession, props: HsmKeyProps) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn resiliency_key_gen(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
    };
    let item = parse_macro_input!(item as ItemFn);

    let args = match RetryKeyGenArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => return e.write_errors().into(),
    };

    expand_retry_key_gen(args, item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

fn expand_retry_key_gen(
    args: RetryKeyGenArgs,
    item: ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
    validate_retry_fn(&item)?;

    let vis = &item.vis;
    let attrs = &item.attrs;
    let body = &item.block;
    let fn_name = &item.sig.ident;
    let inner_name = syn::Ident::new(&format!("__res_{fn_name}"), fn_name.span());
    let session_ident = syn::Ident::new(&args.session, proc_macro2::Span::call_site());

    let max_retries =
        optional_or_default(args.max_retries, quote! { crate::resiliency::MAX_RETRIES });
    let backoff_base_ms = optional_or_default(
        args.backoff_base_ms,
        quote! { crate::resiliency::BACKOFF_BASE_MS },
    );

    // Build the inner function with the original params and return type.
    let inner_generics = &item.sig.generics;
    let inner_params = &item.sig.inputs;
    let inner_ret = &item.sig.output;

    // Build call arguments for forwarding to the inner function.
    let skip = [args.session.as_str()];
    let (mut_sig, call_args, retry_call_args) = build_inner_fn_call_args(&item.sig, &skip);

    Ok(quote! {
        fn #inner_name #inner_generics (#inner_params) #inner_ret
            #body

        #(#attrs)*
        #vis #mut_sig {
            let __partition = #session_ident.partition();
            if !__partition.resiliency_enabled() {
                #inner_name(#call_args)
            } else {
                crate::resiliency::execute_key_gen_with_retry(
                    || #inner_name(#retry_call_args),
                    #session_ident,
                    &__partition,
                    #max_retries,
                    #backoff_base_ms,
                )
            }
        }
    })
}

/// Parsed attribute arguments for `#[resiliency_key_op(...)]`.
#[derive(Debug, FromMeta)]
struct RetryKeyOpArgs {
    /// Name of the key parameter (e.g., `"key"`).
    key: String,

    /// Maximum number of retry attempts.
    #[darling(default)]
    max_retries: Option<u32>,

    /// Base delay in milliseconds for exponential backoff.
    #[darling(default)]
    backoff_base_ms: Option<u64>,
}

/// Attribute macro that wraps a key operation with restore-partition,
/// session-reopen, and key-refresh recovery logic.
///
/// On a retryable error the macro:
/// 1. Restores the partition (re-establishes credentials).
/// 2. Reopens the session if its epoch is stale.
/// 3. Unmasks the key to refresh its device handle (via
///    `key.restore_from_masked()`).
/// 4. Retries the operation.
///
/// The named `key` parameter must expose `.session()` and
/// `.restore_from_masked()` methods (all HSM key types do).
///
/// # Attribute parameters
///
/// | Parameter        | Required | Default                         | Description                      |
/// |------------------|----------|---------------------------------|----------------------------------|
/// | `key`            | **yes**  | —                               | Name of the key parameter.       |
/// | `max_retries`    | no       | `crate::resiliency::MAX_RETRIES`| Max additional retries.          |
/// | `backoff_base_ms`| no       | `crate::resiliency::BACKOFF_BASE_MS`| Base delay (ms).            |
///
/// # Example
///
/// ```ignore
/// #[resiliency_key_op(key = "key")]
/// fn aes_cbc_encrypt(key: &HsmAesKey, data: &[u8]) -> HsmResult<Vec<u8>> {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn resiliency_key_op(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
    };
    let item = parse_macro_input!(item as ItemFn);

    let args = match RetryKeyOpArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => return e.write_errors().into(),
    };

    expand_retry_key_op(args, item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

fn expand_retry_key_op(
    args: RetryKeyOpArgs,
    item: ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
    validate_retry_fn(&item)?;

    let vis = &item.vis;
    let attrs = &item.attrs;
    let body = &item.block;
    let fn_name = &item.sig.ident;
    let inner_name = syn::Ident::new(&format!("__res_{fn_name}"), fn_name.span());
    let key_ident = syn::Ident::new(&args.key, proc_macro2::Span::call_site());

    let max_retries =
        optional_or_default(args.max_retries, quote! { crate::resiliency::MAX_RETRIES });
    let backoff_base_ms = optional_or_default(
        args.backoff_base_ms,
        quote! { crate::resiliency::BACKOFF_BASE_MS },
    );

    // Build the inner function with the original params and return type.
    let inner_generics = &item.sig.generics;
    let inner_params = &item.sig.inputs;
    let inner_ret = &item.sig.output;

    // Build call arguments for forwarding to the inner function.
    let skip = [args.key.as_str()];
    let (mut_sig, call_args, retry_call_args) = build_inner_fn_call_args(&item.sig, &skip);

    Ok(quote! {
        fn #inner_name #inner_generics (#inner_params) #inner_ret
            #body

        #(#attrs)*
        #vis #mut_sig {
            let __session = #key_ident.session();
            let __partition = __session.partition();
            if !__partition.resiliency_enabled() {
                #inner_name(#call_args)
            } else {
                crate::resiliency::execute_key_op_with_retry(
                    || #inner_name(#retry_call_args),
                    &__session,
                    &__partition,
                    || #key_ident.restore_from_masked(),
                    || #key_ident.last_restore_epoch(),
                    #max_retries,
                    #backoff_base_ms,
                )
            }
        }
    })
}

// -------------------------------------
// Parameter analysis for retry closures
// -------------------------------------

/// Builds the call-site argument lists for forwarding to a `__res_<name>`
/// inner function.
///
/// Returns:
/// 1. The outer function's signature (with `Option<&mut T>` params made
///    `mut`).
/// 2. `call_args` — token stream for the non-retry (direct) call.
/// 3. `retry_call_args` — token stream for calls inside the retry closure.
///    `Option<&mut T>` params use `.as_deref_mut()` and by-value params use
///    `.clone()` so the closure can be called multiple times.
fn build_inner_fn_call_args(
    sig: &syn::Signature,
    skip_idents: &[&str],
) -> (
    syn::Signature,
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
) {
    let mut new_sig = sig.clone();
    let mut call_args = Vec::<proc_macro2::TokenStream>::new();
    let mut retry_call_args = Vec::<proc_macro2::TokenStream>::new();

    for input in &mut new_sig.inputs {
        let syn::FnArg::Typed(pat_type) = input else {
            continue;
        };

        let ident = match pat_type.pat.as_ref() {
            syn::Pat::Ident(pat_ident) => pat_ident.ident.clone(),
            _ => continue,
        };

        let ty = &*pat_type.ty;

        if is_option_mut_ref(ty) {
            // Make the binding `mut` so `.as_deref_mut()` compiles.
            if let syn::Pat::Ident(ref mut pat_ident) = *pat_type.pat {
                pat_ident.mutability = Some(syn::token::Mut::default());
            }
            call_args.push(quote! { #ident });
            retry_call_args.push(quote! { #ident.as_deref_mut() });
        } else if !is_reference_type(ty) && !skip_idents.iter().any(|s| ident == s) {
            // By-value non-reference parameter — clone for retry.
            call_args.push(quote! { #ident });
            retry_call_args.push(quote! { #ident.clone() });
        } else {
            // Reference or skipped parameter — pass through directly.
            call_args.push(quote! { #ident });
            retry_call_args.push(quote! { #ident });
        }
    }

    let call_tokens = quote! { #(#call_args),* };
    let retry_tokens = quote! { #(#retry_call_args),* };
    (new_sig, call_tokens, retry_tokens)
}

/// Returns `true` when the type looks like `Option<&mut T>` in the AST.
///
/// This is a syntactic check — it matches the common pattern without
/// resolving type aliases.
fn is_option_mut_ref(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            if seg.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(ref args) = seg.arguments {
                    for arg in &args.args {
                        if let syn::GenericArgument::Type(syn::Type::Reference(r)) = arg {
                            return r.mutability.is_some();
                        }
                    }
                }
            }
        }
    }
    false
}

/// Returns `true` when the type is a reference (`&T` or `&mut T`).
fn is_reference_type(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Reference(_))
}

// -------------------------
// Shared validation helpers
// -------------------------

/// Common validation for all retry macros: no async, must return HsmResult<T>,
/// no by-value self.
fn validate_retry_fn(item: &ItemFn) -> syn::Result<()> {
    if item.sig.asyncness.is_some() {
        return Err(syn::Error::new(
            item.sig.fn_token.span(),
            "retry macros do not support async functions",
        ));
    }

    match &item.sig.output {
        syn::ReturnType::Default => {
            return Err(syn::Error::new(
                item.sig.fn_token.span(),
                "retry macros require the function to return HsmResult<T>",
            ));
        }
        syn::ReturnType::Type(_, ty) => {
            let valid = if let syn::Type::Path(type_path) = ty.as_ref() {
                type_path.path.segments.last().is_some_and(|seg| {
                    seg.ident == "HsmResult"
                        && matches!(seg.arguments, syn::PathArguments::AngleBracketed(_))
                })
            } else {
                false
            };
            if !valid {
                return Err(syn::Error::new(
                    ty.span(),
                    "retry macros require the function to return HsmResult<T>",
                ));
            }
        }
    }

    if let Some(syn::FnArg::Receiver(r)) = item.sig.inputs.first() {
        if r.reference.is_none() {
            return Err(syn::Error::new(
                r.self_token.span(),
                "retry macros do not support by-value `self`; use `&self` or `&mut self`.",
            ));
        }
    }

    Ok(())
}

/// Returns the provided literal value as a token stream, or falls back
/// to a default path expression.
fn optional_or_default(
    val: Option<impl quote::ToTokens>,
    default: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    match val {
        Some(v) => quote! { #v },
        None => default,
    }
}

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
//! | Parameter        | Required | Default                         | Description                                          |
//! |------------------|----------|---------------------------------|------------------------------------------------------|
//! | `predicate`      | **yes**  | —                               | Path to a `fn(&HsmResult<T>) -> bool` predicate.     |
//! | `max_retries`    | no       | `crate::resiliency::MAX_RETRIES` | Maximum number of *additional* retries after the      |
//! |                  |          |                                 | initial attempt (total attempts = `max_retries + 1`).|
//! | `backoff_base_ms`| no       | `crate::resiliency::BACKOFF_BASE_MS` | Base delay (ms) for exponential backoff.             |
//! | `condition`      | no       | —                               | Optional runtime expression (as string); if it       |
//! |                  |          |                                 | evaluates to `false`, the body runs once (no retry). |
//!
//! # Examples
//!
//! ```ignore
//! // Unconditional retry (e.g., static methods)
//! #[retry_with_backoff(predicate = is_io_abort_error)]
//! pub fn open_partition(path: &str) -> HsmResult<HsmPartition> { /* ... */ }
//!
//! // Conditional retry (only when resiliency is enabled)
//! #[retry_with_backoff(
//!     predicate = is_io_abort_error,
//!     condition = "self.resiliency_enabled()",
//! )]
//! pub fn open_session(&self, ...) -> HsmResult<HsmSession> { /* ... */ }
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

fn expand_retry(args: RetryArgs, item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    // Validate: must not be async.
    if item.sig.asyncness.is_some() {
        return Err(syn::Error::new(
            item.sig.fn_token.span(),
            "#[retry_with_backoff] does not support async functions",
        ));
    }

    // Validate: return type must be HsmResult<T>.
    match &item.sig.output {
        syn::ReturnType::Default => {
            return Err(syn::Error::new(
                item.sig.fn_token.span(),
                "#[retry_with_backoff] requires the function to return HsmResult<T>",
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
                    "#[retry_with_backoff] requires the function to return HsmResult<T>, \
                     found a different return type",
                ));
            }
        }
    }

    // Validate: reject by-value `self` receivers — retrying would move the
    // receiver, which cannot be called more than once.
    if let Some(syn::FnArg::Receiver(r)) = item.sig.inputs.first() {
        if r.reference.is_none() {
            return Err(syn::Error::new(
                r.self_token.span(),
                "#[retry_with_backoff] does not support by-value `self`; \
                 retrying would move the receiver. Use `&self` or `&mut self` instead.",
            ));
        }
    }

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

    // Wrap the original body in a closure rather than a nested inner function.
    // This naturally handles methods with `&self`/`&mut self` receivers
    // (closures capture the receiver), whereas a nested `fn` cannot have a
    // receiver parameter.
    let retry_call = quote! {
        crate::resiliency::execute_with_backoff(
            || #body,
            #predicate,
            #max_retries,
            #backoff_base_ms,
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
            } else
                #body
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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Procedural macros for API testing infrastructure.
//!
//! This crate provides custom test attribute macros that enhance standard Rust tests
//! with tracing support and specialized test setup for API testing scenarios.

use proc_macro::*;
use quote::quote;
use syn::spanned::*;
use syn::*;

/// Attribute macro for creating API tests with tracing support.
///
/// This macro wraps a test function to automatically initialize tracing
/// and create a tracing span for the test execution. The test function
/// must be synchronous and take no arguments.
///
/// # Constraints
///
/// - The function must not be async
/// - The function must not have any parameters
///
/// # Errors
///
/// Returns a compile error if:
/// - The function is marked as async
/// - The function has any parameters
#[proc_macro_attribute]
pub fn api_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    make_api_test(item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Attribute macro for creating partition-based API tests with tracing support.
///
/// This macro is similar to `api_test` but designed for tests that require
/// a partition parameter. It wraps the test function to automatically initialize
/// tracing, create a tracing span, and provide a partition object via the
/// `with_partition` utility function.
///
/// # Constraints
///
/// - The function must not be async
/// - The function must accept exactly one parameter (the partition)
///
/// # Errors
///
/// Returns a compile error if:
/// - The function is marked as async
#[proc_macro_attribute]
pub fn partition_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    make_partition_test(item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Attribute macro for creating session-based API tests with tracing support.
///
/// This macro is similar to `api_test` but designed for tests that require
/// a session parameter. It wraps the test function to automatically initialize
/// tracing, create a tracing span, and provide a session object via the
/// `with_session` utility function.
///
/// # Constraints
///
/// - The function must not be async
/// - The function must accept exactly one parameter (the session)
///
/// # Errors
///
/// Returns a compile error if:
/// - The function is marked as async
#[proc_macro_attribute]
pub fn session_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    make_session_test(item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Generates the implementation for the `api_test` attribute macro.
///
/// This function transforms the input test function into a test that:
/// 1. Initializes tracing
/// 2. Creates a named tracing span for the test
/// 3. Enters the span and executes the original test function
///
/// # Arguments
///
/// * `item` - The function item to transform into an API test
///
/// # Returns
///
/// Returns a token stream representing the transformed test function,
/// or an error if the function signature is invalid.
fn make_api_test(item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.fn_token.span(),
            "test function must not be async",
        ));
    }

    let name = &item.sig.ident;
    let return_type = &item.sig.output;
    if !item.sig.inputs.is_empty() {
        return Err(Error::new(item.sig.inputs.span(), "expected 0 arguments"));
    };
    let attrs = &item.attrs;

    Ok(quote! {
        #[::core::prelude::v1::test]
        #(#attrs)*
        fn #name() #return_type {
            #item
            crate::utils::api::init();
            let span = tracing::span!(tracing::Level::INFO, stringify!(#name));
            let _span_guard = span.enter();
            #name()
        }
    })
}

/// Generates the implementation for the `partition_test` attribute macro.
///
/// This function transforms the input test function into a test that:
/// 1. Initializes tracing
/// 2. Creates a named tracing span for the test
/// 3. Enters the span
/// 4. Provides a partition via the `with_partition` utility function
/// 5. Executes the original test function with the partition parameter
///
/// # Arguments
///
/// * `item` - The function item to transform into a partition-based API test
///
/// # Returns
///
/// Returns a token stream representing the transformed test function,
/// or an error if the function signature is invalid.
fn make_partition_test(item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.fn_token.span(),
            "test function must not be async",
        ));
    }

    let name = &item.sig.ident;
    let return_type = &item.sig.output;
    let attrs = &item.attrs;

    Ok(quote! {
        #[::core::prelude::v1::test]
        #(#attrs)*
        fn #name() #return_type {
            #item
            crate::utils::api::init();
            let span = tracing::span!(tracing::Level::INFO, stringify!(#name), );
            let _span_guard = span.enter();
            crate::utils::partition::with_partition(|partition, creds| {
                #name(partition, creds)
            });
        }
    })
}

/// Generates the implementation for the `session_api_test` attribute macro.
///
/// This function transforms the input test function into a test that:
/// 1. Initializes tracing
/// 2. Creates a named tracing span for the test
/// 3. Enters the span
/// 4. Provides a session via the `with_session` utility function
/// 5. Executes the original test function with the session parameter
///
/// # Arguments
///
/// * `item` - The function item to transform into a session-based API test
///
/// # Returns
///
/// Returns a token stream representing the transformed test function,
/// or an error if the function signature is invalid.
fn make_session_test(item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.fn_token.span(),
            "test function must not be async",
        ));
    }

    let name = &item.sig.ident;
    let return_type = &item.sig.output;
    let attrs = &item.attrs;

    Ok(quote! {
        #[::core::prelude::v1::test]
        #(#attrs)*
        fn #name() #return_type {
            #item
            crate::utils::api::init();
            let span = tracing::span!(tracing::Level::INFO, stringify!(#name), );
            let _span_guard = span.enter();
            crate::utils::session::with_session(|session| {
                #name(session)
            });
        }
    })
}

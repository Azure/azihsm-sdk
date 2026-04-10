// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Proc macro that offloads synchronous, blocking work to a dedicated thread.
//!
//! # Overview
//!
//! The [`offload`] attribute macro takes an `impl` block of **synchronous**
//! handler functions and generates an async-friendly wrapper struct backed by a
//! dedicated worker thread and an `mpsc` channel. This lets you call blocking
//! code (cryptography, FFI, file I/O, etc.) from async contexts without
//! stalling the async executor.
//!
//! The macro generates:
//!
//! - A `pub struct` with a `new()` constructor that spawns background
//!   `std::thread`(s).
//! - An `async fn` wrapper for each handler that sends the operation to the
//!   worker thread and `.await`s the result.
//! - A `shutdown()` method and a `Drop` implementation that cleanly stop the
//!   worker thread(s).
//!
//! All generated code uses only `std` primitives (`std::sync::mpsc`,
//! `std::thread`, `Arc<Mutex<…>>`). No async runtime (tokio, async-std, etc.)
//! is required.
//!
//! # When to use
//!
//! Use this macro when you have synchronous, possibly blocking operations
//! that need to be called from async code without blocking the async executor.
//!
//! # Macro attributes
//!
//! ```text
//! #[offload(error = <ErrorType>, shutdown_error = <ErrorPath>)]
//! ```
//!
//! | Attribute        | Description |
//! |------------------|-------------|
//! | `error`          | The error type `E` used in every handler's `Result<T, E>` return type. |
//! | `shutdown_error` | A path of type `E` returned when the caller tries to use the worker after it has shut down (i.e., the channel is disconnected). |
//! | `workers`        | *(Optional, default `1`)* Number of worker threads to spawn. |
//!
//! # Handler rules
//!
//! Each function in the `impl` block must:
//!
//! - **Not** take `self` — the macro generates `&self` methods on the struct.
//! - **Not** be `async` — the macro generates async wrappers automatically.
//! - Return `Result<T, E>` where `E` matches the `error` attribute.
//! - Use simple identifier patterns for parameters (no destructuring).
//!
//! # Parameter type handling
//!
//! Because parameters must cross a thread boundary (from the async caller to
//! the `std::thread` worker), borrowed types are automatically converted to
//! owned types for transit and borrowed back in the handler:
//!
//! | Handler signature        | Async method signature       | Stored in enum as |
//! |--------------------------|------------------------------|-------------------|
//! | `data: &[u8]`            | `data: &[u8]`                | `Vec<u8>`         |
//! | `out: &mut [u8]`         | `out: &mut [u8]`             | `Vec<u8>`         |
//! | `mode: &MyEnum`          | `mode: MyEnum`               | `MyEnum`          |
//! | `x: Option<&[u8]>`       | `x: Option<&[u8]>`           | `Option<Vec<u8>>` |
//! | `x: Option<&mut [u8]>`   | `mut x: Option<&mut [u8]>`   | `Option<Vec<u8>>` |
//! | `x: Option<&T>`          | `x: Option<T>`               | `Option<T>`       |
//! | `n: usize`               | `n: usize`                   | `usize`           |
//!
//! Slice references (`&[T]`) keep borrowed signatures in the async API for
//! ergonomics — the macro copies them into a `Vec<T>` internally.
//! Mutable slice references (`&mut [T]`) are copied into a temporary `Vec<T>`
//! for worker execution, then copied back to the caller's slice after `.await`.
//! Optional mutable slice references (`Option<&mut [T]>`) work the same way:
//! when the caller passes `Some`, the data is copied back after `.await`.
//! Non-slice references (`&T`) become by-value in the async API to avoid
//! lifetime issues.
//!
//! # Generated API
//!
//! For a struct named `Foo`, the macro generates:
//!
//! - `Foo::new() -> Self` — spawns the worker thread.
//! - `Foo::shutdown(&self)` — sends a shutdown signal (non-blocking).
//! - One `async fn` per handler with the same name and visibility.
//! - `Drop for Foo` — sends shutdown and joins the worker thread.
//!
//! Doc comments (`///`) on individual handler functions are forwarded to the
//! generated async methods. Doc comments on the `impl` block are forwarded to
//! the generated struct definition.
//!
//! # Example
//!
//! ```ignore
//! use offload::offload;
//!
//! #[offload(error = MyError, shutdown_error = MyError::WorkerShutdown)]
//! impl MathWorker {
//!     /// Add two numbers.
//!     pub fn add(a: usize, b: usize) -> Result<usize, MyError> {
//!         Ok(a + b)
//!     }
//!
//!     pub fn hash(data: &[u8]) -> Result<Vec<u8>, MyError> {
//!         // some blocking computation ...
//!         # Ok(data.to_vec())
//!     }
//! }
//!
//! // Generated usage:
//! // let w = MathWorker::new();
//! // let sum = w.add(3, 4).await?;      // async, runs on the worker thread
//! // let h = w.hash(b"hello").await?;
//! // drop(w);                            // joins the worker thread
//! ```

mod classify;

use classify::classify;
use darling::FromMeta;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::format_ident;
use quote::quote;
use syn::FnArg;
use syn::ImplItem;
use syn::ItemImpl;
use syn::Pat;
use syn::ReturnType;
use syn::Type;
use syn::parse_macro_input;
use syn::spanned::Spanned;

#[derive(Debug, FromMeta)]
struct OffloadArgs {
    /// Error type used in all `Result` return types.
    error: syn::Path,
    /// Path for the error produced when the worker channel disconnects.
    shutdown_error: syn::Path,
    /// Number of worker threads to spawn (default: 1).
    workers: Option<usize>,
}

/// Attribute macro that offloads synchronous handler functions to a dedicated
/// worker thread, generating async wrappers for each.
///
/// See the [crate-level documentation](crate) for usage, parameter rules, and
/// examples.
#[proc_macro_attribute]
pub fn offload(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
    };
    let item = parse_macro_input!(item as ItemImpl);

    let args = match OffloadArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => return e.write_errors().into(),
    };

    expand_offload(args, item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Parsed representation of one handler function.
struct HandlerInfo {
    /// Original function name (e.g., `hash`).
    name: syn::Ident,
    /// PascalCase variant name (e.g., `Hash`).
    variant_name: syn::Ident,
    /// Visibility of the method (e.g., `pub`).
    vis: syn::Visibility,
    /// Doc attributes to forward.
    doc_attrs: Vec<syn::Attribute>,
    /// Non-doc attributes to forward (e.g., `#[cfg(...)]`).
    other_attrs: Vec<syn::Attribute>,
    /// Parameter names.
    param_names: Vec<syn::Ident>,
    /// Original parameter types (as written in the handler).
    param_types: Vec<Type>,
    /// Classified param kinds.
    param_kinds: Vec<classify::ParamKind>,
    /// The success type `T` from `Result<T, E>`.
    ok_type: Type,
    /// The full function body.
    body: syn::Block,
}

fn expand_offload(args: OffloadArgs, item: ItemImpl) -> syn::Result<TokenStream2> {
    // Validate: no generics
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new(
            item.generics.span(),
            "offload does not support generic impl blocks",
        ));
    }

    // Validate: no trait impl
    if item.trait_.is_some() {
        return Err(syn::Error::new(
            item.span(),
            "offload does not support trait implementations",
        ));
    }

    // Validate: workers >= 1
    let num_workers = args.workers.unwrap_or(1);
    if num_workers == 0 {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "offload `workers` must be at least 1",
        ));
    }

    // Extract struct name
    let struct_type = &item.self_ty;
    let struct_name = extract_type_ident(struct_type)?;

    // Collect doc attrs from the impl block (to forward to the struct)
    let struct_doc_attrs: Vec<_> = item
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .collect();

    // Parse all handler functions
    let mut handlers = Vec::new();
    for impl_item in &item.items {
        let ImplItem::Fn(method) = impl_item else {
            return Err(syn::Error::new(
                impl_item.span(),
                "offload impl block may only contain functions",
            ));
        };

        let sig = &method.sig;

        // Validate: no self receiver
        if sig.receiver().is_some() {
            return Err(syn::Error::new(
                sig.span(),
                "offload handler functions must not take self",
            ));
        }

        // Validate: not async
        if sig.asyncness.is_some() {
            return Err(syn::Error::new(
                sig.asyncness.span(),
                "offload handler functions must be synchronous; \
                 the macro generates async wrappers",
            ));
        }

        // Extract return type
        let ok_type = extract_result_ok_type(&sig.output, &args.error)?;

        // Parse parameters
        let mut param_names = Vec::new();
        let mut param_types = Vec::new();
        let mut param_kinds = Vec::new();

        for input in &sig.inputs {
            let FnArg::Typed(pat_type) = input else {
                return Err(syn::Error::new(input.span(), "unexpected receiver"));
            };
            let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                return Err(syn::Error::new(
                    pat_type.pat.span(),
                    "offload handler parameters must be simple identifiers",
                ));
            };
            param_names.push(pat_ident.ident.clone());
            param_types.push(*pat_type.ty.clone());
            param_kinds.push(classify(&pat_type.ty));
        }

        // Split attributes
        let doc_attrs: Vec<_> = method
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("doc"))
            .cloned()
            .collect();
        let other_attrs: Vec<_> = method
            .attrs
            .iter()
            .filter(|a| !a.path().is_ident("doc"))
            .cloned()
            .collect();

        let variant_name = to_pascal_case(&sig.ident);

        handlers.push(HandlerInfo {
            name: sig.ident.clone(),
            variant_name,
            vis: method.vis.clone(),
            doc_attrs,
            other_attrs,
            param_names,
            param_types,
            param_kinds,
            ok_type,
            body: method.block.clone(),
        });
    }

    if handlers.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "offload impl block must contain at least one handler function",
        ));
    }

    // Generate all output items
    let error_type = &args.error;
    let shutdown_error = &args.shutdown_error;
    let enum_name = format_ident!("{}Op", struct_name);
    let worker_fn_name = format_ident!("__wq_{}_worker", to_snake_case(&struct_name));

    let handler_fns = gen_handler_fns(&handlers, error_type);
    let op_enum = gen_op_enum(&enum_name, &handlers, error_type);
    let worker_fn = gen_worker_fn(&worker_fn_name, &enum_name, &handlers, shutdown_error);
    let struct_def = gen_struct_def(&struct_name, &enum_name, &struct_doc_attrs);
    let impl_block = gen_impl_block(
        &struct_name,
        &enum_name,
        &worker_fn_name,
        &handlers,
        error_type,
        shutdown_error,
        num_workers,
    );
    let drop_impl = gen_drop_impl(&struct_name, &enum_name, num_workers);

    Ok(quote! {
        #handler_fns
        #op_enum
        #worker_fn
        #struct_def
        #impl_block
        #drop_impl
    })
}

// ---------------------------------------------------------------------------
// Code generation helpers
// ---------------------------------------------------------------------------

fn gen_handler_fns(handlers: &[HandlerInfo], error_type: &syn::Path) -> TokenStream2 {
    let fns: Vec<_> = handlers
        .iter()
        .map(|h| {
            let fn_name = format_ident!("__wq_{}", h.name);
            let params: Vec<_> = h
                .param_names
                .iter()
                .zip(h.param_types.iter().zip(&h.param_kinds))
                .map(|(name, (ty, kind))| match kind {
                    classify::ParamKind::OptionMutSliceRef { .. } => quote! { mut #name: #ty },
                    _ => quote! { #name: #ty },
                })
                .collect();
            let ok_type = &h.ok_type;
            let body = &h.body;
            let other_attrs = &h.other_attrs;
            quote! {
                #(#other_attrs)*
                fn #fn_name(#(#params),*) -> Result<#ok_type, #error_type> #body
            }
        })
        .collect();
    quote! { #(#fns)* }
}

fn gen_op_enum(
    enum_name: &syn::Ident,
    handlers: &[HandlerInfo],
    error_type: &syn::Path,
) -> TokenStream2 {
    let variants: Vec<_> = handlers
        .iter()
        .map(|h| {
            let variant = &h.variant_name;
            let fields: Vec<_> = h
                .param_names
                .iter()
                .zip(h.param_types.iter().zip(&h.param_kinds))
                .map(|(name, (orig_ty, kind))| {
                    let field_ty = kind.enum_field_type(orig_ty);
                    quote! { #name: #field_ty }
                })
                .collect();
            let ok_type = &h.ok_type;
            let mut_slice_elem_types: Vec<_> = h
                .param_kinds
                .iter()
                .filter_map(|kind| match kind {
                    classify::ParamKind::MutSliceRef { elem } => Some(elem.as_ref().clone()),
                    _ => None,
                })
                .collect();
            let opt_mut_slice_elem_types: Vec<_> = h
                .param_kinds
                .iter()
                .filter_map(|kind| match kind {
                    classify::ParamKind::OptionMutSliceRef { elem } => {
                        Some(elem.as_ref().clone())
                    }
                    _ => None,
                })
                .collect();
            let state_ok_type =
                if mut_slice_elem_types.is_empty() && opt_mut_slice_elem_types.is_empty() {
                    quote! { #ok_type }
                } else {
                    quote! { (#ok_type, #(::std::vec::Vec<#mut_slice_elem_types>,)* #(::std::option::Option<::std::vec::Vec<#opt_mut_slice_elem_types>>,)*) }
                };
            let other_attrs = &h.other_attrs;
            quote! {
                #(#other_attrs)*
                #variant {
                    #(#fields,)*
                    __state: ::std::sync::Arc<
                        ::std::sync::Mutex<(
                            ::std::option::Option<Result<#state_ok_type, #error_type>>,
                            ::std::option::Option<::std::task::Waker>,
                        )>
                    >,
                }
            }
        })
        .collect();

    quote! {
        enum #enum_name {
            #(#variants,)*
            __Shutdown,
        }
    }
}

fn gen_worker_fn(
    worker_fn_name: &syn::Ident,
    enum_name: &syn::Ident,
    handlers: &[HandlerInfo],
    shutdown_error: &syn::Path,
) -> TokenStream2 {
    let arms: Vec<_> = handlers
        .iter()
        .map(|h| {
            let variant = &h.variant_name;
            let handler_fn = format_ident!("__wq_{}", h.name);
            let pattern_fields: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .map(|(name, kind)| match kind {
                    classify::ParamKind::MutSliceRef { .. }
                    | classify::ParamKind::OptionMutSliceRef { .. } => quote! { mut #name },
                    _ => quote! { #name },
                })
                .collect();
            let unpack_exprs: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .map(|(name, kind)| kind.unpack_expr(name))
                .collect();
            let mut_slice_param_names: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .filter_map(|(name, kind)| match kind {
                    classify::ParamKind::MutSliceRef { .. } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            let opt_mut_slice_param_names: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .filter_map(|(name, kind)| match kind {
                    classify::ParamKind::OptionMutSliceRef { .. } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            let has_any_mut_slices =
                !mut_slice_param_names.is_empty() || !opt_mut_slice_param_names.is_empty();
            let store_result = if !has_any_mut_slices {
                quote! { __result }
            } else {
                quote! {
                    __result.map(|__ok| (
                        __ok,
                        #(#mut_slice_param_names,)*
                        #(#opt_mut_slice_param_names,)*
                    ))
                }
            };
            let other_attrs = &h.other_attrs;
            quote! {
                #(#other_attrs)*
                #enum_name::#variant { #(#pattern_fields,)* __state } => {
                    let __catch = ::std::panic::catch_unwind(
                        ::std::panic::AssertUnwindSafe(|| #handler_fn(#(#unpack_exprs),*))
                    );
                    let __stored = match __catch {
                        ::std::result::Result::Ok(__result) => #store_result,
                        ::std::result::Result::Err(_) => ::std::result::Result::Err(#shutdown_error),
                    };
                    #[allow(clippy::unwrap_used)]
                    let __waker = {
                        let mut __guard = __state.lock().unwrap();
                        __guard.0 = ::std::option::Option::Some(__stored);
                        __guard.1.take()
                    };
                    if let ::std::option::Option::Some(__w) = __waker {
                        __w.wake();
                    }
                }
            }
        })
        .collect();

    quote! {
        fn #worker_fn_name(
            __rx: ::std::sync::Arc<::std::sync::Mutex<::std::sync::mpsc::Receiver<#enum_name>>>
        ) {
            loop {
                let __op = {
                    #[allow(clippy::unwrap_used)]
                    let __rx_guard = __rx.lock().unwrap();
                    match __rx_guard.recv() {
                        ::std::result::Result::Ok(__op) => __op,
                        ::std::result::Result::Err(_) => break,
                    }
                };
                match __op {
                    #enum_name::__Shutdown => break,
                    #(#arms)*
                }
            }
        }
    }
}

fn gen_struct_def(
    struct_name: &syn::Ident,
    enum_name: &syn::Ident,
    doc_attrs: &[&syn::Attribute],
) -> TokenStream2 {
    quote! {
        #(#doc_attrs)*
        pub struct #struct_name {
            __tx: ::std::sync::mpsc::Sender<#enum_name>,
            __handles: ::std::vec::Vec<::std::thread::JoinHandle<()>>,
            __shutdown: ::std::sync::atomic::AtomicBool,
        }
    }
}

fn gen_impl_block(
    struct_name: &syn::Ident,
    enum_name: &syn::Ident,
    worker_fn_name: &syn::Ident,
    handlers: &[HandlerInfo],
    error_type: &syn::Path,
    shutdown_error: &syn::Path,
    num_workers: usize,
) -> TokenStream2 {
    let response_future_name = format_ident!("__WqResponseFuture{}", struct_name);

    let async_methods: Vec<_> = handlers
        .iter()
        .map(|h| {
            let name = &h.name;
            let vis = &h.vis;
            let variant = &h.variant_name;
            let doc_attrs = &h.doc_attrs;
            let other_attrs = &h.other_attrs;
            let ok_type = &h.ok_type;

            let async_params: Vec<_> = h
                .param_names
                .iter()
                .zip(h.param_types.iter().zip(&h.param_kinds))
                .map(|(name, (orig_ty, kind))| {
                    let ty = kind.async_param_type(orig_ty);
                    match kind {
                        classify::ParamKind::OptionMutSliceRef { .. } => {
                            quote! { mut #name: #ty }
                        }
                        _ => quote! { #name: #ty },
                    }
                })
                .collect();

            let pack_fields: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .map(|(name, kind)| {
                    let expr = kind.pack_expr(name);
                    quote! { #name: #expr }
                })
                .collect();

            let mut_slice_param_names: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .filter_map(|(name, kind)| match kind {
                    classify::ParamKind::MutSliceRef { .. } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            let opt_mut_slice_param_names: Vec<_> = h
                .param_names
                .iter()
                .zip(&h.param_kinds)
                .filter_map(|(name, kind)| match kind {
                    classify::ParamKind::OptionMutSliceRef { .. } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            let has_any_mut_slices =
                !mut_slice_param_names.is_empty() || !opt_mut_slice_param_names.is_empty();

            let return_expr = if !has_any_mut_slices {
                quote! { #response_future_name { __state }.await }
            } else {
                let returned_vec_names: Vec<_> = mut_slice_param_names
                    .iter()
                    .map(|name| format_ident!("__returned_{}", name))
                    .collect();
                let returned_opt_vec_names: Vec<_> = opt_mut_slice_param_names
                    .iter()
                    .map(|name| format_ident!("__returned_{}", name))
                    .collect();
                // Copy-back for plain &mut [T] params.
                let copy_back_slices: Vec<_> = mut_slice_param_names
                    .iter()
                    .zip(&returned_vec_names)
                    .map(|(param, ret)| quote! { #param.copy_from_slice(&#ret); })
                    .collect();
                // Copy-back for Option<&mut [T]> params — only when both
                // the caller provided Some and the worker returned Some.
                let copy_back_opt_slices: Vec<_> = opt_mut_slice_param_names
                    .iter()
                    .zip(&returned_opt_vec_names)
                    .map(|(param, ret)| {
                        quote! {
                            if let ::std::option::Option::Some(ref __src) = #ret {
                                if let ::std::option::Option::Some(ref mut __dst) = #param {
                                    __dst.copy_from_slice(__src);
                                }
                            }
                        }
                    })
                    .collect();
                quote! {
                    match (#response_future_name { __state }.await) {
                        ::std::result::Result::Ok((__ok, #(#returned_vec_names,)* #(#returned_opt_vec_names,)*)) => {
                            #(#copy_back_slices)*
                            #(#copy_back_opt_slices)*
                            ::std::result::Result::Ok(__ok)
                        }
                        ::std::result::Result::Err(__err) => ::std::result::Result::Err(__err),
                    }
                }
            };

            quote! {
                #(#doc_attrs)*
                #(#other_attrs)*
                #vis async fn #name(&self, #(#async_params),*) -> Result<#ok_type, #error_type> {
                    if self.__shutdown.load(::std::sync::atomic::Ordering::Acquire) {
                        return ::std::result::Result::Err(#shutdown_error);
                    }
                    let __state = ::std::sync::Arc::new(
                        ::std::sync::Mutex::new((
                            ::std::option::Option::None,
                            ::std::option::Option::None,
                        ))
                    );
                    let __op = #enum_name::#variant {
                        #(#pack_fields,)*
                        __state: ::std::sync::Arc::clone(&__state),
                    };
                    self.__tx.send(__op).map_err(|_| #shutdown_error)?;
                    #return_expr
                }
            }
        })
        .collect();

    quote! {
        #[allow(clippy::unwrap_used)]
        struct #response_future_name<__T> {
            __state: ::std::sync::Arc<
                ::std::sync::Mutex<(
                    ::std::option::Option<__T>,
                    ::std::option::Option<::std::task::Waker>,
                )>
            >,
        }

        #[allow(clippy::unwrap_used)]
        impl<__T> ::std::future::Future for #response_future_name<__T> {
            type Output = __T;

            fn poll(
                self: ::std::pin::Pin<&mut Self>,
                __cx: &mut ::std::task::Context<'_>,
            ) -> ::std::task::Poll<Self::Output> {
                let mut __guard = self.__state.lock().unwrap();
                if let ::std::option::Option::Some(__val) = __guard.0.take() {
                    ::std::task::Poll::Ready(__val)
                } else {
                    __guard.1 = ::std::option::Option::Some(__cx.waker().clone());
                    ::std::task::Poll::Pending
                }
            }
        }

        impl #struct_name {
            /// Create a new instance, spawning the background worker thread(s).
            pub fn new() -> Self {
                let (__tx, __rx) = ::std::sync::mpsc::channel();
                let __rx = ::std::sync::Arc::new(::std::sync::Mutex::new(__rx));
                let mut __handles = ::std::vec::Vec::with_capacity(#num_workers);
                for _ in 0..#num_workers {
                    let __rx = ::std::sync::Arc::clone(&__rx);
                    __handles.push(::std::thread::spawn(move || #worker_fn_name(__rx)));
                }
                Self {
                    __tx,
                    __handles,
                    __shutdown: ::std::sync::atomic::AtomicBool::new(false),
                }
            }

            /// Signal the worker thread(s) to shut down after processing any
            /// already-queued operations. This is non-blocking — it enqueues
            /// shutdown messages and returns immediately. Operations submitted
            /// after this call will fail with the `shutdown_error`.
            /// Worker threads are joined when this instance is dropped.
            pub fn shutdown(&self) {
                self.__shutdown.store(true, ::std::sync::atomic::Ordering::Release);
                for _ in 0..#num_workers {
                    let _ = self.__tx.send(#enum_name::__Shutdown);
                }
            }

            #(#async_methods)*
        }
    }
}

fn gen_drop_impl(
    struct_name: &syn::Ident,
    enum_name: &syn::Ident,
    num_workers: usize,
) -> TokenStream2 {
    quote! {
        impl ::std::ops::Drop for #struct_name {
            fn drop(&mut self) {
                self.__shutdown.store(true, ::std::sync::atomic::Ordering::Release);
                for _ in 0..#num_workers {
                    let _ = self.__tx.send(#enum_name::__Shutdown);
                }
                for __handle in self.__handles.drain(..) {
                    let _ = __handle.join();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Extract the type identifier from a `Type` (e.g., `CryptoPal` from `impl CryptoPal`).
fn extract_type_ident(ty: &Type) -> syn::Result<syn::Ident> {
    let Type::Path(type_path) = ty else {
        return Err(syn::Error::new(
            ty.span(),
            "offload requires a simple type name (not a path or generic)",
        ));
    };
    if type_path.path.leading_colon.is_some() || type_path.path.segments.len() != 1 {
        return Err(syn::Error::new(
            ty.span(),
            "offload requires a simple type name (not a path or generic)",
        ));
    }
    let Some(segment) = type_path.path.segments.last() else {
        return Err(syn::Error::new(ty.span(), "empty type path"));
    };
    if !segment.arguments.is_none() {
        return Err(syn::Error::new(
            segment.arguments.span(),
            "offload does not support generic types",
        ));
    }
    Ok(segment.ident.clone())
}

/// Extract the `T` from `-> Result<T, E>`.
fn extract_result_ok_type(output: &ReturnType, _error_type: &syn::Path) -> syn::Result<Type> {
    let ReturnType::Type(_, ty) = output else {
        return Err(syn::Error::new(
            output.span(),
            "offload handlers must return Result<T, E>",
        ));
    };
    let Type::Path(type_path) = ty.as_ref() else {
        return Err(syn::Error::new(
            ty.span(),
            "offload handlers must return Result<T, E>",
        ));
    };
    let Some(segment) = type_path.path.segments.last() else {
        return Err(syn::Error::new(ty.span(), "expected Result type"));
    };
    if segment.ident != "Result" {
        return Err(syn::Error::new(
            segment.ident.span(),
            "offload handlers must return Result<T, E>",
        ));
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return Err(syn::Error::new(
            segment.arguments.span(),
            "expected Result<T, E> with generic arguments",
        ));
    };
    if args.args.len() != 2 {
        return Err(syn::Error::new(
            args.span(),
            "expected Result<T, E> with exactly two type arguments",
        ));
    }
    let syn::GenericArgument::Type(ok_type) = &args.args[0] else {
        return Err(syn::Error::new(args.args[0].span(), "expected a type"));
    };
    Ok(ok_type.clone())
}

/// Convert `snake_case` identifier to `PascalCase`.
fn to_pascal_case(ident: &syn::Ident) -> syn::Ident {
    let s = ident.to_string();
    let pascal: String = s
        .split('_')
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    upper + chars.as_str()
                }
                None => String::new(),
            }
        })
        .collect();
    syn::Ident::new(&pascal, ident.span())
}

/// Convert `PascalCase` identifier to `snake_case`.
fn to_snake_case(ident: &syn::Ident) -> String {
    let s = ident.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            for lower in ch.to_lowercase() {
                result.push(lower);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use syn::ReturnType;

    use super::*;

    // -- to_pascal_case ---------------------------------------------------

    #[test]
    fn pascal_case_double_underscore() {
        let ident = syn::Ident::new("my__op", proc_macro2::Span::call_site());
        let result = to_pascal_case(&ident);
        assert_eq!(result, "MyOp");
    }

    // -- extract_type_ident -----------------------------------------------

    #[test]
    fn type_ident_non_path() {
        let ty: Type = syn::parse_str("(u8, u8)").unwrap();
        assert!(extract_type_ident(&ty).is_err());
    }

    #[test]
    fn type_ident_generic() {
        let ty: Type = syn::parse_str("Foo<u8>").unwrap();
        assert!(extract_type_ident(&ty).is_err());
    }

    #[test]
    fn type_ident_simple_succeeds() {
        let ty: Type = syn::parse_str("MyWorker").unwrap();
        let ident = extract_type_ident(&ty).unwrap();
        assert_eq!(ident, "MyWorker");
    }

    #[test]
    fn type_ident_qualified_path() {
        let ty: Type = syn::parse_str("foo::Bar").unwrap();
        assert!(extract_type_ident(&ty).is_err());
    }

    #[test]
    fn type_ident_leading_colon() {
        let ty: Type = syn::parse_str("::Bar").unwrap();
        assert!(extract_type_ident(&ty).is_err());
    }

    // -- extract_result_ok_type -------------------------------------------

    fn parse_return_type(s: &str) -> ReturnType {
        let func: syn::ItemFn = syn::parse_str(&format!("fn f() {s} {{}}")).unwrap();
        func.sig.output
    }

    #[test]
    fn result_ok_no_return_type() {
        let error_path: syn::Path = syn::parse_str("MyError").unwrap();
        assert!(extract_result_ok_type(&ReturnType::Default, &error_path).is_err());
    }

    #[test]
    fn result_ok_non_path_return() {
        let ret = parse_return_type("-> &u8");
        let error_path: syn::Path = syn::parse_str("MyError").unwrap();
        assert!(extract_result_ok_type(&ret, &error_path).is_err());
    }

    #[test]
    fn result_ok_non_result_return() {
        let ret = parse_return_type("-> Vec<u8>");
        let error_path: syn::Path = syn::parse_str("MyError").unwrap();
        assert!(extract_result_ok_type(&ret, &error_path).is_err());
    }

    #[test]
    fn result_ok_wrong_arg_count() {
        let ret = parse_return_type("-> Result<u8>");
        let error_path: syn::Path = syn::parse_str("MyError").unwrap();
        assert!(extract_result_ok_type(&ret, &error_path).is_err());
    }

    #[test]
    fn result_ok_valid() {
        let ret = parse_return_type("-> Result<u32, MyError>");
        let error_path: syn::Path = syn::parse_str("MyError").unwrap();
        let ok_ty = extract_result_ok_type(&ret, &error_path).unwrap();
        assert_eq!(quote! { #ok_ty }.to_string(), "u32");
    }

    #[test]
    fn result_ok_bare_result() {
        let ret = parse_return_type("-> Result");
        let error_path: syn::Path = syn::parse_str("MyError").unwrap();
        assert!(extract_result_ok_type(&ret, &error_path).is_err());
    }

    // -- expand_offload validation -----------------------------------

    fn test_args(workers: Option<usize>) -> OffloadArgs {
        OffloadArgs {
            error: syn::parse_str("E").unwrap(),
            shutdown_error: syn::parse_str("E::Shutdown").unwrap(),
            workers,
        }
    }

    #[test]
    fn reject_generic_impl() {
        let item: ItemImpl = syn::parse_str("impl<T> Foo { }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    #[test]
    fn reject_trait_impl() {
        let item: ItemImpl = syn::parse_str("impl MyTrait for Foo { }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    #[test]
    fn reject_zero_workers() {
        let item: ItemImpl =
            syn::parse_str("impl Foo { fn op() -> Result<(), E> { Ok(()) } }").unwrap();
        assert!(expand_offload(test_args(Some(0)), item).is_err());
    }

    #[test]
    fn reject_non_fn_item() {
        let item: ItemImpl = syn::parse_str("impl Foo { const X: u32 = 1; }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    #[test]
    fn reject_self_receiver() {
        let item: ItemImpl =
            syn::parse_str("impl Foo { fn op(&self) -> Result<(), E> { Ok(()) } }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    #[test]
    fn reject_async_handler() {
        let item: ItemImpl =
            syn::parse_str("impl Foo { async fn op() -> Result<(), E> { Ok(()) } }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    #[test]
    fn reject_destructured_param() {
        let item: ItemImpl =
            syn::parse_str("impl Foo { fn op((a, b): (u32, u32)) -> Result<(), E> { Ok(()) } }")
                .unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    #[test]
    fn reject_empty_impl() {
        let item: ItemImpl = syn::parse_str("impl Foo { }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }

    // -- extract_type_ident: generic type path ----------------------------

    #[test]
    fn reject_generic_type_in_impl() {
        let item: ItemImpl =
            syn::parse_str("impl Foo<u8> { fn op() -> Result<(), E> { Ok(()) } }").unwrap();
        assert!(expand_offload(test_args(None), item).is_err());
    }
}

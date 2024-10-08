//! Procedural macros for writing optionally asynchronous code for traits and functions.
//! Inspires by [`bdk-macros`](https://github.com/bitcoindevkit/bdk/blob/v0.29.0/macros/src/lib.rs)

#![crate_name = "dlc_macros"]
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, Attribute, Expr, ImplItem, Item, ItemFn, ItemImpl, ItemTrait, TraitItem,
};

// Check if the function attributes contains #[maybe_async].
// For conditional compilation of member functions.
fn is_maybe_async_attr(attr: &Attribute) -> bool {
    // Check if the attribute path is exactly "maybe_async"
    if attr.path().is_ident("maybe_async") {
        return true;
    }

    // Check if the attribute path is of the form "module::maybe_async"
    if let Some(last_segment) = attr.path().segments.last() {
        return last_segment.ident == "maybe_async";
    }
    false
}

// Add async to a standalone function.
fn add_async_to_fn(mut func: ItemFn) -> TokenStream {
    // For standalone functions, we'll always make them potentially async
    let sync_version = func.clone();
    func.sig.asyncness = Some(syn::Token![async](func.sig.span()));

    quote! {
        #[cfg(not(feature = "async"))]
        #sync_version

        #[cfg(feature = "async")]
        #func
    }
    .into()
}

// Adds the `async_trait` macro to the trait and appends async to all of
// the member functions marked `#[maybe_async]`.
fn add_async_to_trait(mut trait_item: ItemTrait) -> TokenStream {
    // Check if the trait itself has the `#[maybe_async]` attribute
    let is_trait_async = trait_item.attrs.iter().any(is_maybe_async_attr);
    trait_item.attrs.retain(|attr| !is_maybe_async_attr(attr)); // Remove the attribute from the trait

    let mut async_trait_item = trait_item.clone();

    for item in &mut async_trait_item.items {
        if let TraitItem::Fn(method) = item {
            if is_trait_async || method.attrs.iter().any(is_maybe_async_attr) {
                method.sig.asyncness = Some(syn::Token![async](method.sig.span()));
                method.attrs.retain(is_maybe_async_attr);
            }
        }
    }

    quote! {
        #[cfg(not(feature = "async"))]
        #trait_item

        #[cfg(feature = "async")]
        #[async_trait::async_trait]
        #async_trait_item
    }
    .into()
}

// Adds async to a member of a struct implementation method.
fn add_async_to_impl(impl_item: ItemImpl) -> TokenStream {
    let mut async_impl_item = impl_item.clone();

    for item in &mut async_impl_item.items {
        if let ImplItem::Fn(method) = item {
            if method.attrs.iter().any(is_maybe_async_attr) {
                method.sig.asyncness = Some(syn::Token![async](method.sig.span()));
                method.attrs.retain(|attr| !is_maybe_async_attr(attr));
            }
        }
    }

    quote! {
        #[cfg(not(feature = "async"))]
        #impl_item

        #[cfg(feature = "async")]
        #[async_trait::async_trait]
        #async_impl_item
    }
    .into()
}

/// Makes a method or every method of a trait `async`, if the `async` feature is enabled.
///
/// Requires the `async-trait` crate as a dependency whenever this attribute is used on a trait
/// definition or trait implementation.
#[proc_macro_attribute]
pub fn maybe_async(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    match input {
        Item::Fn(func) => add_async_to_fn(func),
        Item::Trait(trait_item) => add_async_to_trait(trait_item),
        Item::Impl(impl_item) => add_async_to_impl(impl_item),
        Item::Verbatim(verbatim) => {
            // This case handles unexpected verbatim content, like doc comments
            quote! {
                #verbatim
            }
            .into()
        }
        other => {
            let item_type = format!("{:?}", other);
            let error_msg = format!(
                "#[maybe_async] can only be used on functions, traits, or impl blocks, not on: {}",
                item_type
            );
            quote! {
                compile_error!(#error_msg);
            }
            .into()
        }
    }
}

/// Awaits, if the `async` feature is enabled.
#[proc_macro]
pub fn maybe_await(input: TokenStream) -> TokenStream {
    let expr = parse_macro_input!(input as Expr);
    let quoted = quote! {
        {
            #[cfg(not(feature = "async"))]
            {
                #expr
            }

            #[cfg(feature = "async")]
            {
                #expr.await
            }
        }
    };

    quoted.into()
}

/// Awaits, if the `async` feature is enabled, uses `tokio::Runtime::block_on()` otherwise
///
/// Requires the `tokio` crate as a dependecy with `rt-core` or `rt-threaded` to build.
#[proc_macro]
pub fn await_or_block(expr: TokenStream) -> TokenStream {
    let expr = parse_macro_input!(expr as Expr);
    let quoted = quote! {
        {
            #[cfg(not(feature = "async"))]
            {
                tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(#expr)
            }

            #[cfg(feature = "async")]
            {
                #expr.await
            }
        }
    };

    quoted.into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_async_trait() {
        let t = trybuild::TestCases::new();
        t.pass("tests/sync.rs");
    }
}

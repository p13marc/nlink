//! `#[send_futures]`: a compile-time check that public futures are `Send`
//! (#884).
//!
//! On an inherent `impl` block, every `pub async fn` in it gets a sibling
//! checker; on a free `pub async fn`, that one does. A checker takes the
//! function's own parameters, calls it, and requires the future to be
//! `Send`. It takes them as the function does, borrowed where the function
//! borrows, and that is what found #879: the reconcile futures were `Send`
//! for no lifetime of `&self`, even `'static`.
//!
//! Every type and generic parameter of the checker is bounded `Send + Sync`,
//! and so is `Self`. The check is: given `Send` inputs, the future is
//! `Send`. A generic `Connection<P>` method is checked for every `P` whose
//! connection is `Send + Sync`, not for one picked protocol.
//!
//! The checkers are `#[cfg(test)]`, so only test builds compile them; the
//! library build is unchanged. `#[send_futures(skip = "reason")]` on a
//! method, or on a free function in place of `#[send_futures]`, records why
//! a future is not `Send` and leaves it unchecked.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, FnArg, GenericParam, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, LitStr,
    ReturnType, Signature, Type, TypeParamBound, Visibility, WherePredicate, parse_quote,
    spanned::Spanned,
};

pub(crate) fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let skip = parse_args(args)?;
    match syn::parse2::<Item>(item)? {
        Item::Impl(item) => {
            if skip.is_some() {
                return Err(syn::Error::new(
                    item.span(),
                    "#[send_futures(skip = ..)] goes on a method, not on an impl block",
                ));
            }
            expand_impl(item)
        }
        Item::Fn(item) => {
            if skip.is_some() {
                return Ok(quote!(#item));
            }
            expand_fn(item)
        }
        other => Err(syn::Error::new(
            other.span(),
            "#[send_futures] goes on an inherent impl block or a free `pub async fn`",
        )),
    }
}

/// `skip = "reason"`, or nothing.
fn parse_args(args: TokenStream) -> syn::Result<Option<LitStr>> {
    if args.is_empty() {
        return Ok(None);
    }
    let mut skip = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("skip") {
            let reason: LitStr = meta.value()?.parse()?;
            if reason.value().trim().is_empty() {
                return Err(meta.error("a skip needs its reason"));
            }
            skip = Some(reason);
            Ok(())
        } else {
            Err(meta.error("expected `skip = \"reason\"`"))
        }
    });
    syn::parse::Parser::parse2(parser, args)?;
    Ok(skip)
}

fn expand_impl(mut item: ItemImpl) -> syn::Result<TokenStream> {
    if let Some((path, _)) = &item.trait_ {
        return Err(syn::Error::new(
            path.span(),
            "#[send_futures] checks an inherent impl's methods; a trait impl cannot gain them",
        ));
    }
    // A generic impl's checkers hold for every instance with `Send + Sync`
    // parameters whose `Self` is `Send + Sync`. A concrete impl needs no
    // bound: its type's own auto traits decide, and a `Self: Send` bound on
    // a type with a lifetime makes rustc require that lifetime be `'static`.
    let impl_params: Vec<_> = item
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(t) => Some(t.ident.clone()),
            _ => None,
        })
        .collect();
    let mut checkers = Vec::new();
    for member in &mut item.items {
        let ImplItem::Fn(method) = member else {
            continue;
        };
        let skipped = take_skip(&mut method.attrs)?;
        if skipped || !is_public_async(&method.vis, &method.sig) {
            continue;
        }
        checkers.push(checker(
            method_call(method),
            &method.sig,
            &method.attrs,
            &impl_params,
        )?);
    }
    item.items
        .extend(checkers.into_iter().map(ImplItem::Verbatim));
    Ok(quote!(#item))
}

fn expand_fn(item: ItemFn) -> syn::Result<TokenStream> {
    if !is_public_async(&item.vis, &item.sig) {
        return Err(syn::Error::new(
            item.sig.span(),
            "#[send_futures] on a function checks a `pub async fn`",
        ));
    }
    let name = &item.sig.ident;
    let checker = checker(quote!(#name), &item.sig, &item.attrs, &[])?;
    Ok(quote!(#item #checker))
}

/// Remove a `#[send_futures(skip = "..")]` from a method, and say whether
/// there was one.
fn take_skip(attrs: &mut Vec<Attribute>) -> syn::Result<bool> {
    let mut skipped = false;
    let mut error = None;
    attrs.retain(|a| {
        let named = a
            .path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "send_futures");
        if !named {
            return true;
        }
        match a
            .meta
            .require_list()
            .and_then(|l| parse_args(l.tokens.clone()))
        {
            Ok(Some(_)) => skipped = true,
            Ok(None) => {
                error = Some(syn::Error::new(
                    a.span(),
                    "on a method, write #[send_futures(skip = \"reason\")]",
                ));
            }
            Err(e) => error = Some(e),
        }
        false
    });
    match error {
        Some(e) => Err(e),
        None => Ok(skipped),
    }
}

fn is_public_async(vis: &Visibility, sig: &Signature) -> bool {
    matches!(vis, Visibility::Public(_)) && sig.asyncness.is_some()
}

/// `Self::name`, the path a checker calls a method by, whatever its
/// receiver.
fn method_call(method: &ImplItemFn) -> TokenStream {
    let name = &method.sig.ident;
    quote!(Self::#name)
}

/// A checker for `sig`, called through `callee`: the same generics and
/// parameters, each bounded `Send + Sync`, and a body that requires the
/// future to be `Send`. `impl_params` are the type parameters of the impl
/// it is in, bounded the same way.
fn checker(
    callee: TokenStream,
    sig: &Signature,
    attrs: &[Attribute],
    impl_params: &[syn::Ident],
) -> syn::Result<TokenStream> {
    let name = format_ident!("__send_futures_{}", sig.ident);
    let cfgs = attrs.iter().filter(|a| a.path().is_ident("cfg"));

    let mut generics = sig.generics.clone();
    let where_clause = generics.make_where_clause();
    if !impl_params.is_empty() {
        where_clause
            .predicates
            .push(parse_quote!(Self: ::core::marker::Send + ::core::marker::Sync));
    }
    for ident in impl_params {
        let predicate: WherePredicate =
            parse_quote!(#ident: ::core::marker::Send + ::core::marker::Sync);
        where_clause.predicates.push(predicate);
    }
    let type_params: Vec<_> = sig
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(t) => Some(t.ident.clone()),
            _ => None,
        })
        .collect();
    let explicit: Vec<_> = sig
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(t) => Some(t.ident.clone()),
            GenericParam::Const(c) => Some(c.ident.clone()),
            GenericParam::Lifetime(_) => None,
        })
        .collect();
    for ident in &type_params {
        let predicate: WherePredicate =
            parse_quote!(#ident: ::core::marker::Send + ::core::marker::Sync);
        where_clause.predicates.push(predicate);
    }

    let mut params = Vec::new();
    let mut args = Vec::new();
    let mut impl_trait_args = false;
    for (i, input) in sig.inputs.iter().enumerate() {
        match input {
            FnArg::Receiver(receiver) => {
                let mut receiver = receiver.clone();
                receiver.attrs.clear();
                // How `mut self` binds is the method's business; a
                // `&mut self` keeps its `mut`, which is in `kind`.
                receiver.mutability = None;
                params.push(quote!(#receiver));
                args.push(quote!(self));
            }
            FnArg::Typed(typed) => {
                let ident = format_ident!("__arg{i}");
                let mut ty = (*typed.ty).clone();
                impl_trait_args |= has_impl_trait(&ty);
                bound_impl_traits(&mut ty);
                params.push(quote!(#ident: #ty));
                args.push(quote!(#ident));
            }
        }
    }

    // A function with `impl Trait` parameters cannot be given explicit
    // generic arguments; every other one is, so that a type parameter
    // nothing infers still resolves.
    let turbofish = if impl_trait_args || explicit.is_empty() {
        quote!()
    } else {
        quote!(::<#(#explicit),*>)
    };
    let call = quote!(#callee #turbofish (#(#args),*));
    let call = if matches!(sig.safety, syn::Safety::Unsafe(_)) {
        quote!(unsafe { #call })
    } else {
        call
    };
    // The future's output is the declared return type, which settles a
    // type parameter only the return type names (`fn f<P>(..) ->
    // Result<Connection<P>>`), one no turbofish can give when there is an
    // `impl Trait` parameter too.
    let output = match &sig.output {
        ReturnType::Default => quote!(()),
        ReturnType::Type(_, ty) if !has_impl_trait(ty) => quote!(#ty),
        ReturnType::Type(..) => quote!(_),
    };
    let (fn_generics, _, where_clause) = generics.split_for_impl();
    Ok(quote! {
        #(#cfgs)*
        #[cfg(any(test, trybuild))]
        #[doc(hidden)]
        #[allow(dead_code, deprecated, non_snake_case, clippy::all)]
        fn #name #fn_generics (#(#params),*) #where_clause {
            fn is_send<F, O>(_: &F)
            where
                F: ::core::future::Future<Output = O> + ::core::marker::Send,
            {
            }
            let future = #call;
            is_send::<_, #output>(&future);
        }
    })
}

/// Whether `ty` has an `impl Trait` anywhere in it.
fn has_impl_trait(ty: &Type) -> bool {
    fn any_impl(tokens: TokenStream) -> bool {
        tokens.into_iter().any(|t| match t {
            proc_macro2::TokenTree::Ident(i) => i == "impl",
            proc_macro2::TokenTree::Group(g) => any_impl(g.stream()),
            _ => false,
        })
    }
    any_impl(quote!(#ty))
}

/// Add `Send + Sync` to every `impl Trait` in `ty`, however deep:
/// `Option<impl Into<String>>` and `(impl AsFd, u8)` too.
fn bound_impl_traits(ty: &mut Type) {
    match ty {
        Type::ImplTrait(t) => {
            t.bounds
                .push(TypeParamBound::Trait(parse_quote!(::core::marker::Send)));
            t.bounds
                .push(TypeParamBound::Trait(parse_quote!(::core::marker::Sync)));
        }
        Type::Reference(r) => bound_impl_traits(&mut r.elem),
        Type::Paren(p) => bound_impl_traits(&mut p.elem),
        Type::Group(g) => bound_impl_traits(&mut g.elem),
        Type::Slice(s) => bound_impl_traits(&mut s.elem),
        Type::Array(a) => bound_impl_traits(&mut a.elem),
        Type::Ptr(p) => bound_impl_traits(&mut p.elem),
        Type::Tuple(t) => t.elems.iter_mut().for_each(bound_impl_traits),
        Type::Path(p) => {
            for segment in &mut p.path.segments {
                if let syn::PathArguments::AngleBracketed(args) = &mut segment.arguments {
                    for arg in &mut args.args {
                        if let syn::GenericArgument::Type(ty) = arg {
                            bound_impl_traits(ty);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

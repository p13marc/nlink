//! Shared expansion for typed-enum codec derives
//! (`GenlCommand` / `GenlAttribute` / `GenlEnum`).
//!
//! All three derives produce the same shape — `From<EnumType>
//! for ReprType` + `TryFrom<ReprType> for EnumType` + a tiny
//! `EnumTypeUnknownValue` error newtype. They differ only in:
//!
//! - The attribute name (`genl_command` / `genl_attribute` /
//!   `genl_enum`).
//! - Which `repr` widths are accepted.
//!
//! This module factors out the common logic so each derive's
//! entry point is just config + a call into [`expand_codec`].

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::DeriveInput;

use crate::{
    find_meta_list, fits_in_width, parse_repr_attr, require_unit_enum,
    variant_discriminant, ReprWidth,
};

/// Spec for a typed-enum codec derive.
pub(crate) struct CodecDeriveSpec {
    /// Name shown in error messages (e.g., `"GenlCommand"`).
    pub derive_name: &'static str,
    /// Attribute name (e.g., `"genl_command"`).
    pub attr_name: &'static str,
    /// Which repr widths this derive accepts. Other widths get
    /// rejected at compile time with a clear pointer at the
    /// alternative derive.
    pub allowed: &'static [ReprWidth],
    /// Pointer-at-the-right-derive message tacked onto the
    /// "repr not allowed" error when the user picks a width
    /// outside `allowed`. Format: `"use #[derive(X)] for ..."`.
    pub rejected_repr_hint: &'static str,
}

pub(crate) fn expand_codec(
    input: DeriveInput,
    spec: CodecDeriveSpec,
) -> syn::Result<TokenStream2> {
    let enum_ident = &input.ident;
    let span = enum_ident.span();

    let ml = find_meta_list(&input.attrs, spec.attr_name).ok_or_else(|| {
        syn::Error::new(
            span,
            format!(
                "#[derive({})] requires #[{}(repr = \"u8\"|\"u16\"|...)] attribute",
                spec.derive_name, spec.attr_name
            ),
        )
    })?;
    let width = parse_repr_attr(ml, spec.attr_name)?;
    if !spec.allowed.contains(&width) {
        return Err(syn::Error::new_spanned(
            ml,
            format!(
                "#[{}(repr = \"{}\")] is not allowed; {}",
                spec.attr_name,
                width.ident(),
                spec.rejected_repr_hint,
            ),
        ));
    }

    let de = require_unit_enum(&input.data, spec.derive_name, span)?;
    if de.variants.is_empty() {
        return Err(syn::Error::new(
            span,
            format!("#[derive({})] requires at least one variant", spec.derive_name),
        ));
    }
    let mut variants = Vec::with_capacity(de.variants.len());
    for v in &de.variants {
        let value = variant_discriminant(v)?;
        if !fits_in_width(value, width) {
            return Err(syn::Error::new_spanned(
                v,
                format!(
                    "variant discriminant {value} overflows the chosen repr ({})",
                    width.ident()
                ),
            ));
        }
        variants.push((v.ident.clone(), value));
    }

    let repr = width.ident();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let from_arms = variants.iter().map(|(ident, value)| {
        let lit = proc_macro2::Literal::u64_unsuffixed(*value);
        quote! { #enum_ident::#ident => #lit }
    });

    let tryfrom_arms = variants.iter().map(|(ident, value)| {
        let lit = proc_macro2::Literal::u64_unsuffixed(*value);
        quote! { #lit => ::core::result::Result::Ok(#enum_ident::#ident) }
    });

    let error_ident =
        proc_macro2::Ident::new(&format!("{enum_ident}UnknownValue"), enum_ident.span());

    Ok(quote! {
        /// Error returned by the generated
        /// `TryFrom<wire repr>` impl when the wire value
        /// doesn't match any declared variant.
        ///
        /// Carries the original raw value so callers can log or
        /// propagate it through their own error type.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct #error_ident(pub #repr);

        impl ::core::fmt::Display for #error_ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(
                    f,
                    "unknown {} value: {}",
                    ::core::stringify!(#enum_ident),
                    self.0
                )
            }
        }

        impl ::core::error::Error for #error_ident {}

        impl #impl_generics ::core::convert::From<#enum_ident #ty_generics> for #repr #where_clause {
            #[inline]
            fn from(value: #enum_ident #ty_generics) -> Self {
                match value {
                    #(#from_arms,)*
                }
            }
        }

        impl #impl_generics ::core::convert::TryFrom<#repr> for #enum_ident #ty_generics #where_clause {
            type Error = #error_ident;

            #[inline]
            fn try_from(value: #repr) -> ::core::result::Result<Self, Self::Error> {
                match value {
                    #(#tryfrom_arms,)*
                    other => ::core::result::Result::Err(#error_ident(other)),
                }
            }
        }
    })
}

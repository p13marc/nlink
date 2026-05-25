//! `#[genl_family(name = "...", version = N)]` attribute macro.
//!
//! Rewrites a unit-struct declaration into a complete GENL
//! family marker type with all the in-tree trait impls
//! (`ProtocolState` + `AsyncProtocolInit` +
//! `__macro_seal::ProtocolStateSeal` +
//! `__macro_seal::AsyncConstructibleSeal`) the rest of nlink
//! needs to slot the marker into the existing
//! `Connection<P>::new_async()` machinery.
//!
//! See the docstring on `nlink_macros::genl_family` for the
//! user-facing description + example.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse::Parser, punctuated::Punctuated, Expr, ExprLit, Lit, LitInt, LitStr, Meta, Token};

use crate::ItemStruct;

pub(crate) fn expand(
    attr_args: TokenStream2,
    input: ItemStruct,
) -> syn::Result<TokenStream2> {
    let span = input.ident.span();

    // 1. Parse the attribute args: name + version.
    let (family_name, version) = parse_attr_args(attr_args)?;

    // 2. Validate the input struct: must be a unit struct (no
    //    fields). We rewrite it to add the family_id field.
    require_unit_struct(&input)?;

    let struct_ident = &input.ident;
    let vis = &input.vis;
    let attrs = &input.attrs;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            span,
            "#[genl_family] does not support generic parameters",
        ));
    }

    // 3. Generate the rewritten struct + all trait impls.
    Ok(quote! {
        #(#attrs)*
        #vis struct #struct_ident {
            family_id: u16,
            /// Kernel-side multicast group name → ID map, populated
            /// at construction time from `CTRL_ATTR_MCAST_GROUPS`.
            /// Empty if the family registers no multicast groups.
            /// Look up via [`Self::mcast_group`].
            mcast_groups: ::std::collections::HashMap<::std::string::String, u32>,
        }

        impl #struct_ident {
            /// Kernel-assigned Generic Netlink family ID
            /// resolved at `Connection::<Self>::new_async()` time.
            #[inline]
            pub fn family_id(&self) -> u16 {
                self.family_id
            }

            /// Look up a multicast-group ID by name. Returns
            /// `None` if the family doesn't expose that group
            /// (kernel didn't register it, or the binary is
            /// running against an older kernel that doesn't ship
            /// that group). Plan 156 Phase 5.
            #[inline]
            pub fn mcast_group(&self, name: &str) -> ::core::option::Option<u32> {
                self.mcast_groups.get(name).copied()
            }

            /// Family name (the kernel-side string registered via
            /// `CTRL_CMD_NEWFAMILY`). Compile-time constant for
            /// downstream diagnostic + introspection use.
            pub const NAME: &'static str = #family_name;

            /// Family version. Used as the GENL header's
            /// `version` field on outgoing messages.
            pub const VERSION: u8 = #version;
        }

        impl ::core::default::Default for #struct_ident {
            fn default() -> Self {
                // Default-constructed family markers have a
                // family_id of 0 — invalid until `resolve_async`
                // populates it. Documented contract:
                // `Connection::<Self>::new_async().await?` is the
                // only legal construction path for downstream use.
                Self {
                    family_id: 0,
                    mcast_groups: ::std::collections::HashMap::new(),
                }
            }
        }

        impl ::core::fmt::Debug for #struct_ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(::core::stringify!(#struct_ident))
                    .field("name", &Self::NAME)
                    .field("version", &Self::VERSION)
                    .field("family_id", &self.family_id)
                    .field("mcast_groups", &self.mcast_groups)
                    .finish()
            }
        }

        impl ::nlink::netlink::__macro_seal::ProtocolStateSeal
            for #struct_ident #ty_generics #where_clause
        {}

        impl #impl_generics ::nlink::netlink::ProtocolState
            for #struct_ident #ty_generics #where_clause
        {
            const PROTOCOL: ::nlink::netlink::Protocol =
                ::nlink::netlink::Protocol::Generic;
        }

        impl #impl_generics ::nlink::netlink::AsyncProtocolInit
            for #struct_ident #ty_generics #where_clause
        {
            fn resolve_async(
                socket: &::nlink::netlink::NetlinkSocket,
            ) -> impl ::core::future::Future<
                Output = ::core::result::Result<Self, ::nlink::Error>,
            > + ::core::marker::Send {
                async move {
                    let (family_id, mcast_groups) =
                        ::nlink::macros::__rt::resolve_genl_family_with_groups(
                            socket, #family_name,
                        ).await?;
                    ::core::result::Result::Ok(Self { family_id, mcast_groups })
                }
            }
        }

        impl ::nlink::netlink::__macro_seal::AsyncConstructibleSeal
            for #struct_ident #ty_generics #where_clause
        {}

        impl #impl_generics ::nlink::macros::GenlFamily
            for #struct_ident #ty_generics #where_clause
        {
            const VERSION: u8 = #version;
            const NAME: &'static str = #family_name;

            #[inline]
            fn family_id(&self) -> u16 {
                self.family_id
            }

            #[inline]
            fn mcast_group(&self, name: &str) -> ::core::option::Option<u32> {
                self.mcast_groups.get(name).copied()
            }
        }
    })
}

fn parse_attr_args(args: TokenStream2) -> syn::Result<(LitStr, LitInt)> {
    // Parse the comma-separated `key = value` list inside the
    // attribute parentheses: name = "...", version = N.
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let metas = parser.parse2(args.clone()).map_err(|e| {
        syn::Error::new(
            e.span(),
            "#[genl_family(name = \"...\", version = N)] expects two key = value \
             arguments",
        )
    })?;

    let mut family_name: Option<LitStr> = None;
    let mut version: Option<LitInt> = None;

    for meta in &metas {
        let nv = match meta {
            Meta::NameValue(nv) => nv,
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "expected `key = value` (e.g. `name = \"my_family\"`)",
                ))
            }
        };
        let key = nv.path.get_ident().ok_or_else(|| {
            syn::Error::new_spanned(&nv.path, "expected a simple identifier key")
        })?;
        match key.to_string().as_str() {
            "name" => match &nv.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) => family_name = Some(s.clone()),
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "`name` must be a string literal (e.g. `name = \"dpll\"`)",
                    ))
                }
            },
            "version" => match &nv.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Int(n), ..
                }) => version = Some(n.clone()),
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "`version` must be an integer literal (e.g. `version = 1`)",
                    ))
                }
            },
            other => {
                return Err(syn::Error::new_spanned(
                    key,
                    format!(
                        "unknown #[genl_family] key {other:?}; expected `name` or `version`"
                    ),
                ))
            }
        }
    }

    let family_name = family_name.ok_or_else(|| {
        syn::Error::new_spanned(
            &args,
            "#[genl_family(...)] is missing `name = \"...\"`",
        )
    })?;
    let version = version.ok_or_else(|| {
        syn::Error::new_spanned(
            &args,
            "#[genl_family(...)] is missing `version = N`",
        )
    })?;

    Ok((family_name, version))
}

fn require_unit_struct(input: &ItemStruct) -> syn::Result<()> {
    use syn::Fields;
    match &input.fields {
        Fields::Unit => Ok(()),
        Fields::Named(_) | Fields::Unnamed(_) => Err(syn::Error::new_spanned(
            &input.fields,
            "#[genl_family] must be applied to a unit struct (e.g. `pub struct \
             MyFamily;`); the macro rewrites it to add the `family_id` field — \
             pre-declared fields would conflict",
        )),
    }
}

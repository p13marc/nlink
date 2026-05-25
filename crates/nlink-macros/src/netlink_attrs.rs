//! `#[derive(NetlinkAttrs)]` expansion.
//!
//! Generates an `impl ::nlink::macros::NetlinkAttrs for T` whose
//! `write_attrs` / `read_attrs` methods mirror what
//! `#[derive(GenlMessage)]` does for `to_bytes` / `from_bytes` —
//! same field-type-mapping table, same per-field
//! `#[genl_attr(...)]` annotation, no `cmd` const.
//!
//! Used for **nested attribute groups** — payload structs the
//! kernel encodes as the contents of a single `NLA_F_NESTED`
//! attribute. The typical DPLL shape is:
//!
//! ```ignore
//! #[derive(NetlinkAttrs, Debug, Default)]
//! pub struct ParentDeviceBlock {
//!     #[genl_attr(1u16)] pub device_id: u32,
//!     #[genl_attr(2u16)] pub pin_id: u32,
//! }
//!
//! #[derive(GenlMessage, Debug, Default)]
//! #[genl_message(cmd = DpllCmd::PinGet)]
//! pub struct DpllPinReply {
//!     #[genl_attr(DpllPinAttr::Id)] pub id: u32,
//!     #[genl_attr(DpllPinAttr::ParentDevice, nested)]
//!     pub parent_device: Option<ParentDeviceBlock>,
//! }
//! ```
//!
//! The outer `GenlMessage` derive recognizes the `nested` keyword
//! on a `#[genl_attr(...)]` and routes through the nested type's
//! `write_attrs` / `read_attrs` instead of the primitive helpers.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::genl_message::{parse_field, FieldSpec};

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    let span = struct_ident.span();

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => n,
            Fields::Unnamed(_) => {
                return Err(syn::Error::new(
                    span,
                    "#[derive(NetlinkAttrs)] requires a struct with named fields, \
                     not a tuple struct",
                ))
            }
            Fields::Unit => {
                return Err(syn::Error::new(
                    span,
                    "#[derive(NetlinkAttrs)] requires a struct with named fields, \
                     not a unit struct",
                ))
            }
        },
        Data::Enum(_) => {
            return Err(syn::Error::new(
                span,
                "#[derive(NetlinkAttrs)] is only valid on structs; use \
                 #[derive(GenlEnum)] for value enums",
            ))
        }
        Data::Union(_) => {
            return Err(syn::Error::new(
                span,
                "#[derive(NetlinkAttrs)] is only valid on structs, not unions",
            ))
        }
    };

    if fields.named.is_empty() {
        return Err(syn::Error::new(
            span,
            "#[derive(NetlinkAttrs)] requires at least one field; zero-field \
             groups have no on-wire representation",
        ));
    }

    let field_specs: Vec<FieldSpec> = fields
        .named
        .iter()
        .map(parse_field)
        .collect::<syn::Result<_>>()?;

    let emit_calls = field_specs.iter().map(FieldSpec::emit_call);
    let field_defaults = field_specs.iter().map(FieldSpec::field_default);
    let parse_arms = field_specs.iter().map(FieldSpec::parse_arm);
    let field_idents = field_specs.iter().map(|s| &s.ident);

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::nlink::macros::NetlinkAttrs
            for #struct_ident #ty_generics #where_clause
        {
            fn write_attrs(
                &self,
                builder: &mut ::nlink::netlink::MessageBuilder,
            ) -> ::core::result::Result<(), ::nlink::Error> {
                #(#emit_calls)*
                ::core::result::Result::Ok(())
            }

            fn read_attrs(
                __payload: &[u8],
            ) -> ::core::result::Result<Self, ::nlink::Error> {
                #(#field_defaults)*
                for (__ty, __attr_payload)
                    in ::nlink::macros::__rt::attr_iter(__payload)
                {
                    match __ty {
                        #(#parse_arms,)*
                        _ => {} // unknown attr — forward-compat
                    }
                }
                ::core::result::Result::Ok(Self {
                    #(#field_idents,)*
                })
            }
        }
    })
}

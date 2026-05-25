//! `#[derive(GenlAttribute)]` expansion — typed attribute-kind
//! enum.
//!
//! Same shape as [`GenlCommand`][crate::genl_command] but for
//! attribute kinds (the u16 attribute-type field on each
//! `nlattr`). Reprs `u8` and `u16` only.

use proc_macro2::TokenStream as TokenStream2;
use syn::DeriveInput;

use crate::{
    codec::{expand_codec, CodecDeriveSpec},
    ReprWidth,
};

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    expand_codec(
        input,
        CodecDeriveSpec {
            derive_name: "GenlAttribute",
            attr_name: "genl_attribute",
            allowed: &[ReprWidth::U8, ReprWidth::U16],
            rejected_repr_hint: "GENL attribute kinds are u16 by kernel convention \
                (with the top bit reserved for NLA_F_NESTED). Use #[derive(GenlEnum)] \
                for u32-wide value enums encoded INSIDE an attribute payload",
        },
    )
}

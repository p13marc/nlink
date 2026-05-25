//! `#[derive(GenlCommand)]` expansion.
//!
//! Thin wrapper around [`crate::codec::expand_codec`] with the
//! command-specific config: attribute name `genl_command`,
//! reprs `u8` and `u16` only, pointer at `GenlEnum` for users
//! who tried `u32`.

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
            derive_name: "GenlCommand",
            attr_name: "genl_command",
            allowed: &[ReprWidth::U8, ReprWidth::U16],
            rejected_repr_hint: "GENL commands are u8-or-u16 by kernel convention; \
                use #[derive(GenlEnum)] for u32-wide value enums (e.g. policy/mode \
                codes)",
        },
    )
}

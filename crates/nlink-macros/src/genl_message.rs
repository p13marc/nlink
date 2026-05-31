//! `#[derive(GenlMessage)]` expansion.
//!
//! Parses a struct annotated with `#[genl_message(cmd = EXPR)]`
//! and one `#[genl_attr(EXPR)]` per field, then generates
//! `impl GenlMessage` (CMD + to_bytes + from_bytes) by mapping
//! each field's Rust type at expand time to the right
//! `nlink::macros::__rt::*` helper.
//!
//! # Supported field types (0.16 Phase 3b)
//!
//! - `u8` / `u16` / `u32` / `u64`
//! - `String`
//! - `Vec<u8>`
//! - `Option<T>` where `T` is any of the above — omitted on
//!   `None`, present-only-when-set on emit, `Some(parsed)` on
//!   parse if the attribute is present.
//!
//! Unsupported types (`i32`, nested `T: NetlinkAttrs`, `bool`,
//! `IpAddr`, etc.) produce a compile-time error that names the
//! field and points at the unsupported-type message in the
//! derive's docstring. Nested-attribute support lands in a
//! later phase alongside `#[derive(NetlinkAttrs)]`.
//!
//! # from_bytes semantics
//!
//! `from_bytes` walks the attribute payload via
//! [`crate::macros::__rt::attr_iter`][`nlink::macros::__rt::attr_iter`]
//! and assigns each known attribute. **Missing attributes
//! produce default values** (zero for ints, empty for
//! strings/bytes, `None` for `Option<T>`). This is the
//! pragmatic 0.16 stance — "required-attribute enforcement"
//! is a follow-up that needs a per-field `#[genl_attr(required)]`
//! marker. Document the assumption in the derived struct's
//! rustdoc if the kernel never returns the field as missing.
//!
//! Unknown attribute types are silently skipped — forward
//! compatibility with newer kernels that emit attrs older
//! consumers don't understand.

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Data, DeriveInput, Expr, Field, Fields, GenericArgument, Ident, LitStr, PathArguments, Token,
    Type,
};

use crate::{find_meta_list, ReprWidth};

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    let span = struct_ident.span();

    // 1. Parse #[genl_message(cmd = EXPR)] — required.
    let cmd_expr = parse_genl_message_attr(&input)?;

    // 2. Require a named-field struct.
    let fields = require_named_struct(&input.data, span)?;
    if fields.named.is_empty() {
        return Err(syn::Error::new(
            span,
            "#[derive(GenlMessage)] requires at least one field; \
             zero-field messages have no on-wire representation",
        ));
    }

    // 3. Per-field: parse #[genl_attr(EXPR)] + classify the
    //    field's Rust type.
    let field_specs: Vec<FieldSpec> = fields
        .named
        .iter()
        .map(parse_field)
        .collect::<syn::Result<_>>()?;

    // 4. Generate the three impl bodies.
    let emit_calls = field_specs.iter().map(FieldSpec::emit_call);
    let field_defaults = field_specs.iter().map(FieldSpec::field_default);
    let parse_arms = field_specs.iter().map(FieldSpec::parse_arm);
    let field_idents = field_specs.iter().map(|s| &s.ident);

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::nlink::macros::GenlMessage for #struct_ident #ty_generics #where_clause {
            const CMD: u8 = (#cmd_expr) as u8;

            fn to_bytes(
                &self,
                builder: &mut ::nlink::netlink::MessageBuilder,
            ) -> ::core::result::Result<(), ::nlink::Error> {
                #(#emit_calls)*
                ::core::result::Result::Ok(())
            }

            fn from_bytes(
                __payload: &[u8],
            ) -> ::core::result::Result<Self, ::nlink::Error> {
                // Generated locals use double-underscore prefix so
                // they can't collide with user field names — e.g.
                // a field named `payload` would otherwise shadow
                // the function parameter and break the attr_iter
                // call below.
                #(#field_defaults)*
                for (__ty, __attr_payload)
                    in ::nlink::macros::__rt::attr_iter(__payload)
                {
                    match __ty {
                        #(#parse_arms,)*
                        _ => {} // unknown attr — forward-compat with newer kernels
                    }
                }
                ::core::result::Result::Ok(Self {
                    #(#field_idents,)*
                })
            }
        }
    })
}

// --------------------------------------------------------------
// Helpers
// --------------------------------------------------------------

fn parse_genl_message_attr(input: &DeriveInput) -> syn::Result<Expr> {
    let ml = find_meta_list(&input.attrs, "genl_message").ok_or_else(|| {
        syn::Error::new(
            input.ident.span(),
            "#[derive(GenlMessage)] requires #[genl_message(cmd = EXPR)] attribute; \
             EXPR can be an integer literal (`cmd = 2`) or a typed-enum variant cast \
             (`cmd = MyCmd::Get`)",
        )
    })?;
    let mut found_cmd: Option<Expr> = None;
    ml.parse_nested_meta(|meta| {
        if meta.path.is_ident("cmd") {
            let value = meta.value()?;
            let expr: Expr = value.parse()?;
            found_cmd = Some(expr);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown genl_message key {:?}; expected `cmd`",
                meta.path
                    .get_ident()
                    .map(|i| i.to_string())
                    .unwrap_or_default()
            )))
        }
    })?;
    found_cmd.ok_or_else(|| {
        syn::Error::new_spanned(ml, "#[genl_message(...)] must specify `cmd = EXPR`")
    })
}

fn require_named_struct(data: &Data, span: Span) -> syn::Result<&syn::FieldsNamed> {
    match data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => Ok(n),
            Fields::Unnamed(_) => Err(syn::Error::new(
                span,
                "#[derive(GenlMessage)] requires a struct with named fields, not a \
                 tuple struct",
            )),
            Fields::Unit => Err(syn::Error::new(
                span,
                "#[derive(GenlMessage)] requires a struct with named fields, not a \
                 unit struct",
            )),
        },
        Data::Enum(_) => Err(syn::Error::new(
            span,
            "#[derive(GenlMessage)] is only valid on structs; use #[derive(GenlEnum)] \
             for value enums or #[derive(GenlCommand)] for command enums",
        )),
        Data::Union(_) => Err(syn::Error::new(
            span,
            "#[derive(GenlMessage)] is only valid on structs, not unions",
        )),
    }
}

#[derive(Debug, Clone)]
enum WireKind {
    U8,
    U16,
    U32,
    U64,
    I32,
    /// Plan 206 — kernel `s64`. Used by DPLL `phase_offset`
    /// (attoseconds × 1000); routinely exceeds `i32::MAX`.
    I64,
    Str,
    Bytes,
    /// A `#[derive(GenlEnum)]`-typed field. `type_path` is the
    /// fully-qualified field type (e.g. `DpllMode`); `repr` is the
    /// underlying wire width supplied via
    /// `#[genl_attr(MyAttr::Foo, repr = "u32")]`.
    Enum {
        type_path: Box<Type>,
        repr: ReprWidth,
    },
    /// A repeated `GenlEnum`-typed field — `Vec<MyEnum>`. The
    /// kernel emits the same attribute type once per element. On
    /// parse we accumulate into the Vec; on emit we write one
    /// attribute per element.
    RepeatedEnum {
        type_path: Box<Type>,
        repr: ReprWidth,
    },
    /// A bitflags-style newtype — the type exposes
    /// `.bits() -> Repr` and `Type::from_bits_retain(Repr) -> Self`
    /// (the standard `bitflags::Flags` shape from the `bitflags`
    /// crate). Emit writes `.bits()`; parse round-trips through
    /// `from_bits_retain` so unknown kernel-side bits are
    /// preserved verbatim instead of being dropped.
    Bitflags {
        type_path: Box<Type>,
        repr: ReprWidth,
    },
    /// A `#[derive(NetlinkAttrs)]`-typed nested attribute group.
    /// Emit wraps the field's `write_attrs` output in an
    /// `NLA_F_NESTED` attribute. Parse calls `T::read_attrs` on
    /// the nested payload. Must be wrapped in `Option<T>` because
    /// nested-group structs typically don't derive `Default`.
    Nested { type_path: Box<Type> },
    Optional(Box<WireKind>),
}

/// Parsed contents of the field annotation. Three mutually-exclusive
/// field-kind hints: `repr = "..."` (GenlEnum-typed), `bitflags
/// = "..."` (bitflags newtype), or `nested` (NetlinkAttrs-typed
/// nested group). Supplying more than one on a single field is a
/// compile error.
struct GenlAttrArgs {
    attr_expr: Expr,
    /// `Some(width, kind)` if the field carries a width-marker
    /// hint (repr or bitflags). Mutually exclusive with `nested`.
    width: Option<(ReprWidth, WidthKind)>,
    /// True if the field annotation supplied the `nested` keyword.
    /// Mutually exclusive with `width`.
    nested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WidthKind {
    /// `repr = "..."` — GenlEnum-typed field.
    Enum,
    /// `bitflags = "..."` — bitflags-newtype field.
    Bitflags,
}

impl Parse for GenlAttrArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let attr_expr: Expr = input.parse()?;
        let mut width: Option<(ReprWidth, WidthKind)> = None;
        let mut nested = false;
        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let ident: Ident = input.parse()?;
            let key = ident.to_string();
            match key.as_str() {
                "repr" | "bitflags" => {
                    if width.is_some() || nested {
                        return Err(syn::Error::new(
                            ident.span(),
                            "#[genl_attr] accepts at most one of `repr` / \
                             `bitflags` / `nested` (mutually exclusive — pick the \
                             field-kind that matches your type)",
                        ));
                    }
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    let w = ReprWidth::parse(&lit)?;
                    let kind = if key == "repr" {
                        WidthKind::Enum
                    } else {
                        WidthKind::Bitflags
                    };
                    width = Some((w, kind));
                }
                "nested" => {
                    if width.is_some() || nested {
                        return Err(syn::Error::new(
                            ident.span(),
                            "#[genl_attr] accepts at most one of `repr` / \
                             `bitflags` / `nested` (mutually exclusive — pick the \
                             field-kind that matches your type)",
                        ));
                    }
                    nested = true;
                }
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "unknown #[genl_attr] key `{other}`; expected \
                             `repr = \"u8\"|\"u16\"|\"u32\"` (GenlEnum-typed), \
                             `bitflags = \"u8\"|\"u16\"|\"u32\"` (bitflags newtype), \
                             or `nested` (NetlinkAttrs-typed nested group)"
                        ),
                    ))
                }
            }
        }
        Ok(Self { attr_expr, width, nested })
    }
}

impl WireKind {
    /// Token for the inner Rust type — e.g. `u32` or `String`.
    /// `Optional` returns the wrapped form `Option<T>`.
    fn type_token(&self) -> TokenStream2 {
        match self {
            Self::U8 => quote! { u8 },
            Self::U16 => quote! { u16 },
            Self::U32 => quote! { u32 },
            Self::U64 => quote! { u64 },
            Self::I32 => quote! { i32 },
            Self::I64 => quote! { i64 },
            Self::Str => quote! { ::std::string::String },
            Self::Bytes => quote! { ::std::vec::Vec<u8> },
            Self::Enum { type_path, .. } => quote! { #type_path },
            Self::RepeatedEnum { type_path, .. } => {
                quote! { ::std::vec::Vec<#type_path> }
            }
            Self::Bitflags { type_path, .. } => quote! { #type_path },
            Self::Nested { type_path } => quote! { #type_path },
            Self::Optional(inner) => {
                let inner_ty = inner.type_token();
                quote! { ::core::option::Option<#inner_ty> }
            }
        }
    }

    /// The default-value expression used as the from_bytes seed
    /// before walking the attribute iterator.
    fn default_expr(&self) -> TokenStream2 {
        match self {
            Self::U8 | Self::U16 | Self::U32 | Self::U64 => quote! { 0 },
            Self::I32 => quote! { 0i32 },
            Self::I64 => quote! { 0i64 },
            Self::Str => quote! { ::std::string::String::new() },
            Self::Bytes => quote! { ::std::vec::Vec::new() },
            Self::Enum { .. } => {
                // Unreachable: classify_type rejects bare `MyEnum`
                // and requires `Option<MyEnum>`. The Enum default
                // therefore only ever appears wrapped inside
                // Optional, whose arm below returns None.
                quote! { unreachable!("bare-Enum WireKind reached default_expr") }
            }
            Self::RepeatedEnum { .. } => quote! { ::std::vec::Vec::new() },
            Self::Bitflags { type_path, repr } => {
                // Default = empty / all-zero bits via from_bits_retain(0).
                // Sidesteps requiring `Default` on the user's type.
                let repr_ident = repr.ident();
                quote! { #type_path::from_bits_retain(0 as #repr_ident) }
            }
            Self::Nested { .. } => {
                // Unreachable: classify_type_inner requires Nested
                // fields to be wrapped in `Option<T>`.
                quote! { unreachable!("bare-Nested WireKind reached default_expr") }
            }
            Self::Optional(_) => quote! { ::core::option::Option::None },
        }
    }

    /// The `__rt::parse_*_attr` function for this kind.
    fn parse_fn(&self) -> TokenStream2 {
        match self {
            Self::U8 => quote! { ::nlink::macros::__rt::parse_u8_attr },
            Self::U16 => quote! { ::nlink::macros::__rt::parse_u16_attr },
            Self::U32 => quote! { ::nlink::macros::__rt::parse_u32_attr },
            Self::U64 => quote! { ::nlink::macros::__rt::parse_u64_attr },
            Self::I32 => quote! { ::nlink::macros::__rt::parse_i32_attr },
            Self::I64 => quote! { ::nlink::macros::__rt::parse_i64_attr },
            Self::Str => quote! { ::nlink::macros::__rt::parse_str_attr },
            Self::Bytes => quote! { ::nlink::macros::__rt::parse_bytes_attr },
            Self::Enum { repr, .. }
            | Self::RepeatedEnum { repr, .. }
            | Self::Bitflags { repr, .. } => {
                // Use the repr's underlying parse helper. The
                // outer parse_arm handles the TryFrom / from_bits
                // conversion.
                let ident = repr.ident();
                let fn_ident = proc_macro2::Ident::new(
                    &format!("parse_{ident}_attr"),
                    proc_macro2::Span::call_site(),
                );
                quote! { ::nlink::macros::__rt::#fn_ident }
            }
            Self::Nested { .. } => {
                // Nested has no scalar parse helper — the outer
                // parse_arm dispatches directly through
                // `T::read_attrs`. Defensive placeholder.
                quote! { compile_error!("internal: Nested in parse_fn") }
            }
            Self::Optional(inner) => inner.parse_fn(),
        }
    }

    /// Generate the emit call for a non-Option field.
    /// `self_expr` is the borrowed field value
    /// (e.g. `&self.label` for String/Bytes, `self.id` for ints).
    fn emit_call_inner(
        &self,
        builder: &TokenStream2,
        attr_expr: &Expr,
        value_expr: &TokenStream2,
    ) -> TokenStream2 {
        match self {
            Self::U8 => quote! {
                ::nlink::macros::__rt::emit_u8_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::U16 => quote! {
                ::nlink::macros::__rt::emit_u16_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::U32 => quote! {
                ::nlink::macros::__rt::emit_u32_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::U64 => quote! {
                ::nlink::macros::__rt::emit_u64_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::I32 => quote! {
                ::nlink::macros::__rt::emit_i32_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::I64 => quote! {
                ::nlink::macros::__rt::emit_i64_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::Str => quote! {
                ::nlink::macros::__rt::emit_str_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::Bytes => quote! {
                ::nlink::macros::__rt::emit_bytes_attr(#builder, (#attr_expr) as u16, #value_expr);
            },
            Self::Enum { repr, .. } => {
                // Route through the repr's emit helper. The
                // GenlEnum derive ships `From<MyEnum> for Repr`
                // so `Repr::from(value)` converts losslessly.
                let ident = repr.ident();
                let fn_ident = proc_macro2::Ident::new(
                    &format!("emit_{ident}_attr"),
                    proc_macro2::Span::call_site(),
                );
                quote! {
                    ::nlink::macros::__rt::#fn_ident(
                        #builder,
                        (#attr_expr) as u16,
                        <#ident as ::core::convert::From<_>>::from(#value_expr),
                    );
                }
            }
            Self::RepeatedEnum { .. } => {
                // RepeatedEnum is handled at the FieldSpec::emit_call
                // level (loop over Vec elements); emit_call_inner is
                // never called for this variant. Defensive arm in
                // case a future refactor routes it here.
                quote! { compile_error!("internal: RepeatedEnum in emit_call_inner") }
            }
            Self::Bitflags { repr, .. } => {
                // Write field.bits() directly — bitflags' `.bits()`
                // returns the underlying repr type.
                let repr_ident = repr.ident();
                let fn_ident = proc_macro2::Ident::new(
                    &format!("emit_{repr_ident}_attr"),
                    proc_macro2::Span::call_site(),
                );
                quote! {
                    ::nlink::macros::__rt::#fn_ident(
                        #builder,
                        (#attr_expr) as u16,
                        #value_expr.bits(),
                    );
                }
            }
            Self::Nested { .. } => {
                // Open a nested-attribute container, delegate the
                // body to the nested type's write_attrs, then close
                // it. NLA_F_NESTED = 0x8000.
                quote! {
                    {
                        let __nest = #builder.nest_start(((#attr_expr) as u16) | 0x8000u16);
                        ::nlink::macros::NetlinkAttrs::write_attrs(#value_expr, #builder)?;
                        #builder.nest_end(__nest);
                    }
                }
            }
            Self::Optional(_) => {
                // Optional should never call emit_call_inner directly —
                // its outer emit_call handles the if-let-Some wrapping.
                quote! { compile_error!("internal: Optional in emit_call_inner") }
            }
        }
    }

    /// Whether the emit call takes `&` or moves: ints + enums copy,
    /// strings/bytes/nested-groups need `&` (write_attrs takes &self).
    fn needs_reference_on_emit(&self) -> bool {
        matches!(self, Self::Str | Self::Bytes | Self::Nested { .. })
    }
}

pub(crate) struct FieldSpec {
    pub(crate) ident: Ident,
    pub(crate) attr_expr: Expr,
    kind: WireKind,
}

impl FieldSpec {
    pub(crate) fn emit_call(&self) -> TokenStream2 {
        let ident = &self.ident;
        let attr = &self.attr_expr;
        let builder = quote! { builder };
        match &self.kind {
            WireKind::Optional(inner) => {
                let value_expr = if inner.needs_reference_on_emit() {
                    quote! { v }
                } else {
                    quote! { *v }
                };
                let inner_emit = inner.emit_call_inner(&builder, attr, &value_expr);
                quote! {
                    if let ::core::option::Option::Some(v) = self.#ident.as_ref() {
                        #inner_emit
                    }
                }
            }
            WireKind::RepeatedEnum { repr, .. } => {
                // Emit one attribute per Vec element. `*v` copies the
                // (Copy) enum value; From<MyEnum> for Repr converts.
                let ident_repr = repr.ident();
                let fn_ident = proc_macro2::Ident::new(
                    &format!("emit_{ident_repr}_attr"),
                    proc_macro2::Span::call_site(),
                );
                quote! {
                    for __v in self.#ident.iter() {
                        ::nlink::macros::__rt::#fn_ident(
                            #builder,
                            (#attr) as u16,
                            <#ident_repr as ::core::convert::From<_>>::from(*__v),
                        );
                    }
                }
            }
            other => {
                let value_expr = if other.needs_reference_on_emit() {
                    quote! { &self.#ident }
                } else {
                    quote! { self.#ident }
                };
                other.emit_call_inner(&builder, attr, &value_expr)
            }
        }
    }

    pub(crate) fn field_default(&self) -> TokenStream2 {
        let ident = &self.ident;
        let ty = self.kind.type_token();
        let default = self.kind.default_expr();
        quote! { let mut #ident: #ty = #default; }
    }

    pub(crate) fn parse_arm(&self) -> TokenStream2 {
        let ident = &self.ident;
        let attr = &self.attr_expr;
        let parse_fn = self.kind.parse_fn();
        match &self.kind {
            WireKind::Optional(inner) => match inner.as_ref() {
                WireKind::Enum { type_path, .. } => quote! {
                    __ty if __ty == (#attr) as u16 => {
                        let __raw = #parse_fn(__attr_payload)?;
                        let __decoded = <#type_path as ::core::convert::TryFrom<_>>::try_from(__raw)
                            .map_err(|e| ::nlink::Error::InvalidMessage(
                                ::std::format!("{e}")
                            ))?;
                        #ident = ::core::option::Option::Some(__decoded);
                    }
                },
                WireKind::Nested { type_path } => quote! {
                    // The kernel may set NLA_F_NESTED in the attr
                    // type byte; mask it off when matching, then
                    // dispatch to the nested type's read_attrs over
                    // the inner payload.
                    __ty if (__ty & !0x8000u16) == (#attr) as u16 => {
                        let __inner = <#type_path as ::nlink::macros::NetlinkAttrs>::read_attrs(__attr_payload)?;
                        #ident = ::core::option::Option::Some(__inner);
                    }
                },
                _ => quote! {
                    __ty if __ty == (#attr) as u16 => {
                        #ident = ::core::option::Option::Some(#parse_fn(__attr_payload)?);
                    }
                },
            },
            WireKind::Enum { type_path, .. } => quote! {
                __ty if __ty == (#attr) as u16 => {
                    let __raw = #parse_fn(__attr_payload)?;
                    #ident = <#type_path as ::core::convert::TryFrom<_>>::try_from(__raw)
                        .map_err(|e| ::nlink::Error::InvalidMessage(
                            ::std::format!("{e}")
                        ))?;
                }
            },
            WireKind::RepeatedEnum { type_path, .. } => quote! {
                __ty if __ty == (#attr) as u16 => {
                    // Kernel may emit the same attr type repeatedly
                    // for list-valued fields. Push each occurrence.
                    let __raw = #parse_fn(__attr_payload)?;
                    let __decoded = <#type_path as ::core::convert::TryFrom<_>>::try_from(__raw)
                        .map_err(|e| ::nlink::Error::InvalidMessage(
                            ::std::format!("{e}")
                        ))?;
                    #ident.push(__decoded);
                }
            },
            WireKind::Bitflags { type_path, .. } => quote! {
                __ty if __ty == (#attr) as u16 => {
                    let __raw = #parse_fn(__attr_payload)?;
                    // from_bits_retain preserves unknown bits, so a
                    // newer kernel emitting flags this binary doesn't
                    // recognize round-trips correctly instead of
                    // silently dropping bits.
                    #ident = #type_path::from_bits_retain(__raw);
                }
            },
            _ => quote! {
                __ty if __ty == (#attr) as u16 => {
                    #ident = #parse_fn(__attr_payload)?;
                }
            },
        }
    }
}

pub(crate) fn parse_field(field: &Field) -> syn::Result<FieldSpec> {
    let ident = field
        .ident
        .clone()
        .ok_or_else(|| syn::Error::new_spanned(field, "field must have a name"))?;

    let ml = find_meta_list(&field.attrs, "genl_attr").ok_or_else(|| {
        syn::Error::new_spanned(
            field,
            format!(
                "field `{ident}` is missing #[genl_attr(EXPR)] — every field in a \
                 #[derive(GenlMessage)] struct must declare its attribute kind"
            ),
        )
    })?;

    // #[genl_attr(EXPR [, repr | bitflags | nested ...])]
    let GenlAttrArgs {
        attr_expr,
        width,
        nested,
    } = ml.parse_args()?;

    let kind = classify_type(&field.ty, width, nested)?;

    Ok(FieldSpec {
        ident,
        attr_expr,
        kind,
    })
}

fn classify_type(
    ty: &Type,
    width_hint: Option<(ReprWidth, WidthKind)>,
    nested: bool,
) -> syn::Result<WireKind> {
    classify_type_inner(ty, width_hint, nested, /* inside_option = */ false)
}

fn classify_type_inner(
    ty: &Type,
    width_hint: Option<(ReprWidth, WidthKind)>,
    nested: bool,
    inside_option: bool,
) -> syn::Result<WireKind> {
    let Type::Path(p) = ty else {
        return Err(syn::Error::new_spanned(
            ty,
            "unsupported field-type shape; expected a named type",
        ));
    };
    let last = p.path.segments.last().ok_or_else(|| {
        syn::Error::new_spanned(ty, "empty type path")
    })?;
    let name = last.ident.to_string();
    match name.as_str() {
        "u8" => Ok(WireKind::U8),
        "u16" => Ok(WireKind::U16),
        "u32" => Ok(WireKind::U32),
        "u64" => Ok(WireKind::U64),
        "i32" => Ok(WireKind::I32),
        "i64" => Ok(WireKind::I64),
        "String" => Ok(WireKind::Str),
        "Vec" => {
            // Vec<u8> = whole-payload byte string (the existing
            // single-attribute meaning).
            // Vec<MyEnum> + repr hint = repeated GenlEnum attr.
            // Other Vec<T> with a repr hint = compile error
            // pointing at the supported shapes.
            let inner = single_type_arg(last, ty)?;
            let inner_path = match inner {
                Type::Path(p) => p,
                _ => {
                    return Err(syn::Error::new_spanned(
                        inner,
                        "Vec inner type must be a path; only Vec<u8> and \
                         Vec<MyGenlEnum> are supported in #[derive(GenlMessage)]",
                    ))
                }
            };
            let inner_last = inner_path.path.segments.last().ok_or_else(|| {
                syn::Error::new_spanned(inner, "empty inner type path")
            })?;
            if inner_last.ident == "u8" {
                return Ok(WireKind::Bytes);
            }
            if let Some((repr, WidthKind::Enum)) = width_hint {
                return Ok(WireKind::RepeatedEnum {
                    type_path: Box::new(inner.clone()),
                    repr,
                });
            }
            Err(syn::Error::new_spanned(
                inner,
                format!(
                    "Vec<{}> needs a `repr = \"u8\"|\"u16\"|\"u32\"` hint on its \
                     `#[genl_attr(...)]` annotation — `Vec<MyGenlEnum>` is the \
                     repeated-attribute shape; bare Vec<{}> without a hint is \
                     ambiguous (could mean Vec<u8> bytes, but it's not u8). \
                     Repeated-bitflags fields aren't currently supported.",
                    inner_last.ident, inner_last.ident
                ),
            ))
        }
        "Option" => {
            let inner = single_type_arg(last, ty)?;
            let inner_kind = classify_type_inner(
                inner,
                width_hint,
                nested,
                /* inside_option = */ true,
            )?;
            if matches!(inner_kind, WireKind::Optional(_)) {
                return Err(syn::Error::new_spanned(
                    ty,
                    "nested Option<Option<T>> is not supported in #[derive(GenlMessage)]",
                ));
            }
            Ok(WireKind::Optional(Box::new(inner_kind)))
        }
        _ => {
            // Unknown type: dispatch on the field's hint kind.
            //   `repr = "u32"`     → GenlEnum-typed (requires Option<>)
            //   `bitflags = "u32"` → bitflags newtype (no Option needed —
            //                        from_bits_retain(0) is the natural
            //                        empty value)
            //   `nested`           → NetlinkAttrs-typed group (requires
            //                        Option<>, same reason as repr).
            // Without any hint, error pointing the user at how to fix it.
            if nested {
                if !inside_option {
                    return Err(syn::Error::new_spanned(
                        ty,
                        format!(
                            "nested-group field `{name}` must be wrapped in \
                             `Option<{name}>` for #[derive(GenlMessage)]. \
                             Nested attribute groups have no sensible Default \
                             (the kernel either emits the block or doesn't); \
                             `None` is the natural missing-group state. Change \
                             the field to `Option<{name}>` and re-derive."
                        ),
                    ));
                }
                return Ok(WireKind::Nested {
                    type_path: Box::new(ty.clone()),
                });
            }
            match width_hint {
                Some((repr, WidthKind::Enum)) => {
                    if !inside_option {
                        return Err(syn::Error::new_spanned(
                            ty,
                            format!(
                                "GenlEnum-typed field `{name}` must be wrapped in \
                                 `Option<{name}>` for #[derive(GenlMessage)] (kernel \
                                 UAPI enums typically don't have a sensible Default; \
                                 missing-attr semantics map cleanly to None). Change \
                                 the field to `Option<{name}>` and re-derive. Wire \
                                 repr stays `repr = \"{}\"`.",
                                match repr {
                                    ReprWidth::U8 => "u8",
                                    ReprWidth::U16 => "u16",
                                    ReprWidth::U32 => "u32",
                                }
                            ),
                        ));
                    }
                    Ok(WireKind::Enum {
                        type_path: Box::new(ty.clone()),
                        repr,
                    })
                }
                Some((repr, WidthKind::Bitflags)) => {
                    // Bitflags newtypes are self-empty-able via
                    // from_bits_retain(0); no Option<> required.
                    // Allowed at both top-level and inside Option<>.
                    Ok(WireKind::Bitflags {
                        type_path: Box::new(ty.clone()),
                        repr,
                    })
                }
                None => Err(syn::Error::new_spanned(
                    ty,
                    format!(
                        "unsupported field type `{name}` in #[derive(GenlMessage)]. \
                         Supported: u8, u16, u32, u64, i32, String, Vec<u8>, Option<T>. \
                         For `#[derive(GenlEnum)]`-typed fields, wrap in `Option<T>` \
                         and add `repr = \"u8\"|\"u16\"|\"u32\"`. \
                         For bitflags newtypes (`.bits()` + `from_bits_retain`), \
                         add `bitflags = \"u8\"|\"u16\"|\"u32\"`. \
                         For `#[derive(NetlinkAttrs)]`-typed nested groups, wrap \
                         in `Option<T>` and add `nested`."
                    ),
                )),
            }
        }
    }
}

/// Extract the single type argument from a generic segment
/// (e.g. `Option<T>` → `T`, `Vec<u8>` → `u8`).
fn single_type_arg<'a>(
    seg: &'a syn::PathSegment,
    parent_ty: &Type,
) -> syn::Result<&'a Type> {
    let args = match &seg.arguments {
        PathArguments::AngleBracketed(a) => a,
        _ => {
            return Err(syn::Error::new_spanned(
                parent_ty,
                format!("`{}` must have a single type parameter", seg.ident),
            ))
        }
    };
    let _ = parent_ty.span();
    if args.args.len() != 1 {
        return Err(syn::Error::new_spanned(
            args,
            format!(
                "`{}` requires exactly one type parameter; found {}",
                seg.ident,
                args.args.len()
            ),
        ));
    }
    match &args.args[0] {
        GenericArgument::Type(t) => Ok(t),
        other => Err(syn::Error::new_spanned(
            other,
            format!("`{}` type parameter must be a type", seg.ident),
        )),
    }
}

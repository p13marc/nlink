//! Proc-macro derives for the [`nlink`][nlink] Linux-netlink
//! library — typed GENL family / command / attribute / message
//! codecs.
//!
//! **Don't depend on this crate directly.** Use `nlink` and write
//! `use nlink::macros::*;` to pull in every macro plus the
//! supporting traits in one shot. See the README + the
//! [`define-your-own-genl-family` recipe][recipe] for end-to-end
//! usage; the runnable example lives at
//! [`crates/nlink/examples/macros/define_taskstats.rs`][example].
//!
//! # Shipped surface (0.16, Plan 154 Phases 1–6)
//!
//! - [`macro@GenlCommand`] + `#[genl_command(repr = "u8"|"u16")]`
//!   — typed GENL command enum
//! - [`macro@GenlAttribute`] + `#[genl_attribute(repr = "u8"|"u16")]`
//!   — typed attribute-kind enum
//! - [`macro@GenlEnum`] + `#[genl_enum(repr = "u8"|"u16"|"u32")]`
//!   — typed value enum encoded *inside* an attribute payload
//! - [`macro@GenlMessage`] + `#[genl_message(cmd = ...)]` +
//!   per-field `#[genl_attr(...)]` — typed request/response
//!   body. Pairs with the generic
//!   `Connection::<F: GenlFamily>::send_typed<M, R>` /
//!   `dump_typed_stream<M, R>` dispatch in `nlink`.
//! - [`macro@genl_family`] — `#[genl_family(name = "...", version
//!   = N)]` rewrites a unit-struct declaration into a complete
//!   family marker (`ProtocolState` + `AsyncProtocolInit` +
//!   `GenlFamily` + sealed-trait impls + `family_id` field +
//!   `Default` / `Debug`).
//!
//! The three codec derives (`GenlCommand`, `GenlAttribute`,
//! `GenlEnum`) produce the same shape — `From<EnumType> for
//! ReprType` + `TryFrom<ReprType> for EnumType` + a small
//! `EnumTypeUnknownValue(repr)` error newtype.
//!
//! # Deferred follow-up
//!
//! `#[derive(NetlinkAttrs)]` for nested attribute groups
//! (`NLA_F_NESTED`) is tracked as a Plan 154 follow-up. The
//! `nlink::macros::NetlinkAttrs` *trait* is already in tree so
//! hand-implementations work today; the derive will close the
//! last remaining "hand-roll this bit" gap.
//!
//! [nlink]: https://docs.rs/nlink
//! [recipe]: https://github.com/p13marc/nlink/blob/master/docs/recipes/define-your-own-genl-family.md
//! [example]: https://github.com/p13marc/nlink/blob/master/crates/nlink/examples/macros/define_taskstats.rs

use proc_macro::TokenStream;
use proc_macro2::Span;
use syn::{parse_macro_input, Data, DeriveInput, Expr, ExprLit, Lit, LitStr, Meta};

// Re-export the syn `ItemStruct` shape used by the
// `#[genl_family]` attribute macro to consume its input.
pub(crate) use syn::ItemStruct;

mod codec;
mod genl_attribute;
mod genl_command;
mod genl_family;
mod genl_enum;
mod genl_message;
mod netlink_attrs;

/// Derive a typed-enum codec for a Generic Netlink **command** ID
/// enum.
///
/// Generates `impl From<EnumType> for ReprType` (infallible —
/// every variant has a known discriminant) and `impl
/// TryFrom<ReprType> for EnumType` (fallible — unknown values
/// land in an `Err(InvalidValue)` arm).
///
/// `ReprType` is either `u8` or `u16` per the
/// `#[genl_command(repr = "...")]` attribute.
///
/// # Example
///
/// ```ignore
/// use nlink_macros::GenlCommand;
///
/// #[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
/// #[genl_command(repr = "u8")]
/// #[non_exhaustive]
/// pub enum MyCmd {
///     Unspec = 0,
///     Get = 1,
///     Set = 2,
/// }
///
/// // Generated impls:
/// let raw: u8 = MyCmd::Get.into();
/// assert_eq!(raw, 1);
/// let parsed = MyCmd::try_from(2u8).unwrap();
/// assert_eq!(parsed, MyCmd::Set);
/// assert!(MyCmd::try_from(255u8).is_err());
/// ```
///
/// # Requirements
///
/// - The annotated type must be an `enum`.
/// - Each variant must have an explicit `= literal` discriminant
///   (e.g. `Get = 1`). Anonymous-discriminant variants (`Get,`)
///   are rejected at compile time because kernel ABI demands
///   stable wire values.
/// - Variants must be unit-only (no fields). Tuple/struct
///   variants are rejected.
///
/// Errors point at the offending span via `syn::Error::new_spanned`.
#[proc_macro_derive(GenlCommand, attributes(genl_command))]
pub fn derive_genl_command(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    genl_command::expand(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive a typed-enum codec for a Generic Netlink **attribute
/// kind** enum.
///
/// Same shape as [`macro@GenlCommand`] but for the u16
/// attribute-type field on each `nlattr`. Accepts `repr = "u8"`
/// or `repr = "u16"`; the `NLA_F_NESTED` (0x8000) and
/// `NLA_F_NET_BYTEORDER` (0x4000) flag bits are the caller's
/// responsibility — the derive doesn't reserve them.
///
/// # Example
///
/// ```ignore
/// use nlink_macros::GenlAttribute;
///
/// #[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
/// #[genl_attribute(repr = "u16")]
/// #[non_exhaustive]
/// pub enum DpllAttr {
///     Id = 1,
///     ModuleName = 2,
///     ClockId = 4,
///     Mode = 5,
/// }
/// ```
#[proc_macro_derive(GenlAttribute, attributes(genl_attribute))]
pub fn derive_genl_attribute(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    genl_attribute::expand(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive a typed-enum codec for a value enum encoded *inside*
/// an attribute payload (rather than as the attribute kind
/// itself).
///
/// Use this for kernel-UAPI enums like `DPLL_LOCK_STATUS_*`,
/// `DEVLINK_RATE_TYPE_*`, or any other typed value the kernel
/// declares via `enum dpll_lock_status` etc. Accepts `repr =
/// "u8"`, `"u16"`, or `"u32"`. Strictly weaker than
/// [`macro@GenlAttribute`] — no attribute-kind machinery — and
/// no constraint on 1-based-vs-0-based discriminants: the derive
/// matches whatever the user declares.
///
/// # Example
///
/// ```ignore
/// use nlink_macros::GenlEnum;
///
/// // 1-based (the common kernel convention).
/// #[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
/// #[genl_enum(repr = "u32")]
/// #[non_exhaustive]
/// pub enum DpllMode {
///     Manual = 1,
///     Automatic = 2,
/// }
///
/// // 0-based outlier (rare but real — DPLL_FEATURE_STATE_*).
/// #[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
/// #[genl_enum(repr = "u32")]
/// #[non_exhaustive]
/// pub enum DpllFeatureState {
///     Disable = 0,
///     Enable = 1,
/// }
/// ```
#[proc_macro_derive(GenlEnum, attributes(genl_enum))]
pub fn derive_genl_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    genl_enum::expand(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive `nlink::macros::GenlMessage` for a struct-shaped GENL
/// message body.
///
/// The struct's `#[genl_message(cmd = EXPR)]` attribute supplies
/// the command byte (any compile-time-evaluable expression that
/// casts to `u8` — typically an integer literal or a typed-enum
/// variant cast like `cmd = MyCmd::Get`). Each named field carries
/// a `#[genl_attr(EXPR)]` attribute naming its on-wire attribute
/// kind (similarly, any expression that casts to `u16`).
///
/// # Supported field types (0.16 Phase 3b)
///
/// - `u8` / `u16` / `u32` / `u64`
/// - `String`
/// - `Vec<u8>`
/// - `Option<T>` where `T` is any of the above — omitted on
///   `None`, present-when-`Some`, `Some(parsed)` if the kernel
///   returns it.
///
/// Unsupported types (`i32`, nested groups, `IpAddr`, `bool`)
/// produce a compile-time error that points at the field.
/// Nested-group support via `#[derive(NetlinkAttrs)]` ships in a
/// later phase.
///
/// # `from_bytes` semantics
///
/// Missing attributes produce default values (zero for ints,
/// empty for strings/bytes, `None` for `Option<T>`). Unknown
/// attribute types are silently skipped — forward-compatibility
/// with newer kernels.
///
/// # Example
///
/// ```ignore
/// use nlink::macros::*;
///
/// #[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
/// #[genl_command(repr = "u8")]
/// pub enum MyCmd { Unspec = 0, Get = 1 }
///
/// #[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
/// #[genl_attribute(repr = "u16")]
/// pub enum MyAttr { Id = 1, Name = 2, Description = 3 }
///
/// #[derive(GenlMessage, Debug)]
/// #[genl_message(cmd = MyCmd::Get)]
/// pub struct GetRequest {
///     #[genl_attr(MyAttr::Id)]
///     pub id: u32,
///     #[genl_attr(MyAttr::Name)]
///     pub name: String,
///     #[genl_attr(MyAttr::Description)]
///     pub description: Option<String>,
/// }
///
/// // Generated:
/// // impl GenlMessage for GetRequest {
/// //     const CMD: u8 = MyCmd::Get as u8;  // = 1
/// //     fn to_bytes(&self, b: &mut MessageBuilder) -> Result<()> { ... }
/// //     fn from_bytes(payload: &[u8]) -> Result<Self> { ... }
/// // }
/// ```
#[proc_macro_derive(GenlMessage, attributes(genl_message, genl_attr))]
pub fn derive_genl_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    genl_message::expand(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive `NetlinkAttrs` for a nested attribute group — a struct
/// the kernel encodes as the contents of a single `NLA_F_NESTED`
/// attribute.
///
/// Same field-type-mapping table as `#[derive(GenlMessage)]`
/// (primitives + `Option<T>` + `Vec<u8>` + `Vec<GenlEnum>` +
/// bitflags + `Option<GenlEnum>`), same per-field
/// `#[genl_attr(EXPR [, repr = "..."] [, bitflags = "..."])]`
/// annotation. The only difference: no `cmd` const, methods are
/// `write_attrs` / `read_attrs` (matching the
/// `nlink::macros::NetlinkAttrs` trait).
///
/// # Example
///
/// ```ignore
/// use nlink::macros::*;
///
/// #[derive(NetlinkAttrs, Debug, Default)]
/// pub struct ParentDeviceBlock {
///     #[genl_attr(1u16)] pub device_id: u32,
///     #[genl_attr(2u16)] pub pin_id: u32,
/// }
///
/// // Use the group inside a GenlMessage struct via `nested`:
/// #[derive(GenlMessage, Debug, Default)]
/// #[genl_message(cmd = DpllCmd::PinGet)]
/// pub struct DpllPinReply {
///     #[genl_attr(DpllPinAttr::Id)] pub id: u32,
///     #[genl_attr(DpllPinAttr::ParentDevice, nested)]
///     pub parent_device: Option<ParentDeviceBlock>,
/// }
/// ```
#[proc_macro_derive(NetlinkAttrs, attributes(genl_attr))]
pub fn derive_netlink_attrs(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    netlink_attrs::expand(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Declare a Generic Netlink family marker.
///
/// Rewrites a unit-struct declaration into a complete family
/// marker type with all the trait impls (`ProtocolState`,
/// `AsyncProtocolInit`, `__macro_seal::ProtocolStateSeal`,
/// `__macro_seal::AsyncConstructibleSeal`) the rest of nlink
/// needs to plug the marker into the existing
/// `Connection::<P>::new_async()` machinery.
///
/// # Arguments
///
/// - `name = "..."` — the family name registered with the
///   kernel (matches the `nl80211`, `dpll`, `wireguard` strings).
/// - `version = N` — the GENL family version (kernel UAPI;
///   typically `1`).
///
/// # Example
///
/// ```ignore
/// use nlink::macros::genl_family;
///
/// #[genl_family(name = "my_family", version = 1)]
/// pub struct MyFamily;
///
/// // Expands to a struct with a `family_id: u16` field +
/// // `MyFamily::NAME` + `MyFamily::VERSION` constants +
/// // ProtocolState / AsyncProtocolInit / AsyncConstructible
/// // impls. Use as the protocol marker:
/// //
/// // let conn = Connection::<MyFamily>::new_async().await?;
/// ```
///
/// # Requirements
///
/// - The annotated struct must be a unit struct (`pub struct
///   MyFamily;`). The macro rewrites it to add the `family_id`
///   field; pre-declared fields would conflict.
/// - The struct must not be generic.
///
/// # Sealed-trait impl detail
///
/// The macro emits `impl
/// nlink::netlink::protocol::__macro_seal::ProtocolStateSeal`
/// (which is the private `Sealed` trait re-exported under a
/// `#[doc(hidden)]` path for this macro's use). This satisfies
/// the in-tree sealed-trait contract that prevents arbitrary
/// types from claiming `ProtocolState`; using
/// `#[genl_family]` is the only path the contract authorizes.
#[proc_macro_attribute]
pub fn genl_family(args: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemStruct);
    genl_family::expand(args.into(), item)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

// --------------------------------------------------------------
// Shared helpers used across derives. Kept in lib.rs because
// they're small + private to this crate.
// --------------------------------------------------------------

/// Width of a typed-codec enum's wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReprWidth {
    U8,
    U16,
    U32,
}

impl ReprWidth {
    pub(crate) fn ident(self) -> proc_macro2::Ident {
        let s = match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
        };
        proc_macro2::Ident::new(s, Span::call_site())
    }

    /// Parse from the `repr = "u8"` string-literal form used by
    /// `#[genl_command(repr = "...")]` and siblings.
    pub(crate) fn parse(lit: &LitStr) -> syn::Result<Self> {
        match lit.value().as_str() {
            "u8" => Ok(Self::U8),
            "u16" => Ok(Self::U16),
            "u32" => Ok(Self::U32),
            other => Err(syn::Error::new(
                lit.span(),
                format!("unknown repr {other:?}; expected \"u8\", \"u16\", or \"u32\""),
            )),
        }
    }
}

/// Find the `#[genl_command(...)]` (or other named) attribute on
/// the derive input and return its `Meta::List`.
pub(crate) fn find_meta_list<'a>(
    attrs: &'a [syn::Attribute],
    name: &str,
) -> Option<&'a syn::MetaList> {
    attrs.iter().find_map(|a| match &a.meta {
        Meta::List(ml) if ml.path.is_ident(name) => Some(ml),
        _ => None,
    })
}

/// Parse `repr = "u8"` (etc.) out of the `Meta::List` inside an
/// attribute. Returns `Err` if `repr` is missing or malformed.
pub(crate) fn parse_repr_attr(ml: &syn::MetaList, attr_name: &str) -> syn::Result<ReprWidth> {
    let mut found_repr: Option<ReprWidth> = None;
    ml.parse_nested_meta(|meta| {
        if meta.path.is_ident("repr") {
            let value = meta.value()?;
            let lit: LitStr = value.parse()?;
            found_repr = Some(ReprWidth::parse(&lit)?);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown {attr_name} key {:?}; expected `repr`",
                meta.path
                    .get_ident()
                    .map(|i| i.to_string())
                    .unwrap_or_default()
            )))
        }
    })?;
    found_repr.ok_or_else(|| {
        syn::Error::new_spanned(
            ml,
            format!("#[{attr_name}(...)] must specify `repr = \"u8\"|\"u16\"|\"u32\"`"),
        )
    })
}

/// Extract the explicit `= literal` discriminant from a variant.
/// Returns the literal value as a `u64` (variants must fit; the
/// derive validates against the repr's width separately).
pub(crate) fn variant_discriminant(variant: &syn::Variant) -> syn::Result<u64> {
    let (_, expr) = variant.discriminant.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(
            variant,
            "GenlCommand/GenlAttribute/GenlEnum variants must have an \
             explicit `= literal` discriminant — kernel ABI requires \
             stable wire values",
        )
    })?;
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(int), ..
        }) => int.base10_parse::<u64>(),
        _ => Err(syn::Error::new_spanned(
            expr,
            "discriminant must be an integer literal (e.g., `= 1`)",
        )),
    }
}

/// Ensure the data is an enum + every variant is a unit variant
/// (no fields).
pub(crate) fn require_unit_enum<'a>(
    data: &'a Data,
    derive_name: &str,
    span: Span,
) -> syn::Result<&'a syn::DataEnum> {
    let de = match data {
        Data::Enum(e) => e,
        Data::Struct(_) => {
            return Err(syn::Error::new(
                span,
                format!("#[derive({derive_name})] is only valid on enums, not structs"),
            ))
        }
        Data::Union(_) => {
            return Err(syn::Error::new(
                span,
                format!("#[derive({derive_name})] is only valid on enums, not unions"),
            ))
        }
    };
    for v in &de.variants {
        match &v.fields {
            syn::Fields::Unit => {}
            _ => {
                return Err(syn::Error::new_spanned(
                    v,
                    format!(
                        "#[derive({derive_name})] variants must be unit-only \
                         (no fields); `{}` has fields",
                        v.ident
                    ),
                ))
            }
        }
    }
    Ok(de)
}

/// Validate that `value` fits in `width` (the discriminant doesn't
/// overflow the chosen repr).
pub(crate) fn fits_in_width(value: u64, width: ReprWidth) -> bool {
    match width {
        ReprWidth::U8 => value <= u8::MAX as u64,
        ReprWidth::U16 => value <= u16::MAX as u64,
        ReprWidth::U32 => value <= u32::MAX as u64,
    }
}


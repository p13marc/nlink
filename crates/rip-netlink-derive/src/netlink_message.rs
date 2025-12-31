//! Implementation of the NetlinkMessage derive macro.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Expr, Fields, Lit, Meta, parse_macro_input};

/// Field information extracted from attributes.
struct FieldInfo {
    name: syn::Ident,
    ty: syn::Type,
    is_header: bool,
    attr_id: Option<u16>,
    nested: bool,
}

/// Parse a field's #[netlink(...)] attributes.
fn parse_field_attrs(field: &syn::Field) -> Option<FieldInfo> {
    let name = field.ident.clone()?;
    let ty = field.ty.clone();
    let mut is_header = false;
    let mut attr_id = None;
    let mut nested = false;

    for attr in &field.attrs {
        if !attr.path().is_ident("netlink") {
            continue;
        }

        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("header") {
                is_header = true;
            } else if meta.path.is_ident("nested") {
                nested = true;
            } else if meta.path.is_ident("attr") {
                let value: Expr = meta.value()?.parse()?;
                if let Expr::Lit(expr_lit) = value {
                    if let Lit::Int(lit_int) = expr_lit.lit {
                        attr_id = Some(lit_int.base10_parse::<u16>().unwrap());
                    }
                }
            }
            Ok(())
        });
    }

    Some(FieldInfo {
        name,
        ty,
        is_header,
        attr_id,
        nested,
    })
}

/// Extract the header type from struct-level attributes.
fn parse_struct_attrs(input: &DeriveInput) -> Option<syn::Type> {
    for attr in &input.attrs {
        if !attr.path().is_ident("netlink") {
            continue;
        }

        let mut header_type = None;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("header") {
                let value: Expr = meta.value()?.parse()?;
                if let Expr::Path(expr_path) = value {
                    header_type = Some(syn::Type::Path(syn::TypePath {
                        qself: None,
                        path: expr_path.path,
                    }));
                }
            }
            Ok(())
        });

        if header_type.is_some() {
            return header_type;
        }
    }
    None
}

pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Get header type from struct attributes
    let header_type = parse_struct_attrs(&input);

    // Extract fields
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("NetlinkMessage only supports named fields"),
        },
        _ => panic!("NetlinkMessage only supports structs"),
    };

    // Parse field information
    let field_infos: Vec<_> = fields.iter().filter_map(parse_field_attrs).collect();

    // Find header field
    let header_field = field_infos.iter().find(|f| f.is_header);

    // Collect attribute fields
    let attr_fields: Vec<_> = field_infos.iter().filter(|f| f.attr_id.is_some()).collect();

    // Generate parsing code for attributes
    let attr_parse_arms: Vec<_> = attr_fields
        .iter()
        .map(|field| {
            let field_name = &field.name;
            let attr_id = field.attr_id.unwrap();
            let ty = &field.ty;

            // Check if the type is Option<T>
            let is_option = if let syn::Type::Path(type_path) = ty {
                type_path
                    .path
                    .segments
                    .last()
                    .map(|seg| seg.ident == "Option")
                    .unwrap_or(false)
            } else {
                false
            };

            // Extract inner type from Option<T>
            let inner_ty = if is_option {
                if let syn::Type::Path(type_path) = ty {
                    if let Some(seg) = type_path.path.segments.last() {
                        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                            if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                                Some(inner.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if field.nested {
                // Nested attribute - parse recursively
                quote! {
                    #attr_id => {
                        match rip_netlink::parse::FromNetlink::parse(&mut attr_data.as_ref()) {
                            Ok(val) => result.#field_name = Some(val),
                            Err(_) => {}
                        }
                    }
                }
            } else if let Some(inner) = inner_ty {
                // Check for common types and generate appropriate parsing
                let inner_str = quote!(#inner).to_string();

                if inner_str.contains("String") {
                    quote! {
                        #attr_id => {
                            if let Ok(s) = std::str::from_utf8(attr_data) {
                                result.#field_name = Some(s.trim_end_matches('\0').to_string());
                            }
                        }
                    }
                } else if inner_str.contains("u32") {
                    quote! {
                        #attr_id => {
                            if attr_data.len() >= 4 {
                                let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                                result.#field_name = Some(u32::from_ne_bytes(bytes));
                            }
                        }
                    }
                } else if inner_str.contains("u16") {
                    quote! {
                        #attr_id => {
                            if attr_data.len() >= 2 {
                                let bytes: [u8; 2] = attr_data[..2].try_into().unwrap();
                                result.#field_name = Some(u16::from_ne_bytes(bytes));
                            }
                        }
                    }
                } else if inner_str.contains("u8") {
                    quote! {
                        #attr_id => {
                            if !attr_data.is_empty() {
                                result.#field_name = Some(attr_data[0]);
                            }
                        }
                    }
                } else if inner_str.contains("Vec") {
                    quote! {
                        #attr_id => {
                            result.#field_name = Some(attr_data.to_vec());
                        }
                    }
                } else {
                    // Default: try to parse using FromNetlink
                    quote! {
                        #attr_id => {
                            match rip_netlink::parse::FromNetlink::parse(&mut attr_data.as_ref()) {
                                Ok(val) => result.#field_name = Some(val),
                                Err(_) => {}
                            }
                        }
                    }
                }
            } else {
                // Non-optional field - store raw bytes as Vec<u8>
                quote! {
                    #attr_id => {
                        result.#field_name = attr_data.to_vec();
                    }
                }
            }
        })
        .collect();

    // Generate field initializers for Default
    let field_defaults: Vec<_> = field_infos
        .iter()
        .map(|field| {
            let field_name = &field.name;
            quote! { #field_name: Default::default() }
        })
        .collect();

    // Generate the impl
    let header_parse = if let Some(header_field) = header_field {
        let header_name = &header_field.name;
        let header_ty = header_type.unwrap_or_else(|| header_field.ty.clone());
        quote! {
            // Parse header
            let header = <#header_ty as rip_netlink::parse::FromNetlink>::parse(input)?;
            result.#header_name = header;
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        impl rip_netlink::parse::FromNetlink for #name {
            fn parse(input: &mut &[u8]) -> rip_netlink::parse::PResult<Self> {
                use winnow::Parser;
                use winnow::binary::le_u16;
                use winnow::token::take;

                let mut result = #name {
                    #(#field_defaults),*
                };

                #header_parse

                // Parse attributes
                while !input.is_empty() {
                    // Parse attribute header (length, type)
                    if input.len() < 4 {
                        break;
                    }

                    let len = le_u16.parse_next(input)? as usize;
                    let attr_type = le_u16.parse_next(input)?;

                    if len < 4 {
                        break;
                    }

                    let payload_len = len.saturating_sub(4);
                    if input.len() < payload_len {
                        break;
                    }

                    let attr_data: &[u8] = take(payload_len).parse_next(input)?;

                    // Align to 4 bytes
                    let aligned = (len + 3) & !3;
                    let padding = aligned.saturating_sub(len);
                    if input.len() >= padding {
                        let _: &[u8] = take(padding).parse_next(input)?;
                    }

                    // Match attribute type
                    match attr_type & 0x3FFF { // Mask out NLA_F_NESTED and NLA_F_NET_BYTEORDER
                        #(#attr_parse_arms)*
                        _ => {} // Ignore unknown attributes
                    }
                }

                Ok(result)
            }
        }
    };

    TokenStream::from(expanded)
}

//! Derive macros for rip-netlink strongly-typed API.
//!
//! This crate provides procedural macros for automatically implementing
//! netlink message parsing and serialization.

use proc_macro::TokenStream;

mod netlink_message;

/// Derive macro for implementing `FromNetlink` and `ToNetlink` traits.
///
/// # Example
///
/// ```ignore
/// use rip_netlink_derive::NetlinkMessage;
///
/// #[derive(NetlinkMessage)]
/// #[netlink(header = IfAddrMsg)]
/// pub struct AddressMessage {
///     #[netlink(header)]
///     pub header: IfAddrMsg,
///
///     #[netlink(attr = 1)] // IFA_ADDRESS
///     pub address: Option<Vec<u8>>,
///
///     #[netlink(attr = 2)] // IFA_LOCAL
///     pub local: Option<Vec<u8>>,
///
///     #[netlink(attr = 3)] // IFA_LABEL
///     pub label: Option<String>,
/// }
/// ```
#[proc_macro_derive(NetlinkMessage, attributes(netlink))]
pub fn derive_netlink_message(input: TokenStream) -> TokenStream {
    netlink_message::derive(input)
}

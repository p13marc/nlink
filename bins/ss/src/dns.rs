//! Reverse-DNS resolution for `ss -r`.
//!
//! Uses libc `getnameinfo(3)` with `NI_NAMEREQD`, so an address with
//! no PTR record returns `None` (the caller then falls back to the
//! numeric form) rather than echoing the literal IP back. This is a
//! `bins/` concern — it performs a blocking resolver lookup, which is
//! fine for the demo CLI's final output stage but is deliberately
//! kept out of the library.

use std::{
    ffi::CStr,
    mem,
    net::{IpAddr, SocketAddr},
};

/// Resolve an IP address to a hostname via reverse DNS.
///
/// Returns `None` when the lookup fails or the address has no PTR
/// record (`NI_NAMEREQD`), so callers can fall back to the numeric
/// representation.
pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    // Port is irrelevant for a host lookup; use 0.
    let sa = SocketAddr::new(ip, 0);
    let mut host = [0i8; libc::NI_MAXHOST as usize];

    let rc = match sa {
        SocketAddr::V4(v4) => {
            let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            unsafe {
                libc::getnameinfo(
                    &addr as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            unsafe {
                libc::getnameinfo(
                    &addr as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo wrote a NUL-terminated string on success.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    if name.is_empty() { None } else { Some(name) }
}

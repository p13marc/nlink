//! `wg watch` — poll-based monitor for WireGuard peer changes.
//!
//! Exposes the library's [`WireguardWatcher`], which the bin
//! previously left unused. Emits a readable line per change
//! (peer add/remove, endpoint rebind, handshake refresh,
//! allowed-ips change) instead of the raw `{:?}` Debug form.

use std::time::{Duration, UNIX_EPOCH};

use nlink::netlink::{
    Connection, Error, Result, Wireguard,
    genl::wireguard::{WireguardEvent, WireguardWatchOptions, WireguardWatcher},
};

use crate::output::base64_encode;

pub async fn run(interfaces: Vec<String>, interval_secs: u64) -> Result<()> {
    if interfaces.is_empty() {
        return Err(Error::InvalidMessage(
            "wg watch: specify at least one interface to watch".into(),
        ));
    }

    let conn = Connection::<Wireguard>::new_async().await?;
    let mut opts = WireguardWatchOptions::default().interval(Duration::from_secs(interval_secs));
    for ifname in &interfaces {
        opts = opts.interface(ifname);
    }

    let mut watcher = WireguardWatcher::new(conn, opts)?;
    eprintln!(
        "Watching {} every {interval_secs}s (Ctrl+C to stop)...",
        interfaces.join(", ")
    );

    loop {
        for event in watcher.next_events().await? {
            println!("{}", format_event(&event));
        }
    }
}

fn format_event(event: &WireguardEvent) -> String {
    match event {
        WireguardEvent::PeerAdded { ifname, peer } => {
            format!("[{ifname}] peer added {}", base64_encode(&peer.public_key))
        }
        WireguardEvent::PeerRemoved { ifname, public_key } => {
            format!("[{ifname}] peer removed {}", base64_encode(public_key))
        }
        WireguardEvent::PeerEndpointChanged {
            ifname,
            public_key,
            from,
            to,
        } => format!(
            "[{ifname}] {} endpoint {} -> {}",
            base64_encode(public_key),
            from.map(|a| a.to_string()).unwrap_or_else(|| "none".into()),
            to.map(|a| a.to_string()).unwrap_or_else(|| "none".into()),
        ),
        WireguardEvent::PeerHandshakeRefreshed {
            ifname,
            public_key,
            at,
        } => {
            let secs = at
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!(
                "[{ifname}] {} handshake (unix {secs})",
                base64_encode(public_key)
            )
        }
        WireguardEvent::PeerAllowedIpsChanged {
            ifname,
            public_key,
            previous,
            current,
        } => format!(
            "[{ifname}] {} allowed-ips {} -> {} entries",
            base64_encode(public_key),
            previous.len(),
            current.len(),
        ),
        // WireguardEvent is #[non_exhaustive].
        other => format!("{other:?}"),
    }
}

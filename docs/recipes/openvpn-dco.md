# OpenVPN Data-Channel Offload (DCO)

Push the OpenVPN data-channel into the kernel via the `ovpn` GENL
family (kernel 6.16+). The TLS handshake stays in OpenVPN 2.7
userspace; the pre-derived AEAD keys + per-peer UDP/TCP sockets
are handed to the kernel via this family, eliminating the
per-packet user/kernel boundary that bottlenecked pre-DCO
OpenVPN.

## When to use this

- High-throughput tunnels (40+ Gbps) where the per-packet copy is
  the bottleneck.
- VPN concentrators with many concurrent peers.
- Mobile / IoT clients where context-switch overhead matters.

## When NOT to use this

- Pre-2.7 OpenVPN userspace — DCO requires the 2.7 control-plane
  changes.
- Legacy CBC ciphers (DCO is AEAD-only).
- Kernels < 6.16 (the family is unavailable).

## Imperative shape

Use the typed `Connection<Ovpn>` for direct ops:

```rust
use nlink::netlink::{
    Connection,
    genl::ovpn::{Ovpn, OvpnCipherAlg, OvpnKeyconf, OvpnKeydir, OvpnKeySlot, OvpnPeer},
};

// 1. Open the GENL connection (resolves the "ovpn" family ID).
let conn = Connection::<Ovpn>::new_async().await?;

// 2. Install a peer. The interface is identified by ifindex
//    (created elsewhere via OvpnLink + RTNL).
let mut peer = OvpnPeer::identity(42);
peer.set_remote_v4("10.0.0.1:1194".parse().unwrap());
peer.keepalive_interval = Some(20);
peer.keepalive_timeout = Some(60);
peer.socket = Some(udp_socket_fd as u32); // same-netns fd
conn.peer_new(ifindex, peer).await?;

// 3. Install the primary cipher key.
let keyconf = OvpnKeyconf::new(
    /* peer_id */    42,
    OvpnKeySlot::Primary,
    /* key_id */     1,
    OvpnCipherAlg::AesGcm,
    OvpnKeydir::new(encrypt_key_bytes, encrypt_nonce_tail),
    OvpnKeydir::new(decrypt_key_bytes, decrypt_nonce_tail),
);
conn.key_new(ifindex, keyconf).await?;

// 4. Rekey cutover: install secondary, then swap.
//    The swap is atomic — no packets are dropped.
conn.key_new(ifindex, secondary_keyconf).await?;
conn.key_swap(ifindex, /* peer_id */ 42).await?;

// 5. Delete the peer when the session ends.
conn.peer_del(ifindex, 42).await?;
```

## Declarative shape

For "reconcile to this desired state" semantics, use
`OvpnConfig` — the same mental model as `NetworkConfig`,
`NftablesConfig`, and `WireguardConfig`:

```rust
use nlink::netlink::genl::ovpn::{OvpnConfig, OvpnKeyConfig, OvpnKeySlot};

let cfg = OvpnConfig::new().interface(ifindex, |b| {
    b.peer(42, |p| {
        p.remote("10.0.0.1:1194".parse().unwrap())
            .keepalive(20, 60)
            .vpn_ipv4("172.16.0.42".parse().unwrap())
            .key(OvpnKeySlot::Primary, primary_key_config)
    })
    .peer(43, |p| {
        p.remote("10.0.0.2:1194".parse().unwrap())
            .keepalive(20, 60)
            .key(OvpnKeySlot::Primary, other_primary_key_config)
    })
});

// One-shot apply.
cfg.apply(&conn).await?;

// Or two-phase: inspect the diff before applying.
let diff = cfg.diff(&conn).await?;
println!("Plan: {diff}");
if !diff.is_empty() {
    diff.apply(&conn).await?;
}
```

### Diff semantics

`OvpnDiff` carries five operation lists:

| Field | Trigger |
|---|---|
| `peers_to_add` | Peer in config, absent from kernel |
| `peers_to_update` | Peer in config + kernel, config-relevant fields differ |
| `peers_to_remove` | Peer in kernel, absent from config |
| `keys_to_install` | Key in config, absent from kernel slot (or metadata mismatch) |
| `keys_to_delete` | Key slot's metadata mismatch — deleted before re-install |

**Read-only counters are excluded from diff inputs.** The peer's
`vpn_rx_bytes`, `link_tx_packets`, etc. grow monotonically and
would otherwise trigger spurious drift detection. This is the
Plan 178 invariant applied to `OvpnPeer`.

**Key bytes are write-only.** `key_get` returns metadata only
(`cipher_alg`, `key_id`, `slot`). The diff uses
`(cipher_alg, key_id)` as the key identity; configs that change
either of those fields trigger a `delete + install` pair. Configs
that change just the key bytes (same `cipher_alg`, same `key_id`)
are seen as no-ops — re-applying installs the same bytes, which
is fine.

## Reconcile against concurrent mutators

If another process may race with your apply, use
`apply_reconcile`:

```rust
cfg.apply_reconcile(&conn).await?;
```

It applies once, re-diffs, and returns an error if the kernel
state still diverges from the config (e.g. someone added a peer
mid-apply). The pattern mirrors `NetworkConfig::apply_reconcile`.

## Multicast notifications

Subscribe to the `peers` group for `peer-del-ntf`, `key-swap-ntf`,
and `peer-float-ntf`:

```rust
use nlink::netlink::genl::ovpn::OvpnEvent;
use tokio_stream::StreamExt;

let mut conn = Connection::<Ovpn>::new_async().await?;
conn.subscribe_peers()?;

let mut events = conn.events().await;
while let Some(evt) = events.next().await {
    match evt? {
        OvpnEvent::PeerDeleted(reply) => {
            let peer = reply.peer.unwrap();
            tracing::info!(
                "peer {} removed: {:?}",
                peer.id.unwrap_or(0),
                peer.del_reason,
            );
        }
        OvpnEvent::KeySwap(reply) => {
            // Kernel hints that IV space is exhausted; userspace
            // should renegotiate via OpenVPN 2.7 control-channel.
            let kc = reply.keyconf.unwrap();
            tracing::warn!(
                "peer {:?} key {:?} needs rekey",
                kc.peer_id, kc.slot
            );
        }
        OvpnEvent::PeerFloat(reply) => {
            let peer = reply.peer.unwrap();
            tracing::info!(
                "peer {} floated to {:?}",
                peer.id.unwrap_or(0),
                peer.remote_socket(),
            );
        }
    }
}
```

## Monitoring a DCO server

A server's observability has two halves: **poll** the connected peers
and their counters, and **subscribe** to lifecycle notifications. The
multicast stream above is the push side; `peer_dump` is the pull side.

`peer_dump(ifindex)` returns every peer with its read-only counters —
VPN-layer and transport-layer byte/packet totals — plus the current
remote endpoint and keepalive settings:

```rust
let conn = Connection::<Ovpn>::new_async().await?;

for p in conn.peer_dump(ifindex).await? {
    println!(
        "peer {} @ {:?}  vpn rx/tx={:?}/{:?}B  link rx/tx={:?}/{:?}B",
        p.id.unwrap_or(0),
        p.remote_socket(),
        p.vpn_rx_bytes, p.vpn_tx_bytes,
        p.link_rx_bytes, p.link_tx_bytes,
    );
}
```

Poll this on an interval for a traffic / rate view, and run the
[multicast subscription](#multicast-notifications) concurrently for
immediate `peer-del` / `key-swap` / `peer-float` signals. Together they
are the full per-peer picture: `peer_dump` answers "who's connected and
how much have they moved", the event stream answers "what just changed".

There is no server/client *mode* — the `ovpn` family is symmetric and
per-peer, so a server is simply a DCO interface carrying many peers,
each enumerated by `peer_dump` and keyed by its 3-byte peer ID. (Note
that netlink only sees DCO's *data plane*; the TLS control channel
stays in userspace OpenVPN.)

The `genl_ovpn` example bundles this as a `monitor <ifname>` mode:
`cargo run -p nlink --example genl_ovpn -- monitor tun0`.

## Cross-namespace fd passing

The kernel's per-peer socket is identified by an `OVPN_A_PEER_SOCKET`
attribute. When the calling process holds the fd in the same
netns as the ovpn interface, set `OvpnPeer::socket = Some(fd as u32)`
and the kernel resolves it via `sockfd_lookup`.

For cross-netns fd passing, the kernel expects an `SCM_RIGHTS`
auxiliary control message on the netlink sendmsg. nlink's
`Connection::<Ovpn>::attach_socket(ifindex, peer_id, RawFd)`
method's signature is shipped today, but the implementation
returns `Error::NotSupported` until the sendmsg-layer SCM_RIGHTS
support lands (queued for a follow-up release; see Plan 197 §7).

## Security note — key material zeroization

`OvpnKeydir` holds raw cipher key bytes as a `Vec<u8>`. nlink
**does not** zero-on-drop. Callers handling real key material
should wrap the bytes in a zeroize-aware container (e.g. the
`zeroize` crate's `Zeroizing<Vec<u8>>`) and only copy into the
`OvpnKeydir` at the moment of the kernel call. The same advice
applies to `OvpnKeyConfig` inside `OvpnConfig`.

## Kernel version detection

Detect availability without crashing:

```rust
match Connection::<Ovpn>::new_async().await {
    Ok(conn) => { /* use it */ }
    Err(e) if e.is_not_found() => {
        // Kernel < 6.16 or `ovpn` module not loaded.
        tracing::warn!("OVPN DCO unavailable; falling back to userspace");
    }
    Err(e) => return Err(e),
}
```

## Reference

- Kernel UAPI: `Documentation/netlink/specs/ovpn.yaml`
- Out-of-tree development: `https://github.com/OpenVPN/ovpn-net-next`
- Example: `crates/nlink/examples/genl/ovpn.rs`
- Changelog: `CHANGELOG.md ## [0.21.0]` (Plan 197); cross-netns
  `attach_socket` follow-on tracked in
  [#136](https://github.com/p13marc/nlink/issues/136)

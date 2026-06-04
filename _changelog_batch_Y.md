## Batch Y — Plan 197 OVPN GENL family (0.21.0)

### Added

- **OVPN Generic Netlink family** (`nlink::netlink::genl::ovpn`)
  for OpenVPN data-channel offload (DCO). Kernel 6.16+ ships
  in-kernel encrypt + decrypt of the OpenVPN data plane,
  eliminating the per-packet user/kernel boundary that
  bottlenecked pre-2.7 OpenVPN. nlink ships:

  - **Imperative** `Connection<Ovpn>` with `peer_new` / `peer_set`
    / `peer_get` / `peer_dump` / `peer_del` plus `key_new` /
    `key_get` / `key_swap` / `key_del` — the 8 GENL commands the
    upstream `Documentation/netlink/specs/ovpn.yaml` defines.
  - **Multicast** `peers` group subscription via
    `Connection::<Ovpn>::subscribe_peers()` + `OvpnEvent` enum
    (`PeerDeleted`, `KeySwap`, `PeerFloat` — the 3 multicast
    notifications upstream defines).
  - **Declarative** `OvpnConfig` mirroring `WireguardConfig` /
    `NftablesConfig` (Plan 196 / Plan 157) — describe per-interface
    peer + key state, `cfg.diff(&conn).await?` + `.apply()` to
    converge. `apply_reconcile` for concurrent-mutator scenarios.
  - **Diff invariants**: read-only counters (`vpn_*`, `link_*`)
    excluded from drift detection (Plan 178 invariant). Key bytes
    are write-only — diff identity = `(cipher_alg, key_id)`,
    matching Wireguard's private-key handling.
  - **Wire-shape types** generated via `#[derive(GenlMessage)]` +
    `#[derive(NetlinkAttrs)]` from `nlink-macros`. Byte-order-
    sensitive IPv4 / port fields stored as `Vec<u8>` (kernel
    emits BE; typed `set_remote_v4` / `remote_socket` helpers
    convert to/from `std::net` types).

  Cookbook: `docs/recipes/openvpn-dco.md` walks the imperative
  + declarative shapes, multicast notifications, key zeroization
  advice, and cross-netns fd-passing caveat. Example:
  `crates/nlink/examples/genl/ovpn.rs` (probe / apply run modes,
  `--features lab` for the full lifecycle demo).

  Integration tests at `crates/nlink/tests/integration/ovpn.rs`
  (root-gated + `require_module!("ovpn")`) cover family
  resolution, empty-iface dump, declarative apply round-trip,
  stale-peer cleanup, key install + metadata readback, atomic
  `key_swap`, single-peer delete, and full-lifecycle apply with
  installed key.

  Plan 197.

### Deferred to a follow-up

- **`Connection::<Ovpn>::attach_socket` cross-netns SCM_RIGHTS**
  ships today as a method returning `Error::NotSupported` with a
  clear deferral note. Same-netns callers should set
  `OvpnPeer::socket = Some(fd as u32)` on `peer_new` — the
  kernel resolves the fd via `sockfd_lookup` without needing
  SCM_RIGHTS. Cross-netns fd passing requires a sendmsg-layer
  refactor (the `NetlinkSocket` sendmsg path needs a `cmsghdr`
  carrying `SCM_RIGHTS + fd`); queued for a follow-up release.
  The method signature is in tree now so callers can plan
  against it.

### Internal

- New module: `crates/nlink/src/netlink/genl/ovpn/` (mod.rs,
  types.rs, messages.rs, connection.rs, events.rs, config.rs)
  — ~1600 LOC including the inline test modules.
- `EventSource for Ovpn` added in `crates/nlink/src/netlink/stream.rs`
  (mirrors the DPLL pattern from Plan 156 Phase 5).
- Cookbook README + recipe index updated.

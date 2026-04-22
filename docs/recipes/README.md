# nlink Cookbook Recipes

Cookbook-style end-to-end walkthroughs for common nlink use cases.
Each recipe opens with a problem statement, shows a self-contained
code snippet, and closes with caveats, cross-references, and a pointer
to the hand-rolled netlink primitives if you want to go deeper.

## Index

### Topology building blocks

- [**VLAN-aware bridge**](bridge-vlan.md) — build a bridge with
  `vlan_filtering(true)`, configure trunk and access ports, handle the
  default-VLAN-1 gotcha, and map VLANs to VXLAN VNIs.

### Traffic shaping & impairment

- [**Per-peer impairment**](per-peer-impairment.md) — different
  delay/loss/jitter per destination on a shared segment (bridges,
  multipoint radio fabrics). Uses `PerPeerImpairer`.
- [**Bidirectional rate limiting**](bidirectional-rate-limit.md) —
  symmetric or asymmetric egress + ingress shaping via HTB + IFB.
  Uses `RateLimiter`.

### Encrypted tunnels

- [**WireGuard mesh in namespaces**](wireguard-mesh.md) — 3-node WG
  full-mesh entirely within one host, using `nlink::lab` + the
  `Connection::<Wireguard>` write-path.

### Firewalling

- [**Stateful firewall with conntrack**](nftables-stateful-fw.md) —
  drop-by-default `inet` table, `ct state established,related` shortcut,
  blocklist set, plus a 3-namespace WAN/router/LAN lab demo. Uses the
  typed `nftables::Transaction` API + `Connection::<Netfilter>` for
  conntrack verification.

### Observability & orchestration

- [**Multi-namespace event monitoring**](multi-namespace-events.md) —
  watch link/addr/route/TC events across N namespaces concurrently
  with `tokio_stream::StreamMap`.

## Recipe shape

Every recipe follows the same structure:

1. **When to use this** — the problem the recipe solves, and when a
   simpler tool is enough.
2. **High-level approach** — the technique in one paragraph + a
   diagram where it helps.
3. **Code** — a copy-pasteable `no_run` snippet that exercises the
   real nlink API.
4. **Caveats** — required kernel modules, capability surface,
   interactions with other helpers.
5. **Hand-rolled equivalent** — what the high-level helper is doing
   underneath, so you can adapt if the helper doesn't fit.
6. **See also** — sibling recipes, API docs on docs.rs, kernel docs.

## Related material

- [`nlink::lab`](https://docs.rs/nlink/latest/nlink/lab/index.html) —
  `LabNamespace`, `LabBridge`, `LabVeth`, `with_namespace`: the
  test-and-demo helpers that most recipes use for namespace setup.
  Behind the `lab` feature flag.
- [`examples/`](../../crates/nlink/examples/) — runnable binaries
  (`cargo run --example <name>`) that exercise the APIs end-to-end.
  The example promotions in commits `d023381`, `62b2ee5`, `87d0a56`,
  `9168f40`, `c872d37`, `306c8fb`, and `f0e329e` cover TC pipelines,
  WireGuard / MACsec / MPTCP lifecycles, ethtool / nl80211 / devlink
  write paths, and the `nlink::lab` demo.
- [`CLAUDE.md`](../../CLAUDE.md) — the top-level module + API tour.

## Wanted

Recipes we'd like to have but haven't written yet (contributions
welcome):

- **XFRM IPsec site-to-site tunnel** — two namespaces acting as two
  sites, with SA/SP configuration via the XFRM protocol. Tracked in
  Plan 135.
- **Cgroup-based traffic classification** — blocked on the
  [`BasicFilter` ematch API](../../133-tc-coverage-plan.md) (Plan 133
  PR C). Once that lands, the recipe is a 200-line writeup.

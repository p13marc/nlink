# IPsec tunnel between two lab namespaces (XFRM)

Programmatically install matching IPsec Security Associations
(SAs) and Security Policies (SPs) on both ends of a transparent
tunnel — no IKE daemon, no `ip xfrm` shell-out, just typed
`Connection<Xfrm>` CRUD.

## When to use this

Typed XFRM CRUD is the right tool when you need to:

- Stand up a deterministic IPsec tunnel for testing (lab nets,
  CI fixtures, packet-capture rigs) where the keys can be
  hard-coded.
- Drive SA / SP lifecycles from a Rust process without IKE — the
  typical use is sidecar / control-plane code that talks to a
  separate KE library and then commits the keys via XFRM.
- Rotate keys in place via `update_sa` (no delete-then-add gap
  that would leave traffic unprotected).

Reach for `strongSwan` / `Libreswan` / native WireGuard if you
need IKE, NAT-T discovery, certificate management, or peer
auth. This recipe is the layer underneath all of those.

## High-level approach

Two `LabNamespace`s connected by a shared L2 segment. Each side
installs:

- One **outbound SA** (egress encrypt) — keyed `(src=us, dst=them, spi)`.
- One **outbound SP** (egress policy) — selector matches their
  subnet; template references the outbound SA.
- One **inbound SA** (ingress decrypt) — keyed `(src=them, dst=us, spi')`.
- One **inbound SP** (ingress policy) — selector matches our
  subnet from their direction.

```
                bridge-ipsec
                     │
       ┌─────────────┼─────────────┐
       │                           │
   ns site-a                   ns site-b
   10.50.0.1/24                10.50.0.2/24
   ESP-tunnel  ──── encap ──── ESP-tunnel
                     │
                     ▼
              kernel xfrm tables:
              SA(src=A, dst=B, spi=0xAABB)  ← egress on A, ingress on B
              SA(src=B, dst=A, spi=0xCCDD)  ← egress on B, ingress on A
```

SPI uniqueness: the `(daddr, spi, proto)` triple must be unique
within a kernel namespace. Pick distinct SPIs per direction.

## Code: install both ends

```rust
use std::net::IpAddr;

use nlink::lab::{LabNamespace, with_namespace};
use nlink::netlink::xfrm::{
    IpsecProtocol, PolicyDirection, XfrmMode, XfrmSaBuilder, XfrmSelector,
    XfrmSpBuilder, XfrmUserTmpl,
};
use nlink::netlink::{Connection, Xfrm};

const SPI_A_TO_B: u32 = 0x0000_AABB;
const SPI_B_TO_A: u32 = 0x0000_CCDD;
const REQID: u32 = 42;

// 32-byte test keys — DO NOT SHIP REAL DEPLOYMENTS WITH STATIC KEYS.
// Real code derives keys via IKE / KEX / out-of-band exchange.
const AUTH_KEY: [u8; 32] = [0u8; 32];
const ENCR_KEY: [u8; 16] = [0u8; 16];

async fn install_site(
    site_addr: IpAddr,    // this site's IP
    peer_addr: IpAddr,    // other side's IP
    out_spi: u32,         // SPI for traffic we send
    in_spi: u32,          // SPI for traffic we receive
) -> nlink::Result<()> {
    let conn = Connection::<Xfrm>::new()?;

    // Outbound SA: encrypt traffic we're sending to the peer.
    let sa_out = XfrmSaBuilder::new(site_addr, peer_addr, out_spi, IpsecProtocol::Esp)
        .mode(XfrmMode::Tunnel)
        .reqid(REQID)
        .auth_hmac_sha256(&AUTH_KEY)
        .encr_aes_cbc(&ENCR_KEY);
    conn.add_sa(sa_out).await?;

    // Inbound SA: decrypt traffic from the peer.
    let sa_in = XfrmSaBuilder::new(peer_addr, site_addr, in_spi, IpsecProtocol::Esp)
        .mode(XfrmMode::Tunnel)
        .reqid(REQID)
        .auth_hmac_sha256(&AUTH_KEY)
        .encr_aes_cbc(&ENCR_KEY);
    conn.add_sa(sa_in).await?;

    // Outbound SP: any traffic from us to peer's subnet → encrypt
    // via the outbound SA template.
    let sp_out = XfrmSpBuilder::new(
        XfrmSelector { family: libc::AF_INET as u16, ..Default::default() },
        PolicyDirection::Out,
    )
    .priority(100)
    .template(XfrmUserTmpl::match_any(
        site_addr, peer_addr, IpsecProtocol::Esp, XfrmMode::Tunnel, REQID,
    ));
    conn.add_sp(sp_out).await?;

    // Inbound SP: any traffic from peer's subnet to us → expect to
    // be decrypted via the inbound SA template.
    let sp_in = XfrmSpBuilder::new(
        XfrmSelector { family: libc::AF_INET as u16, ..Default::default() },
        PolicyDirection::In,
    )
    .priority(100)
    .template(XfrmUserTmpl::match_any(
        peer_addr, site_addr, IpsecProtocol::Esp, XfrmMode::Tunnel, REQID,
    ));
    conn.add_sp(sp_in).await?;

    Ok(())
}

# async fn example() -> nlink::Result<()> {
let site_a: IpAddr = "10.50.0.1".parse().unwrap();
let site_b: IpAddr = "10.50.0.2".parse().unwrap();

with_namespace("ipsec-a", |_ns_a| async move {
    install_site(site_a, site_b, SPI_A_TO_B, SPI_B_TO_A).await
})
.await?;
with_namespace("ipsec-b", |_ns_b| async move {
    install_site(site_b, site_a, SPI_B_TO_A, SPI_A_TO_B).await
})
.await?;
# Ok(())
# }
```

Note the per-namespace `Connection::<Xfrm>::new()`: SAs and SPs
live in the netns, not the host. The `LabNamespace` Drop deletes
the namespace and its XFRM tables on the way out.

## Verify

After the install, dump from inside either namespace:

```rust
let conn = Connection::<Xfrm>::new()?;
for sa in conn.get_security_associations().await? {
    println!("SA: spi=0x{:08x} reqid={} mode={:?}", sa.spi, sa.reqid, sa.mode);
}
for sp in conn.get_security_policies().await? {
    println!("SP: dir={:?} prio={} action={:?}", sp.direction, sp.priority, sp.action);
}
```

Or under sudo, use `ip xfrm state` / `ip xfrm policy` to see the
same tables.

## Key rotation

`update_sa` replaces an existing SA in place using the
`(daddr, spi, proto, family)` tuple as the lookup key. Useful
for rotating keys without a delete-then-add gap that would
leave traffic unprotected:

```rust
let rotated = XfrmSaBuilder::new(site_addr, peer_addr, out_spi, IpsecProtocol::Esp)
    .mode(XfrmMode::Tunnel)
    .reqid(REQID)
    .auth_hmac_sha256(&NEW_AUTH_KEY)
    .encr_aes_cbc(&NEW_ENCR_KEY);
conn.update_sa(rotated).await?;
```

For atomic key rotation across both peers, a real deployment
runs a brief overlap: stage the new SA + SP at a higher priority
on each side, then drain the old one. That choreography is
out of scope for this recipe.

## Caveats

### Keys

The example uses zero-byte keys for clarity. **A real deployment
must derive keys via IKE or an equivalent out-of-band exchange.**
Static keys in source code are a leaked-secret risk; in `.gitignore`
test fixtures they're an acceptable lab-only shortcut.

### Replay window

`XfrmSaBuilder::new` defaults to a replay window of **32 packets**
(matching `iproute2`'s `ip xfrm` default). The kernel default of
0 disables replay protection — surprising footgun. Override via
`.replay_window(N)` if your deployment needs a wider window
(WAN links, jittery paths).

### MTU

ESP encap adds ~30-50 bytes per packet (header + IV + ICV +
optional padding). Underlay MTU < 1500 starts shedding fragments.
Either lower the inner MTU on the tunnel endpoint or rely on
PMTUD; both are deployment decisions outside this recipe.

### NAT-T (UDP encapsulation)

If either peer is behind NAT, ESP-in-UDP encap is required.
Configure via `XfrmSaBuilder::nat_t_udp_encap(sport, dport)`
on both SAs. The builder picks the right encap_type based on
`dport` (4500 → IKE-compatible, anything else → non-IKE).

### Same-namespace dual install

Installing both ends in the **same** namespace (e.g. for a
loopback-style test) won't actually encrypt anything — the
kernel sees the local-loop traffic before XFRM hooks fire.
Use two namespaces or a real WAN link for a meaningful test.

## Lab smoke test

`examples/xfrm/ipsec_monitor.rs --apply` runs the lifecycle
end-to-end inside a `LabNamespace`:

```bash
sudo cargo run -p nlink --example xfrm_ipsec_monitor -- --apply
```

The runner installs SAs and SPs, dumps them back to verify they
landed, exercises `update_sa` for in-place key rotation, then
tears down via `del_sa` / `flush_sp`. Output shows each step's
SA / SP visibility — useful as a smoke test after kernel
upgrades or when bringing up a new lab box.

## See also

- `nlink::netlink::xfrm` — the typed write surface (`XfrmSaBuilder`,
  `XfrmSpBuilder`, `XfrmUserTmpl`, the 11 CRUD methods on
  `Connection<Xfrm>`).
- `examples/xfrm/ipsec_monitor.rs` — the dump + `--apply` runner.
- [`docs/recipes/conntrack-programmatic.md`](conntrack-programmatic.md)
  — the same shape (typed CRUD over a netlink subsystem) for
  conntrack.
- Linux `Documentation/networking/xfrm_*` and `man ip-xfrm` for
  the kernel-side concepts (XFRM state machine, selector
  precedence, lifetime accounting).

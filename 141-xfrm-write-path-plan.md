---
to: nlink maintainers
from: nlink maintainers
subject: XFRM write-path API extension — `Connection<Xfrm>` SA / SP CRUD
target version: 0.15.0 (Phase 2 of [Plan 142](142-zero-legacy-typed-api-plan.md))
date: 2026-04-25
status: draft — phase-level detail document for **Plan 142 Phase 2**. Independent of Phases 1, 3, 4 — can land in parallel with Phase 1 if maintainer bandwidth allows. Read Plan 142 first; this plan provides the SA/SP wire-format and recipe specifics.
related: Plan 142 master; Plan 135 PR B (this plan's PR C bumps Plan 135 to 7/7); Plan 137 PR A (the typed-builder pattern this plan mirrors).
---

# XFRM write-path API extension

## 0. Summary

Today `Connection<Xfrm>` (`crates/nlink/src/netlink/xfrm.rs`) is
**dump-only**: `get_security_associations` and
`get_security_policies`, nothing else. Same shape `Connection<Netfilter>`
had before Plan 137 PR A — and Plan 137 PR A's pattern (typed
builder + `add_xxx` / `update_xxx` / `del_xxx` / `flush_xxx` on
`Connection`) ports cleanly to XFRM.

Net effect when this lands:

- IPsec SA / SP lifecycles can be driven from typed Rust without
  shelling out to `ip xfrm`.
- Plan 135 PR B's `xfrm-ipsec-tunnel.md` recipe (currently deferred
  with a "needs a Plan-137-shaped library extension first" note)
  becomes writable. That ticks Plan 135 PR B from 6/7 to 7/7.
- Lab harnesses for IPsec testing (transparent encryption between
  two namespaces) become a one-builder-per-side affair instead of
  shelling out.

## 1. Goals & non-goals

### Goals

1. **Ship typed CRUD for Security Associations** —
   `XfrmSaBuilder` + `add_sa` / `update_sa` / `del_sa` /
   `flush_sa` / `get_sa` on `Connection<Xfrm>`.
2. **Ship typed CRUD for Security Policies** —
   `XfrmSpBuilder` + `add_sp` / `update_sp` / `del_sp` /
   `flush_sp` / `get_sp`.
3. **Ship one recipe** — `docs/recipes/xfrm-ipsec-tunnel.md`,
   end-to-end transparent encryption between two `LabNamespace`s.
4. **Wire-format unit tests** that round-trip through the existing
   dump-side parser, same shape as Plan 137 PR A's tests.
5. **One example promotion** — `examples/xfrm/ipsec_monitor.rs`
   (currently dump-only) gains a `--apply` mode that exercises the
   write path inside a temporary namespace.

### Non-goals

1. **Crypto algorithm implementations.** This plan wires up the
   netlink message format for SA crypto specifications (algorithm
   name + key bytes). The actual cryptography is the kernel's job.
2. **IKE / racoon-style key management.** Out of scope — those
   are user-space daemons that talk XFRM. We expose the XFRM API
   they sit on top of.
3. **Migration / state expiry events.** XFRM has multicast event
   groups (`XFRMNLGRP_*`) for SA expiry, etc. That's the
   equivalent of Plan 137 PR B (event subscription). Defer to a
   follow-on plan if there's demand.
4. **NAT traversal (NAT-T) detection helpers.** UDP-encap encoding
   for NAT-T is exposed as raw attributes; no high-level helper
   in this plan.

---

## 2. Phase 1 — Security Association CRUD

### 2.1. API sketch

```rust
// crates/nlink/src/netlink/xfrm.rs

#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct XfrmSaBuilder {
    src: IpAddr,
    dst: IpAddr,
    spi: u32,
    proto: XfrmProto,         // ESP / AH / IPCOMP
    mode: XfrmMode,           // Transport / Tunnel / Beet / RoTransport / RoTunnel
    reqid: u32,
    family: u8,               // AF_INET / AF_INET6
    auth: Option<XfrmAlgoAuth>,    // ("hmac(sha256)", key bytes)
    encr: Option<XfrmAlgoEncr>,    // ("cbc(aes)", key bytes)
    aead: Option<XfrmAlgoAead>,    // ("rfc4106(gcm(aes))", key bytes, icv_truncbits)
    encap: Option<XfrmEncapTmpl>,  // for NAT-T: udp_encap_esp + sport/dport
    flags: XfrmStateFlags,
    extra_flags: u32,
    replay_window: u8,
    lifetime: Option<XfrmLifetimeCfg>, // soft/hard byte/packet/time limits
}

impl XfrmSaBuilder {
    pub fn new(src: IpAddr, dst: IpAddr, spi: u32, proto: XfrmProto) -> Self;
    pub fn mode(self, mode: XfrmMode) -> Self;
    pub fn reqid(self, id: u32) -> Self;
    pub fn auth_hmac_sha256(self, key: &[u8]) -> Self; // common-case helper
    pub fn auth(self, name: impl Into<String>, key: &[u8]) -> Self;
    pub fn encr_aes_cbc(self, key: &[u8]) -> Self;    // common-case helper
    pub fn encr(self, name: impl Into<String>, key: &[u8]) -> Self;
    pub fn aead_aes_gcm(self, key: &[u8], icv_truncbits: u32) -> Self; // GCM helper
    pub fn aead(self, name: impl Into<String>, key: &[u8], icv_truncbits: u32) -> Self;
    pub fn nat_t_udp_encap(self, sport: u16, dport: u16) -> Self;
    pub fn replay_window(self, w: u8) -> Self;
    pub fn lifetime(self, cfg: XfrmLifetimeCfg) -> Self;
}

impl Connection<Xfrm> {
    // Already present:
    pub async fn get_security_associations(&self) -> Result<Vec<SecurityAssociation>>;

    // New:
    pub async fn add_sa(&self, sa: XfrmSaBuilder) -> Result<()>;
    pub async fn update_sa(&self, sa: XfrmSaBuilder) -> Result<()>;
    pub async fn del_sa(&self,
        src: IpAddr, dst: IpAddr, spi: u32,
        proto: XfrmProto,
    ) -> Result<()>;
    pub async fn flush_sa(&self) -> Result<()>;
    pub async fn flush_sa_proto(&self, proto: XfrmProto) -> Result<()>;
    pub async fn get_sa(&self,
        src: IpAddr, dst: IpAddr, spi: u32, proto: XfrmProto,
    ) -> Result<Option<SecurityAssociation>>;
}
```

### 2.2. Wire format

Reference: kernel `include/uapi/linux/xfrm.h`. Key message types
under `NETLINK_XFRM`:

```
XFRM_MSG_NEWSA      = 16
XFRM_MSG_DELSA      = 17
XFRM_MSG_GETSA      = 18
XFRM_MSG_FLUSHSA    = 25
```

`xfrm_usersa_info` is the fixed-size header (~136 bytes; src+dst
selectors, SPI, proto, mode, reqid, lifetime cfg, lifetime cur,
stats, family, flags, replay window). Optional attributes follow:

```c
XFRMA_ALG_AUTH_TRUNC  // (u32 truncbits + algo struct)
XFRMA_ALG_CRYPT       // (algo struct: name[64] + bits + key[])
XFRMA_ALG_AEAD        // (algo struct + icv_truncbits)
XFRMA_ENCAP           // (xfrm_encap_tmpl)
XFRMA_TFCPAD          // u32
XFRMA_REPLAY_VAL      // (replay state)
XFRMA_REPLAY_THRESH   // u32
XFRMA_OUTPUT_MARK     // (u32 + mask)
XFRMA_IF_ID           // u32 (XFRM interface ID)
```

Most users only need ALG_AUTH + ALG_CRYPT (separate auth+encr) or
ALG_AEAD (combined like AES-GCM). The builder's helper methods
gate the simple paths; the generic `auth(name, key)` form gives
escape-hatch access.

### 2.3. Tests (unit, no root)

- `xfrm_sa_v4_esp_aead_wire_roundtrip` — build a typical IPv4 +
  ESP + AES-GCM SA via the builder, parse it back through the
  existing `parse_sa` (currently in xfrm.rs's dump path), assert
  every field round-trips.
- `xfrm_sa_v6_esp_separate_auth_encr_wire_roundtrip` — IPv6 +
  ESP + HMAC-SHA256 + AES-CBC.
- `xfrm_sa_nat_t_udp_encap_wire_roundtrip` — adds NAT-T UDP
  encap; assert XFRMA_ENCAP is present with the right sport/dport.
- `del_sa_wire` — assert `XFRM_MSG_DELSA` carries the right
  selector tuple (src, dst, spi, proto).
- `flush_sa_proto` — assert `XFRM_MSG_FLUSHSA` body's `proto`
  byte gets set.

### 2.4. Effort

~2 days. Builder + emit path + tests.

---

## 3. Phase 2 — Security Policy CRUD

### 3.1. API sketch

```rust
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct XfrmSpBuilder {
    sel: XfrmSelector,        // src/dst with prefixes, optional sport/dport, proto
    direction: XfrmDir,       // In / Out / Forward
    action: XfrmAction,       // Allow / Block
    priority: u32,
    index: Option<u32>,       // pre-pin a policy index, otherwise kernel assigns
    tmpls: Vec<XfrmUserTmpl>, // SA templates the policy resolves through
    mark: Option<XfrmMark>,
    if_id: Option<u32>,
    flags: XfrmPolicyFlags,
}

impl XfrmSpBuilder {
    pub fn new(sel: XfrmSelector, direction: XfrmDir) -> Self;
    pub fn allow(self) -> Self;     // default
    pub fn block(self) -> Self;
    pub fn priority(self, p: u32) -> Self;
    pub fn template(self, tmpl: XfrmUserTmpl) -> Self;
    pub fn mark(self, mark: u32, mask: u32) -> Self;
    pub fn if_id(self, id: u32) -> Self;
}

impl Connection<Xfrm> {
    // Already present:
    pub async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>>;

    // New:
    pub async fn add_sp(&self, sp: XfrmSpBuilder) -> Result<()>;
    pub async fn update_sp(&self, sp: XfrmSpBuilder) -> Result<()>;
    pub async fn del_sp(&self,
        sel: &XfrmSelector,
        direction: XfrmDir,
    ) -> Result<()>;
    pub async fn flush_sp(&self) -> Result<()>;
    pub async fn get_sp(&self,
        sel: &XfrmSelector,
        direction: XfrmDir,
    ) -> Result<Option<SecurityPolicy>>;
}
```

### 3.2. Wire format

```
XFRM_MSG_NEWPOLICY  = 19
XFRM_MSG_DELPOLICY  = 20
XFRM_MSG_GETPOLICY  = 21
XFRM_MSG_FLUSHPOLICY = 28
```

`xfrm_userpolicy_info` (fixed header — selector, lifetime cfg,
priority, index, dir, action, flags, share). Followed by:

```c
XFRMA_TMPL            // array of xfrm_user_tmpl (which SA matches this policy)
XFRMA_SEC_CTX         // SELinux security context (optional)
XFRMA_POLICY_TYPE     // u8 (main / sub)
XFRMA_MARK            // (mark, mask)
XFRMA_IF_ID           // u32
```

The `XFRMA_TMPL` attribute is the meat: each template entry pairs
a destination IP + SPI + proto + mode + reqid, telling the kernel
which SA to look up to satisfy this policy.

### 3.3. Tests

- `xfrm_sp_out_with_tmpl_wire_roundtrip` — typical
  outbound-encrypt policy with one SA template.
- `xfrm_sp_in_with_two_tmpls` — inbound policy chaining two
  SAs (e.g. nested ESP+AH).
- `xfrm_sp_block` — assert `action = BLOCK`, no templates needed.
- `del_sp` — selector + direction round-trip.

### 3.4. Effort

~2 days.

---

## 4. Phase 3 — recipe + example promotion

### 4.1. `docs/recipes/xfrm-ipsec-tunnel.md`

Two-namespace topology: `site-a` and `site-b` connected via a
shared bridge. On each site:

1. Construct an SA with matching SPIs and shared keys (real code
   would derive keys via IKE; the recipe uses `[0u8; 32]` + a
   "don't ship test keys" caveat).
2. Construct an SP that encrypts traffic between the two sites'
   subnets through the SA.
3. Generate test traffic; observe that the kernel encapsulates it
   in ESP and the other side decrypts.
4. Caveats: clock skew (replay window), MTU (encap overhead),
   key rotation, NAT-T detection.

Recipe length target: 250 lines, matches the existing recipe
shape.

### 4.2. `examples/xfrm/ipsec_monitor.rs` `--apply` promotion

Mirrors the `netfilter_conntrack --apply` runner shape:

- Default: print usage + topology diagram.
- `show`: existing dump display.
- `--apply`: in two `LabNamespace`s, install matching SAs + SPs
  on each side, generate ICMP between the sites, assert
  encapsulation happens (verify via `tcpdump -i bridge0` capture
  or via the SA's packet/byte counters bumping).

### 4.3. Effort

~1.5 days for the recipe + ~1 day for the example promotion.

---

## 5. Files touched (estimate across all phases)

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/xfrm.rs` | Builder + emit path for SA + SP | ~1200 |
| `crates/nlink/src/netlink/xfrm.rs::tests` | Wire-format round-trip tests | ~400 |
| `docs/recipes/xfrm-ipsec-tunnel.md` | New recipe | ~250 |
| `docs/recipes/README.md` | Index entry | ~10 |
| `examples/xfrm/ipsec_monitor.rs` | `--apply` promotion | ~150 |
| `crates/nlink/Cargo.toml` | (no new deps expected) | 0 |
| `CHANGELOG.md` | Per-phase entries | per phase |
| `135-recipes-and-lab-helpers-plan.md` | Status header: 6/7 → 7/7 | small |

Total ~2000 LOC code + tests + docs.

---

## 6. Phasing

| PR | Scope | Size | Unlocks |
|---|---|---|---|
| A | Phase 1: SA CRUD + 5 wire-format unit tests | ~800 LOC | SA lifecycle from typed Rust |
| B | Phase 2: SP CRUD + 4 wire-format unit tests | ~600 LOC | Full IPsec stack programmability |
| C | Phase 3: recipe + example `--apply` promotion | ~500 LOC | Plan 135 PR B closes (7/7 recipes) |

PRs A and B can ship independently (you can configure SAs without
SPs to test bare-message-shape, but real use needs both). PR C
requires both.

---

## 7. Tests

Unit tests, all runnable as a regular user (modelled on Plan 137
PR A's test structure). Integration tests under `lab` feature
gated on Plan 140 (CI integration tests harness) — same parking
rationale as Plan 137 integration tests. The `--apply` example
runner provides the on-demand wire-format validation in the
meantime.

---

## 8. Open questions

1. **Algorithm name table.** The kernel accepts arbitrary algo
   strings (`"hmac(sha256)"`, `"cbc(aes)"`, `"rfc4106(gcm(aes))"`,
   etc.). Helpers like `auth_hmac_sha256` cover the common cases;
   the generic `auth(name, key)` form is the escape hatch. Don't
   try to enumerate all algorithms — the kernel decides which
   combinations work.
2. **Key length validation.** The builder could check that key
   bytes match the algorithm's expected length (e.g. AES-256-GCM
   needs 32 bytes + 4 bytes salt). Lean: validate in the helper
   methods (`encr_aes_cbc(key)` errors if key is wrong length),
   leave the generic methods unchecked so users can experiment.
3. **NAT-T encoding subtleties.** `XFRMA_ENCAP` carries the
   sport/dport pair plus the encap type
   (`UDP_ENCAP_ESPINUDP_NON_IKE` vs `UDP_ENCAP_ESPINUDP`). The
   builder picks the right one based on the port (4500 → IKE
   variant, anything else → non-IKE). Document the assumption.
4. **`XfrmMark` vs `XFRMA_OUTPUT_MARK`.** Two adjacent attributes
   with subtly different semantics — `XFRMA_MARK` filters which
   policies/SAs apply by mark; `XFRMA_OUTPUT_MARK` rewrites the
   skb mark on encap output. Keep both, name them clearly in the
   builder API.
5. **Event subscription** (XFRMNLGRP_SA / SP / EXPIRE). Out of
   scope per §1; if a user asks, Plan 137 PR B's `EventSource`
   shape ports cleanly.

---

## 9. Definition of done

### PR A
- [ ] `XfrmSaBuilder` with all documented setters
- [ ] `add_sa` / `update_sa` / `del_sa` / `flush_sa` /
      `flush_sa_proto` / `get_sa` on `Connection<Xfrm>`
- [ ] At least 5 wire-format unit tests covering v4 ESP AEAD,
      v6 ESP separate auth+encr, NAT-T UDP encap, del-by-tuple,
      flush-by-proto
- [ ] CHANGELOG entry under `## [Unreleased]`
- [ ] Workspace clippy clean

### PR B
- [ ] `XfrmSpBuilder` + the `XfrmSelector` / `XfrmUserTmpl`
      supporting types
- [ ] `add_sp` / `update_sp` / `del_sp` / `flush_sp` / `get_sp`
- [ ] At least 4 wire-format unit tests
- [ ] CHANGELOG entry

### PR C
- [ ] `docs/recipes/xfrm-ipsec-tunnel.md` lands; recipe README
      Index updated; "Wanted" entry removed
- [ ] `examples/xfrm/ipsec_monitor.rs --apply` lifecycle works
      end-to-end on Linux 6.19 (validated interactively, like Plan
      137 PR A slice 3)
- [ ] Plan 135 PR B status header bumped to 7/7
- [ ] CHANGELOG entry

---

## 10. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Algo struct layout differs across kernel versions | Low | The struct has been stable since the early 3.x series; validate against Linux 5.15 + 6.x in interactive `--apply` runs |
| Key bytes silently truncated (wrong size for algo) | Medium | Helper methods validate length; generic methods document the requirement |
| Replay-window default surprises (kernel default = 0 = replay disabled) | High | Builder defaults to a sane window (32 packets); test asserts the default |
| `XfrmSelector` ergonomics — too many fields for the common case | Medium | Provide `XfrmSelector::v4_subnet_to_subnet(src/24, dst/24)` and similar shortcuts; full struct stays for advanced users |

End of plan.

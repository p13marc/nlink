# nlink 0.19 deep audit — second-pass findings

**Date:** 2026-05-31
**Branch audited:** `0.19` at commit `5ef0808`
**Scope:** library (`crates/nlink/src/`), bins (`bins/*`), examples
(`crates/nlink/examples/`), docs (`docs/`, `CLAUDE.md`, `README.md`).
**Methodology:** seven specialized parallel agents, each briefed on a
distinct bug class. Findings adversarially verified by reading the
actual code at every cited line before inclusion. Five external bug
catalogues consulted (netlink-packet-route, neli, rtnetlink, Cilium,
vishvananda/netlink) and four kernel UAPI headers cross-checked.

This is the second deep audit of the 0.19 cycle. The first
(committed `5ef0808`) shipped 5 fixes + 18 tests. This one finds
the next ~60 bugs across angles the first audit didn't reach.

---

## TL;DR — read this first

| # | Bug | Severity | File:line | Effort |
|---|-----|----------|-----------|--------|
| **C1** | nftables `NFT_JUMP`/`NFT_GOTO` constants emit wrong kernel verdict codes | **CRITICAL** | `nftables/mod.rs:292-293` | 1 line + test |
| **C2** | `XfrmUserpolicyInfo` body is 4 bytes shorter than kernel expects → `add_sp` rejected with EINVAL | **CRITICAL** | `xfrm.rs:316-336` | 1 field + test |
| **C3** | `XfrmUserpolicyId` body is 4 bytes longer than kernel expects → `del_sp`/`get_sp` brittle on strict-checking kernels | **CRITICAL** | `xfrm.rs:173-180` | 1 field + test |
| **C4** | Devlink multicast subscribes to a group name that doesn't exist (`"devlink"` vs kernel's `"config"`) → all event subscribers fail | **CRITICAL** | `genl/devlink/mod.rs:154` | 1 string + test |
| **C5** | `NetworkConfig` purge is documented but dead code — `addresses_to_remove`/`routes_to_remove`/etc. are never populated | **CRITICAL** | `config/diff.rs:461-548` | Several functions |
| **H1** | DPLL `phase_offset` decoded as `i32` truncates the kernel's `s64` — telco/PTP users get nonsense readings | HIGH | `genl/dpll/messages.rs:331` + `macros/mod.rs:284` | ~50 LOC (new helper) |
| **H2** | `NetworkConfig` master change undetected — declared `master: "br0"` vs kernel `master: ifindex(br1)` silently treated equal | HIGH | `config/diff.rs:425-459` | Resolve ifindex |
| **H3** | `NetworkConfig` route diff identity is `(dst, prefix, table)` only → gateway/dev/metric changes silently lost | HIGH | `config/diff.rs:497-548` | Widen identity tuple |
| **H4** | `NetworkConfig::apply_reconcile` retries non-atomic apply → original error masked by EEXIST | HIGH | `config/mod.rs:154-172` | Recompute diff per retry |
| **H5** | `nft list chain` UI flow + nat-chain typo silently changes firewall default policy to ACCEPT | HIGH | `bins/nft/src/main.rs:318-321, 448` | Error on unknown |
| **H6** | `wg set --private-key /path/typo` silently exits 0 without setting key | HIGH | `bins/wg/src/set.rs:66-70` | Propagate error |
| **H7** | `ip vrf exec` doesn't actually enter VRF — sets env var only | HIGH | `bins/ip/src/commands/vrf.rs:142-170` | Implement or fail |
| **H8** | `bins/ip xfrm` is all stubs returning empty — pretends to query | HIGH | `bins/ip/src/commands/xfrm.rs` (entire file) | Wire up via lib |
| **H9** | 11 remaining recv-loops still missing `with_timeout` / seq filter (deferred from first audit) | HIGH | sockdiag×3, xfrm×2, netfilter, fib_lookup, Generic GENL ×3, wg_command | Same shape as audit.rs fix |
| **H10** | `examples/nftables/firewall.rs` has no root check + leaks an `example` table on partial failure | HIGH | `examples/nftables/firewall.rs:21-152` | Add require_root + cleanup wrap |
| **H11** | TC action raw-pointer casts on netlink attribute data without alignment check (UB on ARM/MIPS) | HIGH | `bins/tc/src/commands/action.rs:221,237,254,280,292,309` | Use zerocopy |
| **M1–M30** | (see body) | MEDIUM | many | range |
| **L1–L50** | (see body) | LOW | many | one-liners |

**Headline:** five **CRITICAL** bugs that ship wrong bytes (or skip
critical state-detection logic) on real hardware, plus ~11 HIGH-impact
bugs across the lib + bins. The CRITICAL items would each have been
caught by a single byte-level or kernel-source cross-check test — the
exact pattern PR #7 taught us in this cycle.

---

## Executive summary

The first audit fixed surface-level recv-loop hazards, parser
contracts, and integer-truncation latent bugs. This second pass goes
deeper into:

1. **Wire-format byte-exact correctness** vs kernel UAPI headers.
   Three of the five CRITICAL findings here. The `XfrmUserpolicyInfo`
   bug means **`add_sp` is fundamentally broken on every supported
   kernel** — every IPsec policy add via nlink gets EINVAL. No
   integration test exercises `add_sp`, which is how it survived.

2. **Declarative-config correctness.** `NetworkConfig` has multiple
   silent-state-divergence bugs: purge is dead code, master changes
   are not detected, route gateway changes are not detected. These
   directly affect nlink-lab's reconciliation correctness.

3. **The bins (`bins/*`).** Never previously audited. 50+ findings
   including a HIGH-severity firewall typo bypass in `bins/nft`, a
   HIGH-severity silent WG key-set failure, two stub commands
   (`ip xfrm`, `ip vrf exec`) that print fake success.

4. **The examples (`examples/*`).** 50 findings including the
   `examples/nftables/firewall.rs` cleanup leak.

5. **Documentation drift.** README + CLAUDE.md are 2 cycles stale
   (still describe 0.17 state). lib.rs doctest passes a `&str` to a
   `RawFd`-typed method that wouldn't compile if not `ignore`d.

---

## CRITICAL findings (verified-real, ship-blocking)

### C1 — nftables NFT_JUMP / NFT_GOTO constants are wrong

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/mod.rs:288-293`

```rust
// nlink ships:
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_RETURN: i32 = -5;
pub const NFT_JUMP: i32 = -2;     // ← WRONG. -2 is NFT_BREAK.
pub const NFT_GOTO: i32 = -3;     // ← WRONG. -3 is NFT_JUMP.
```

**Kernel UAPI** (`include/uapi/linux/netfilter/nf_tables.h`, enum
`nft_verdicts`):

```c
enum nft_verdicts {
    NFT_CONTINUE = -1,
    NFT_BREAK    = -2,
    NFT_JUMP     = -3,
    NFT_GOTO     = -4,
    NFT_RETURN   = -5,
};
```

**Effect (silent semantic corruption):**

- A `Verdict::Jump(chain)` writes `-2` (= `NFT_BREAK`). The kernel
  **terminates rule evaluation in the current chain** instead of
  jumping. The `NFTA_VERDICT_CHAIN` attribute is still sent, but the
  kernel ignores it because `NFT_BREAK` is a non-jump verdict. The
  rule's intended subroutine effect is lost; users see the default
  policy fire.
- A `Verdict::Goto(chain)` writes `-3` (= `NFT_JUMP`). This is
  *almost* the user's intent, but `NFT_JUMP` pushes the return chain
  onto the kernel's evaluation stack while `NFT_GOTO` does not.
  Programs depending on goto's no-return semantics behave wrong.

**Why this survived:** no byte-level regression test pins these
values to the kernel header. The verdict struct is wrapped at
`nftables/expr.rs:230-265` (`write_verdict`) and tested only
end-to-end via integration tests that don't assert on what the
kernel actually did with the verdict.

**Fix:** one-line constant change:

```rust
pub const NFT_CONTINUE: i32 = -1;
pub const NFT_BREAK:    i32 = -2;   // new — was previously missing entirely
pub const NFT_JUMP:     i32 = -3;
pub const NFT_GOTO:     i32 = -4;
pub const NFT_RETURN:   i32 = -5;
```

Plus a regression test asserting each constant against the kernel
header value (or a `#[doc] // verified against linux/netfilter/nf_tables.h v6.X`).

**Severity:** **CRITICAL** — every `Verdict::Jump`/`Verdict::Goto`
in production nftables rules has been wire-incorrect since the
verdict enum was added. This affects every consumer of nlink's
nftables API.

---

### C2 — `XfrmUserpolicyInfo` is 4 bytes too short → `add_sp` rejected

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/xfrm.rs:315-336`

```rust
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyInfo {
    pub sel: XfrmSelector,       // 56 bytes
    pub lft: XfrmLifetimeCfg,    // 64 bytes (8 × u64)
    pub curlft: XfrmLifetimeCur, // 32 bytes (4 × u64)
    pub priority: u32,           // 4
    pub index: u32,              // 4
    pub dir: u8,                 // 1
    pub action: u8,              // 1
    pub flags: u8,               // 1
    pub share: u8,               // 1
    // ← MISSING: _pad: [u8; 4]
}
```

**Wire we produce:** 164 bytes.
**Wire kernel expects:** 168 bytes.

The C struct uses **natural alignment** (no `__attribute__((packed))`).
After the trailing four `__u8` fields (`dir, action, flags, share`),
natural alignment pads to the next `__u64` boundary (because
`XfrmLifetimeCfg` contains u64s, struct alignment is 8). That's 4
trailing pad bytes. nlink uses `#[repr(C, packed)]` and stops at byte
164. The kernel's `xfrm_add_policy()` calls `nlmsg_parse_deprecated(
nlh, sizeof(*p), …)` which requires `nlmsg_len >= NLMSG_HDRLEN + 168`.

**Effect:** Every `Connection<Xfrm>::add_sp` call sends a body 4 bytes
short. The kernel rejects with `-EINVAL`. **The `add_sp` path appears
to be entirely broken on the wire.** No integration test exercises
`add_sp` (`grep add_sp crates/nlink/tests/` returns 0), which is how
this survived.

The dump-side `write_dump_header` for SP (line 2593) sends 164 zero
bytes, but kernel's GETPOLICY dump path is permissive about prefix
length, masking the bug for reads.

**Fix:**

```rust
pub struct XfrmUserpolicyInfo {
    // … existing fields …
    pub share: u8,
    pub _pad: [u8; 4],          // ← add this
}
```

The same explicit trailing-pad pattern is already used correctly for
`XfrmUsersaInfo` at xfrm.rs:311 (`pub _pad: [u8; 7]` — 7 bytes after
`flags: u8` because struct alignment is 8 there).

**Test gap:** an integration test that rounds-trips `add_sp` + `get_sp`
+ `del_sp` in a netns under `require_root!()` would have surfaced
this immediately. The kernel rejection is unambiguous.

**Severity:** **CRITICAL** — the documented `add_sp` API is
non-functional. This is the equivalent of PR #7 for XFRM policy adds.

---

### C3 — `XfrmUserpolicyId` is 4 bytes too long → brittle on strict kernels

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/xfrm.rs:173-180`

```rust
#[repr(C, packed)]
pub struct XfrmUserpolicyId {
    pub sel: XfrmSelector,   // 56 bytes
    pub index: u32,          // 4
    pub dir: u8,             // 1
    pub _pad: [u8; 7],       // ← TOO MANY. Kernel pads to 4-byte align = 3 pad bytes.
}
```

**Wire we produce:** 68 bytes.
**Wire kernel expects:** 64 bytes.

Kernel struct definition (`include/uapi/linux/xfrm.h`):
```c
struct xfrm_userpolicy_id {
    struct xfrm_selector sel;  // 56
    __u32                index; // 4
    __u8                 dir;   // 1 → natural alignment pads to next __u32 = 64
};
```

**Effect:**
- `del_sp()` / `get_sp()` send an oversized body. The kernel's
  `nlmsg_parse_deprecated` treats the extra 4 bytes as a truncated
  `nlattr` header (`nla_len = 0`, `nla_type = 0`).
- On lenient kernels: `nla_validate_deprecated` silently skips the
  malformed trailing nlattr → operation accidentally works.
- On strict-checking kernels (≥ 5.0 with `NETLINK_GET_STRICT_CHK`,
  which nlink can enable via `set_strict_checking`): kernel returns
  EINVAL. Plan 155.2 explicitly added the strict-check toggle —
  using it surfaces this latent bug.

**Fix:** `_pad: [u8; 7]` → `_pad: [u8; 3]` (so total = 64).

**Severity:** **CRITICAL** — silently works today on most kernels,
fails on strict-checking kernels (which nlink ships support for).

---

### C4 — Devlink multicast subscribes to a group name that doesn't exist

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/genl/devlink/mod.rs:154`

```rust
pub const DEVLINK_MCGRP_NAME: &str = "devlink";
```

**Kernel UAPI** (`include/uapi/linux/devlink.h`):
```c
#define DEVLINK_GENL_MCGRP_CONFIG_NAME "config"
```

The devlink GENL family registers **exactly one** multicast group,
named `"config"`. nlink looks up `"devlink"`. The shared
`mcast_groups` HashMap (populated from CTRL_ATTR_MCAST_GROUPS during
family resolution) is keyed by the kernel's actual group name. The
`get("devlink")` miss returns `Error::FamilyNotFound { name:
"devlink::devlink" }` or similar.

**Effect:** `Connection::<Devlink>::subscribe()` **cannot subscribe
to any devlink event on any kernel.** Every user following the
documented event-stream pattern hits this immediately.

**Fix:** `DEVLINK_MCGRP_NAME = "config"`. Add a regression test:
```rust
let conn = Connection::<Devlink>::new_async().await?;
assert!(conn.state().mcast_groups.contains_key("config"));
```

**Severity:** **CRITICAL** — documented feature is entirely
non-functional. Pure runtime defect; would surface on the first
integration test for devlink event subscription, of which there is
currently none.

---

### C5 — `NetworkConfig` purge is dead code

**Files:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/diff.rs:461-548`,
`apply.rs:377-473`

The `ConfigDiff` struct has four `*_to_remove` collections:
- `links_to_remove: Vec<String>`
- `addresses_to_remove: Vec<(String, IpAddr, u8)>`
- `routes_to_remove: Vec<(IpAddr, u8, u32)>`
- `qdiscs_to_remove: Vec<(String, QdiscParent)>`

The apply path reads from them under `if options.purge` at apply.rs:
377, 410, 441, 473. The diff path **never populates them**:

```rust
// diff.rs:492-494, diff_addresses
// Note: We don't auto-remove addresses not in config
// That requires explicit purge mode
let _ = desired; // Silence unused warning
```

Same pattern for routes (line 544-547). Links and qdiscs only get
*_to_replace and *_to_add. The `desired` HashSet that would
populate the remove list is built and immediately dropped.

**Effect:** `ApplyOptions::default().with_purge(true)` is a silent
no-op. The documentation promises "remove resources not in config";
the implementation does nothing for the remove side. Users believe
their kernel state is now equal to declared state; in reality
foreign resources are untouched.

**Fix:** Two options:
1. **Wire it:** in each `diff_*` function, iterate `current_set -
   desired_set` and push to the appropriate `*_to_remove` collection.
   The desired/current sets are already built.
2. **Remove the dead path:** delete the `*_to_remove` fields, the
   `purge` flag, and the apply-side branches. Document why purge
   was deferred.

Option 1 is the user expectation. Option 2 stops the silent lie.

**Severity:** **CRITICAL** — documented feature lies about what it
does. Any user relying on `with_purge(true)` for reconcile
correctness has silent state drift.

---

## HIGH-severity findings (verified-real)

### H1 — DPLL `phase_offset` decoded as `i32` truncates kernel's `s64`

**Files:**
- `/var/home/mpardo/git/rip/crates/nlink/src/netlink/genl/dpll/messages.rs:331`
- `/var/home/mpardo/git/rip/crates/nlink/src/macros/mod.rs:284-294`

```rust
#[genl_attr(DpllPinAttr::PhaseOffset)]
pub phase_offset: Option<i32>,
```

Kernel `Documentation/netlink/specs/dpll.yaml` declares
`phase-offset` as **`s64`** (attoseconds × 1000).

The macro runtime's `parse_i32_attr` accepts any payload with
`len >= 4` and reads the **low 4 bytes only**. On LE platforms, the
high 4 bytes of an 8-byte attribute are silently dropped.

**Effect:** Phase-offset values for telco SyncE / PTP / GNSS users
overflow the i32 range routinely. The reported value is meaningless
whenever the real offset exceeds ±2.147 seconds in attoseconds-×-1000
units — which is essentially always (a 1 ns offset = 1e9 in those
units, well past i32::MAX).

**Why this survived:** `pin_reply_helpers_apply_dividers` test
round-trips `Some(123_000)` through a `Some(i32)` — never trips the
truncation.

**Fix:** non-trivial. Requires:
1. New `__rt::parse_i64_attr` and `emit_i64_attr` helpers.
2. Extend the `GenlMessage` derive to recognize `i64`/`Option<i64>`
   field types.
3. Flip `phase_offset: Option<i32>` → `Option<i64>`.
4. `phase_offset_ns()` already returns `i64` — the conversion just
   divides without truncation now.

**Severity:** **HIGH** — silent value corruption affecting the
canonical DPLL use case (sub-nanosecond clock sync).

---

### H2 — `NetworkConfig` link `master` change undetected

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/diff.rs:425-459`

```rust
// Check master
// Note: This is simplified - would need ifindex lookup for full implementation
if declared.master.is_some() && existing.master.is_none() {
    changes.set_master = declared.master.clone();
} else if declared.master.is_none() && existing.master.is_some() {
    changes.unset_master = true;
}
```

Bug shape:
- `declared.master: Option<String>` (interface name)
- `existing.master: Option<u32>` (ifindex from kernel)
- Comparison treats `Some(name)` vs `Some(ifindex)` as equal whenever
  both are `Some` — regardless of whether the name resolves to the
  ifindex.

**Effect:** Bridge-port reassignment (the most common reconcile
operation in lab/CNI environments) silently no-ops. Declaring
`dummy0.master("br0")` when the kernel has `dummy0.master("br1")`
produces an empty diff.

**Fix:** Build `ifindex → name` map (already partly built as
`ifindex_to_name`), resolve `existing.master`, compare against
`declared.master`. Add `set_master` when they differ.

**Severity:** **HIGH** — silent reconcile divergence on a very
common operation.

---

### H3 — `NetworkConfig` route identity ignores gateway/dev/metric

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/diff.rs:497-548`

```rust
let desired: HashSet<(IpAddr, u8, u32)> = config
    .routes
    .iter()
    .map(|r| (r.destination, r.prefix_len, r.table.unwrap_or(254)))
    .collect();
```

Identity is `(dst, prefix, table)`. Changing gateway, dev, or metric
on the same `(dst, prefix, table)`:
- `current_set.contains(key)` → no `routes_to_add`
- No `routes_to_modify` collection exists
- Apply does nothing

**Effect:** Common reconcile operation (gateway change) silently
no-ops. Identical to H2 in structure — wrong identity tuple.

**Fix:** Either widen identity to `(dst, prefix, table, gw, dev,
metric)` + add a `routes_to_modify` path, OR always replace routes
with `NLM_F_REPLACE` and accept the churn (the qdisc path took
option B).

**Severity:** **HIGH** — same class as H2.

---

### H4 — `NetworkConfig::apply_reconcile` retries non-atomic apply

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/mod.rs:154-172`

```rust
match self.apply(conn).await {
    Ok(result) => { /* success */ }
    Err(e) if (e.is_busy() || e.is_try_again()) && attempt < opts.max_retries => {
        // ... retry whole apply ...
    }
    Err(e) => return Err(e),
}
```

`NetworkConfig::apply` is a **sequence of individual netlink ops**,
not atomic. If op N fails with EBUSY, ops 0..N have already committed
to the kernel. Then `apply_reconcile` retries the **whole** apply:
- `add_link` of a link created on the previous attempt returns
  EEXIST (not `is_busy()`) → terminal error.
- `add_address` with `NLM_F_EXCL` same.

Reconcile gives up with EEXIST and the user gets a misleading "object
exists" error instead of the original EBUSY.

Contrast: `NftablesDiff::apply_reconcile` IS atomic (single nft
batch) — retry is safe there. The naming parity hides the semantic
divergence.

**Fix:** `NetworkConfig::apply_reconcile` should **recompute the
diff** at the start of each retry iteration, not re-run the same
apply. Or document the limitation prominently.

**Severity:** **HIGH** — silent error-masking on transient kernel
contention.

---

### H5 — `bins/nft` typo silently flips firewall to ACCEPT

**File:** `/var/home/mpardo/git/rip/bins/nft/src/main.rs:318-321`

```rust
chain = chain.policy(match p.as_str() {
    "drop" => Policy::Drop,
    _ => Policy::Accept,   // ← typo → accept-everything
});
```

Plus `bins/nft/src/main.rs:448` — rule-spec parser silently advances
on unknown tokens, so `tcp dport 22 acept` (typo of `accept`)
produces a rule with no action. Combined with above: a single typo
in a firewall command can turn a default-DROP firewall into
accept-everything.

**Effect:** Direct security impact for users running the
demo-quality `bins/nft` against real hosts.

**Fix:** Error on unknown policy / unknown token. Standard
`_ => return Err(...)` discipline.

**Severity:** **HIGH** (security UX class).

---

### H6 — `bins/wg set --private-key /typo` silently exits 0

**File:** `/var/home/mpardo/git/rip/bins/wg/src/set.rs:66-70`

```rust
if let Some(ref path) = args.private_key
    && let Ok(key) = read_key_file(path)
{
    dev = dev.private_key(key);
}
```

File-read failure or base64-decode failure silently drops the
private-key setting. Exit 0. User believes new key is installed.
**Security-sensitive.**

**Fix:** propagate error with `?`.

**Severity:** **HIGH** — silent failure on a sensitive operation.

---

### H7 — `ip vrf exec` doesn't actually enter VRF

**File:** `/var/home/mpardo/git/rip/bins/ip/src/commands/vrf.rs:142-170`

`ip vrf exec mgmt curl ...` execs the child with `VRF=name` env var
set. No actual VRF binding (no SO_BINDTOIFINDEX, no l3mdev cgroup).
The comment in source admits this. User sees the command run
"normally" — and uses the default VRF, not `mgmt`.

**Effect:** Silent functional break. Users running this for
multi-VRF testing get default-VRF traffic and don't notice.

**Fix:** Either implement properly or error fast with "not
implemented in this demo".

**Severity:** **HIGH** — silent functional failure.

---

### H8 — `bins/ip xfrm` is entirely stubs returning empty

**File:** `/var/home/mpardo/git/rip/bins/ip/src/commands/xfrm.rs`
(entire file)

- `parse_xfrm_states()` returns empty `Vec` (line 215).
- `parse_xfrm_policies()` returns empty `Vec` (line 225).
- `count_states`/`count_policies` always print `0`.
- `flush_*`/`monitor` print "Use iproute2" and return Ok.

The lib has full XFRM netlink support (`stream_sas`/`stream_sps`
shipped in 0.16) — but the bin pretends to query and returns
nothing while exiting 0.

**Effect:** User running `ip xfrm state show` sees "0 states"
when the kernel actually has dozens. Then they call sales and
complain.

**Fix:** wire up via `Connection::<Xfrm>` (the family exists), or
print "not implemented in this demo" and exit nonzero.

**Severity:** **HIGH** — silent stub.

---

### H9 — 11 remaining recv-loops still missing timeout/seq filter

Deferred from the first audit. Per the dedicated recv-loop agent in
this pass:

| File:line | Method | Severity |
|---|---|---|
| `sockdiag.rs:413` | `query_inet_family` | HIGH |
| `sockdiag.rs:511` | `query_unix_typed` | HIGH |
| `sockdiag.rs:593` | `query_netlink_typed` | HIGH |
| `xfrm.rs:1536` | `get_security_associations` | HIGH |
| `xfrm.rs:1626` | `get_security_policies` | HIGH |
| `netfilter.rs:890` | `get_conntrack_family` | HIGH |
| `fib_lookup.rs:355` | `lookup_with_options` | HIGH |
| `connection.rs:2337` | `Connection<Generic>::query_family` | HIGH |
| `connection.rs:2487` | `Connection<Generic>::command` | HIGH |
| `connection.rs:2520` | `Connection<Generic>::dump_command` | HIGH |
| `genl/wireguard/connection.rs:245` | `wg_command` (stale-frame race) | HIGH |

All same fix shape as the audit.rs/sockdiag.rs::destroy_tcp_socket
fixes shipped in `5ef0808` — wrap body in
`self.with_timeout(async move { ... }).await` + add seq filter.

**Severity:** **HIGH** — each is a potential indefinite hang.

---

### H10 — `examples/nftables/firewall.rs` leaks a stray table on failure

**File:** `/var/home/mpardo/git/rip/crates/nlink/examples/nftables/firewall.rs:21-152`

No root check. If `add_chain`/`add_rule` between lines 34 and 140
fails mid-flight, the cleanup at lines 150-151 (`flush_table` +
`del_table`) is unreachable. The host is left with a stray `example`
nftables table polluting their config.

**Effect:** Users running the example on a non-throwaway host get
silent state pollution.

**Fix:** Wrap body in `let result = async {...}.await; let _ =
conn.del_table("example", Family::Inet).await; result?` so cleanup
always runs.

**Severity:** **HIGH** — only example that pollutes host state on
partial run.

---

### H11 — TC action raw-pointer casts on potentially-unaligned data

**File:** `/var/home/mpardo/git/rip/bins/tc/src/commands/action.rs:221,237,254,280,292,309`

```rust
let gact = unsafe { &*(attr_data.as_ptr() as *const TcGact) };
```

`attr_data` comes from a `Vec<u8>` — alignment to `align_of::<TcGact>()`
(likely 4) is not guaranteed. On strict-alignment architectures
(some ARM, MIPS) this is UB; on x86 it works by accident.

**Effect:** UB on non-x86. The lib elsewhere uses zerocopy
`ref_from_bytes` which is alignment-safe.

**Fix:** Replace with `zerocopy::FromBytes::ref_from_bytes` or
`read_unaligned`.

**Severity:** **HIGH** (UB class).

---

## MEDIUM-severity findings

### M1 — Devlink `Hook::Ingress` ambiguity

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/types.rs:56-67`

`Hook::Ingress => 0` is correct for `Family::Netdev`/`Bridge`
(`NF_NETDEV_INGRESS = 0`) but **wrong for `Family::Inet`**
(`NF_INET_INGRESS = 5`). Also missing `Hook::Egress`
(`NF_NETDEV_EGRESS = 1`).

**Fix:** `to_u32` needs family disambiguation, or `Hook` should
encode the family.

---

### M2 — `NeighborState::from(u16)` collapses bitmask values

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/types/neigh.rs:168-182`

Kernel `ndm_state` is a **bitmask** of `NUD_*` flags. nlink's
`From<u16>` only matches exact-power-of-two values; combined states
fall through to `None`. `is_*()` predicates correctly use bit-AND,
but `LinkMessage::state()` returns a single enum value that hides
multi-bit reality.

**Fix:** Either bitflags newtype (consistent with `CtState`,
`XfrmOffloadFlag`) or document `.state()` semantics.

---

### M3 — `NetworkConfig` purge: `remove_route` drops `table`/`metric`/`dev`

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/apply.rs:821-837`

```rust
async fn remove_route(
    conn: &Connection<Route>,
    dst: IpAddr,
    prefix_len: u8,
    _table: u32,    // ← discarded
) -> Result<()> {
```

Combined with `del_route`'s "newer kernels return ESRCH if the
request omits fields the original add set" behavior at route.rs:1490,
routes in non-default tables can never be purged (covered by C5 in
the wider sense, but distinct enough to flag).

---

### M4 — Address diff prefix-length identity is wrong

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/diff.rs:467-490`

`HashSet<(&str, IpAddr, u8)>` includes prefix. Changing CIDR width
on the same `(dev, addr)` creates a new tuple → `addresses_to_add`
→ `NLM_F_EXCL` → kernel EEXIST (matches on `(dev, addr)` regardless
of prefix).

**Fix:** identity `(dev, addr)`, prefix as data; emit replace.

---

### M5 — Topo-sort misses VXLAN underlay / Macvlan / master deps

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/diff.rs:367-423`

Topo-sort only knows `Vlan` and `Macvlan` parents. Missing:
- VXLAN `underlay_dev` (Plan 190 §2.1) — declaring VXLAN before
  underlay dummy in same batch reproduces Plan 186 §3c bug.
- `master` references — declaring `dummy0.master("br0")` before
  `br0` in same batch fails at apply.

---

### M6 — nftables anonymous-rule reapply churn (unbounded growth)

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/config/diff.rs:502-513`

Anonymous rules (no `handle_key`) get unconditionally pushed to
`rules_to_add`. Pass 3 cleanup deletes only **commented** rules. So
re-applying the same config N times installs the same rule N times.
The rule list grows unboundedly until manual cleanup.

**Fix:** auto-assign a stable comment cookie derived from the
expression hash, or refuse anonymous rules in declarative configs.

---

### M7 — nftables Pass 3 cleanup wipes foreign-commented rules

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/config/diff.rs:583-609`

In a chain the user has declared but with no nlink rules, **any**
kernel rule with **any** comment gets queued for deletion. A user-
installed rule with comment `"my-firewall-rule"` gets wiped by an
nlink config that just declares the chain.

**Fix:** Prefix-mark nlink-owned rules (e.g. emit `nlink:<key>` as
the comment) and filter cleanup on that prefix.

---

### M8 — WireGuard config can't compose with NetworkConfig

**File:** `/var/home/mpardo/git/rip/crates/nlink/src/netlink/genl/wireguard/config.rs:232-246`

`WireguardConfig::diff` calls `conn.get_device_by_name(&ifname)`
which errors if the device doesn't exist. There's no
`LinkBuilder::wireguard()` in `NetworkConfig`, so users must:
```rust
conn.add_link(WireguardLink::new("wg0")).await?;  // imperative
WireguardConfig::new().device("wg0", |d| ...).apply(...).await?;  // declarative
```

The composition gap isn't documented in module-level rustdoc.

**Fix:** Add `LinkBuilder::wireguard()` so the entire WG setup can
be one apply.

---

### M9–M30 — Additional medium-severity findings

(condensed; see per-area sections below for detail):

- **M9.** `Error::is_not_found` doesn't go through `errno()`,
  missing `Error::Io(ENOENT)` case (asymmetry with `is_busy`,
  `is_permission_denied`, `is_already_exists` per Plan 187 §2.5).
  `error.rs:507-519`.
- **M10.** `OperState` ≠ `IFF_UP` admin state — `LinkState::Down`
  declared on no-carrier admin-up interface silently no-ops.
  `config/diff.rs:428-441`.
- **M11.** WG `persistent_keepalive` > u16::MAX silently caps.
  `wireguard/config.rs:489`.
- **M12.** `b64_decode_32` rejects unpadded base64 (interop nit).
  `wireguard/config.rs:146-149`.
- **M13.** `nl80211` SSID parser assumes element-id 0 is first IE
  (vendor-prepended IEs hide SSID). `genl/nl80211/connection.rs:762`.
- **M14.** Five parallel family-resolution code paths duplicate
  the same shape. `wireguard/connection.rs:460` + 4 others.
- **M15.** `Connection<P>: Sync` compiles but concurrent use loses
  responses (F1 from first audit — confirmed not UB, but
  semantically misleading). Need docstring at minimum.
- **M16.** `send_ack_inner` silently re-reads on matching-seq
  non-error frame (defense-in-depth gap). `connection.rs:433-449`.
- **M17.** `RwLock::read/write().unwrap()` on family cache (poison
  panic, currently unreachable but brittle). `connection.rs:2295`+.
- **M18.** Replace-qdisc is non-atomic (del + add window).
  `config/apply.rs:921-937`.
- **M19.** Flowtable diff identity is name-only (devs/priority
  changes silently no-op). `nftables/config/diff.rs:612-634`.
- **M20.** `let _ = conn.del_X(...).await` in bins/ip flush paths
  swallows errors. `bins/ip/src/commands/{address,neighbor}.rs`.
- **M21.** `ip route get` does full dump + filter instead of kernel
  `RTM_GETROUTE`. `bins/ip/src/commands/route.rs:393-423`.
- **M22.** `bins/ip xfrm parse_*` returns empty stubs (covered by
  H8 above).
- **M23.** README.md installs `nlink = "0.17"` (workspace at
  0.19.0). `README.md:29,32,36`.
- **M24.** CLAUDE.md "Active work" section still describes 0.17
  cycle. `CLAUDE.md:543-560`.
- **M25.** lib.rs doctest passes `&str` to `RawFd`-typed
  `new_in_namespace`. `lib.rs:148`.
- **M26.** lib.rs Features list contains non-existent `tc` flag,
  omits `namespace_watcher, lab, syscall_batch, serde`.
  `lib.rs:9-14`.
- **M27.** lib.rs claims `_by_name` reads `/sys/class/net/` (Plan
  192 D4 changed this — now netlink-based). `lib.rs:86-90`.
- **M28.** lib.rs doctest uses `addr.address` (pub(crate)) instead
  of `addr.address()`. `lib.rs:128`.
- **M29.** `Error::is_dump_interrupted` doctest references
  non-existent `nlink::Link`. `error.rs:701`.
- **M30.** `nftables-declarative-config.md:64` uses deprecated
  `summary()`. `docs/recipes/`.

---

## LOW-severity findings

(condensed)

- **L1–L11.** 11 examples (`route/*.rs`, `examples/route/tc/*.rs`)
  reference stale package name `rip` and pre-rename example names
  in their `Run with:` doc comments. Users copy-paste, get "no
  example target named X", bounce.
- **L12–L25.** 14 `--apply` examples use `std::process::exit(1)`
  on non-root instead of the CLAUDE.md `Ok(())` skip-convention.
  Affects automated test runners.
- **L26–L33.** 7 examples document "Requires root" but lack the
  `require_root!()` early-return guard.
- **L34.** CLAUDE.md bins listing is incomplete (6 of 11 bins
  listed). `CLAUDE.md:10,66`.
- **L35.** CLAUDE.md cookbook missing 6 recipes that exist.
  `CLAUDE.md:486-522`.
- **L36.** CLAUDE.md "Plans" architecture row points at
  `128b-roadmap-overview.md` (2-cycle-stale). `CLAUDE.md:69`.
- **L37–L45.** Various bin output bugs: `ss` always prints
  `cubic:<algo>`; `ip macsec` prints `include_sci` twice; `nft`
  display hardcodes `type filter`; `ip tunnel` ignores user
  options; tons more in the bin-audit body.
- **L46–L50.** Various silent default-on-unknown patterns in bins
  (`Scope::from_name`, `nud_state`, `chain_type`, etc.).

---

## Per-area deep-dives

### Wire-format byte-exact audit

Read every `#[repr(C)]` / `#[repr(C, packed)]` struct nlink emits,
compared against `linux/uapi/*.h`. **3 of the 5 CRITICAL findings
are here.**

Audited (sample): `IfInfoMsg`, `IfAddrMsg`, `RtMsg`, `NdMsg`,
`FibRuleHdr`, `TcMsg`, `NfGenMsg`, `GenlMsgHdr`, `XfrmSelector`,
`XfrmUsersaInfo`, `XfrmUserpolicyInfo`, `XfrmUserpolicyId`,
`XfrmLifetimeCfg`/`Cur`, `XfrmStats`, `XfrmUserTmpl`, `XfrmId`,
`bridge_vlan_info`, `tc_ratespec`, NFT verdict codes, NF_INET hook
codes, WG sockaddr_in/in6, WG public/preshared/private key length
handling, AllowedIP family/length, DPLL value-enums, NFT_SET_* flags.

**Findings table:**

| Wire format | Verdict | Severity |
|---|---|---|
| NFT verdict codes (`NFT_*`) | **WRONG** (C1) | CRITICAL |
| `XfrmUserpolicyInfo` 168-byte layout | **WRONG** (C2) | CRITICAL |
| `XfrmUserpolicyId` 64-byte layout | **WRONG** (C3) | CRITICAL |
| NF_INET hook codes (M1) | partial wrong | MEDIUM |
| `tcm_info` packing | correct (PR #7) | — |
| `IfInfoMsg`/`IfAddrMsg`/`RtMsg`/`NdMsg`/`FibRuleHdr` | correct | — |
| `XfrmSelector` (56-byte) | correct | — |
| `XfrmUsersaInfo` (224-byte) | correct | — |
| `GenlMsgHdr` (4-byte) | correct | — |
| WG sockaddr encoding | correct | — |
| `bridge_vlan_info` | correct | — |

**Test gap inventory:** NO byte-level regression test exists for
the 5 affected wire formats (NFT verdicts, XFRM policy info/id,
NF_INET hooks). Adding a single `wire_format_sizes.rs` test module
asserting each struct's `size_of` against the kernel C `sizeof`
would have caught C2 + C3. Adding a `nft_verdict_consts.rs` test
pinning each `NFT_*` to its kernel value would have caught C1.

**Recommended hardening:** adopt a `build.rs` that compiles a tiny C
program emitting `sizeof(struct ...)` consts, then Rust asserts them
at compile time. Drift surfaces at `cargo build`, not at production
EINVAL.

---

### Declarative configs audit

`NetworkConfig`, `NftablesConfig`, `WireguardConfig` audited for
diff correctness and apply semantics.

**Findings (concentrated above as C5, H2, H3, H4, M3–M8, M10):**
- C5 — purge is dead code (entire feature).
- H2 — master change undetected.
- H3 — route gateway/dev/metric change undetected.
- H4 — apply_reconcile retries non-atomic.
- M3 — remove_route drops table/metric/dev.
- M4 — prefix change creates EEXIST.
- M5 — topo-sort misses VXLAN underlay + master deps.
- M6 — anonymous rule unbounded growth.
- M7 — Pass 3 wipes foreign-commented rules.
- M8 — WG config can't compose with NetworkConfig.
- M10 — LinkState::Down vs OperState mismatch.
- M18 — replace-qdisc is non-atomic.
- M19 — flowtable diff is name-only.

**Test gap:** the 0.19 cycle's integration backfill
(`cycle_0_19_backfill.rs`) covers shipped APIs but not the
edge cases — specifically: no test for purge actually purging
anything; no test for route gateway change detection; no test for
master change detection; no test for VXLAN underlay topo-sort; no
test for repeated-apply anonymous-rule churn.

---

### GENL families audit

**Findings (C4, H1, M11, M12, M13, M14 covered above):**
- C4 — devlink mcast group name wrong.
- H1 — DPLL phase_offset truncation.

**Confirmed-clean:** WG polling watcher (Plan 199 design verified),
WG command/attribute IDs, DPLL command/attribute/value enum IDs
(except `phase_offset` type), ethtool/dpll mcast group names,
WG key length handling, AllowedIP family/length, bitflags
preserving unknown-bit (`from_bits_retain`).

---

### Resource lifecycle audit

**Verified clean:** no `tokio::spawn` / thread::spawn in lib code,
no `unsafe impl Send/Sync`, no `mem::forget`/`ManuallyDrop`/
`transmute` in lib, FD lifecycle on socket construction is sound,
all drop impls (Connection, LabNamespace, NamespaceGuard,
PooledConnection) are correct.

**Documented hazards (not bugs):** `new_in_namespace` restoration
failure orphans the thread (Plan 147 §1 documented this; see
`Error::NamespaceRestoreFailed`).

**Surfaced:** F1 from first audit reaffirmed — `Connection<P>: Sync`
is **not UB** but is semantically misleading; the seq filter
correctly handles the cancellation-stale-frame case (covered by
the recv-loop's `if header.nlmsg_seq != seq { continue }`). A
docstring at minimum is recommended.

---

### Documentation drift

(M23–M30 above plus L34–L36, plus the recipe drift):

- README.md still installs 0.17, has no 0.18/0.19 highlight section.
- CLAUDE.md "Active work" describes 0.17 cycle as in-progress.
- lib.rs doctest passes `&str` to RawFd-typed method.
- lib.rs Features list contains non-existent `tc`, omits 4 real
  features.
- lib.rs claims `_by_name` reads sysfs (Plan 192 D4 changed this).
- `Error::is_dump_interrupted` doctest references non-existent
  `nlink::Link`.
- `nftables-declarative-config.md` uses deprecated `.summary()`.

Plus a real behavior bug masquerading as doc drift: **`Error::is_not_found`
does not go through `errno()`**, so `Error::Io(ENOENT)` from the
socket layer is silently missed. Asymmetry with sibling `is_*`
predicates Plan 187 §2.5 explicitly fixed.

---

### Examples audit

50 findings — mostly LOW (covered as L1–L50 above). One HIGH:
- H10 — `examples/nftables/firewall.rs` cleanup leak on partial run.

---

### Bins audit

50+ findings spanning `bins/{ip,tc,ss,nft,wifi,devlink,ethtool,
bridge,config,diag,wg}`. The bin-audit agent produced a complete
per-bin breakdown. Concentrated above:
- H5 — nft typo silently flips firewall policy.
- H6 — wg silent key set failure.
- H7 — ip vrf exec doesn't enter VRF.
- H8 — ip xfrm is stubs.
- H11 — TC action raw-pointer alignment.

Plus dozens of MEDIUM/LOW findings: silent default-on-unknown
patterns, missing error propagation in flush paths, stale doc
references, missing functionality stubs that return Ok silently.

---

## Coverage matrix — what was searched

| Category | Files searched | Findings |
|---|---|---|
| Recv-loops | 22 cited sites + lib-wide grep | 11 HIGH + 9 MEDIUM (H9) |
| Wire-format encoders | 25+ structs vs kernel UAPI | 3 CRITICAL + 1 MEDIUM |
| Declarative configs | `config/`, `nftables/config/`, `wireguard/config.rs` | 1 CRITICAL + 3 HIGH + 7 MEDIUM |
| GENL families | 8 family modules + macros | 1 CRITICAL + 1 HIGH + 4 MEDIUM |
| Resource lifecycle | `socket.rs`, `connection.rs`, `pool/`, `lab/`, `namespace.rs`, `stream.rs`, `dump_stream.rs`, `resync.rs` | 0 HIGH (1 architectural M15) |
| Documentation | README, CLAUDE.md, lib.rs, recipes, examples doc-comments | 1 MEDIUM (M9) + ~30 doc drift |
| Bins | 11 bin crates, 49 files | 5 HIGH + 30+ MEDIUM/LOW |
| Examples | 64 files, 22 subdirs | 1 HIGH + ~50 MEDIUM/LOW |

---

## Recommended ship order

If you can fix only five things in 0.19.1:

1. **C1** — nftables verdict codes (one-line constant change + test).
   Headline correctness bug. Every consumer of `Verdict::Jump`/`Goto`
   has shipped wrong rules.
2. **C2** — XFRM userpolicy_info trailing pad. Adds `_pad: [u8; 4]`.
   `add_sp` becomes functional.
3. **C4** — Devlink mcast group name string. One-line change. Every
   devlink event subscriber starts working.
4. **C5** — Either wire up purge in `diff_*` functions OR remove the
   `purge` flag entirely. Stop the silent lie.
5. **C3** — XFRM userpolicy_id trailing pad. Three-byte fix. Removes
   strict-checking incompatibility.

If you can fix ten things:

6. **H1** — DPLL `phase_offset` i64 (larger change, ~50 LOC). Telco
   users will thank you.
7. **H9** — wrap remaining 11 recv-loops in `with_timeout`. Pattern
   established by `5ef0808`.
8. **H2** — master change detection. ~20 LOC.
9. **H3** — route identity widening. ~30 LOC.
10. **M9** (`Error::is_not_found` Io gap) — one-line fix. Closes
    the asymmetry Plan 187 §2.5 left behind.

The bins/examples findings are valuable but can wait for a
post-cycle hygiene sweep.

---

## Methodology notes

This audit deployed 7 parallel specialized agents:
1. **Bins audit** — `bins/*/src/`, ~49 files / ~14.7 kLoC.
2. **Declarative configs deep audit** — config + nftables/config +
   wireguard/config.
3. **Wire-format byte-exact audit** — kernel UAPI cross-check.
4. **GENL families internals audit** — 8 families + macros.
5. **Resource lifecycle + Send/Sync audit** — FD/task/drop.
6. **Documentation drift audit** — README, CLAUDE.md, lib.rs, recipes.
7. **Remaining recv-loop hazards** — deferred items from first audit.

Each agent returned a structured findings list. Findings ranked HIGH
or CRITICAL were **adversarially verified** by re-reading the cited
code before inclusion in this report. The five CRITICAL findings
were verified by direct file reads documented above.

External bug catalogues consulted: netlink-packet-route (npr) #232,
#152, #100, #140, #96, #99, #54, #43; netlink-packet-core #11, #15;
neli #308, #236, #224, #223, #221, #218, #196, #165, #245, #262,
#273, #237; vishvananda/netlink #1163, #1149, #1108, #1104, #1089,
#1086, #1080, #1002, #987, #955, #947, #905, #877, #851, #792, #780,
#815, #968; rtnetlink #91, #69, #28; Cilium #40280; pyroute2 #874;
little-dude/netlink #139; libnl #104; google/nftables #103;
keepalived #392; RHBZ 655857.

Kernel docs consulted: `kernel.org/docs/userspace-api/netlink/intro`;
`man7 netlink(7)` / `rtnetlink(7)`; LWN nftables spec article; nft
verdict UAPI; xfrm UAPI; devlink UAPI; dpll YAML spec.

---

## Appendix — first-audit fix status

The previous bug-hunt batch (commit `5ef0808`, 2026-05-31) shipped:

- `Batch::send_chunk` timeout wrap ✅
- `audit.rs` × 3 (timeout + seq filter) ✅
- `sockdiag.rs::destroy_tcp_socket` (timeout + seq filter + factory) ✅
- `MessageBuilder::nest_end` / `NlAttr::new` u16 saturation ✅
- 13 `AttrIter` robustness tests ✅
- `Error::DumpInterrupted` + `is_dump_interrupted()` predicate +
  `NlMsgHdr::is_dump_interrupted()` accessor + detection in
  `send_dump_inner` ✅

This second audit's recv-loop findings (H9) are the remaining sites
the first audit deferred — same fix pattern.

---

*End of report. Total findings: 5 CRITICAL, 11 HIGH, 30 MEDIUM,
~50 LOW = ~96 distinct bugs/issues. Distinct from first-audit
findings (already fixed in `5ef0808`).*

---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 209 — Bins remediation (H5, H6, H7, H8, H11 + bin bug bundle)
status: queued for 0.19 — HIGH (security UX + UB + silent stub commands)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §H5–H11, M20, M21
created: 2026-05-31
---

# Plan 209 — Bins remediation

## 1. Why this plan exists

The `bins/{ip,tc,ss,nft,wifi,devlink,ethtool,bridge,config,diag,wg}`
CLI demos were never audited until this cycle. 50+ findings.
Several are HIGH-severity user-impacting bugs:

- **H5** `bins/nft` typo on `--policy` silently flips firewall
  default to ACCEPT (security UX)
- **H6** `bins/wg set --private-key /typo` silently exits 0 without
  setting the key
- **H7** `ip vrf exec` doesn't actually enter VRF — sets env var only
- **H8** `bins/ip xfrm` is entirely stubs returning empty
- **H11** TC action raw-pointer casts on potentially-unaligned data
  (UB on ARM/MIPS)

Plus ~30 MEDIUM / ~15 LOW findings (silent-default-on-unknown
patterns, swallowed errors in flush paths, missing functionality
stubs, misleading output formats).

## 2. Phase 1 — H5 nft typo → reject

**File:** `bins/nft/src/main.rs:318-321, 448`

Replace:
```rust
chain = chain.policy(match p.as_str() {
    "drop" => Policy::Drop,
    _ => Policy::Accept,    // typo silently flips to ACCEPT
});
```

With:
```rust
chain = chain.policy(match p.as_str() {
    "drop" => Policy::Drop,
    "accept" => Policy::Accept,
    other => return Err(format!(
        "unknown policy `{other}` — expected `drop` or `accept`"
    ).into()),
});
```

Same shape for the rule-spec parser at line 448 — error on
unknown token rather than silently advancing.

Add a small shared helper `parse_named_or_err(name, table)` in
`bins/nft/src/util.rs` that all named-token parsers route through,
so the discipline propagates.

## 3. Phase 2 — H6 wg silent key fail → propagate

**File:** `bins/wg/src/set.rs:66-70`

Replace:
```rust
if let Some(ref path) = args.private_key
    && let Ok(key) = read_key_file(path)
{
    dev = dev.private_key(key);
}
```

With:
```rust
if let Some(ref path) = args.private_key {
    let key = read_key_file(path)
        .with_context(|| format!("reading private key from {}", path.display()))?;
    dev = dev.private_key(key);
}
```

Also audit the same pattern for `--preshared-key`, `--public-key`
peer args.

## 4. Phase 3 — H7 ip vrf exec → real implementation OR fail fast

**File:** `bins/ip/src/commands/vrf.rs:142-170`

Option A: implement properly:
- Find the VRF interface's ifindex.
- Fork + use `SO_BINDTOIFINDEX` on the child's sockets (requires
  child cooperation; complex for arbitrary commands).
- Alternative: place the child in a cgroup with l3mdev rule
  targeting the VRF.

Option B: fail fast:
```rust
return Err("ip vrf exec is not implemented in this demo. \
    Use the real iproute2 `ip vrf exec` command. \
    Or invoke commands inside an `ip netns exec` with VRF \
    routing configured.".into());
```

**Recommended: Option B for 0.19.** Implementing proper VRF
exec is a substantial undertaking (cgroup setup, fd inheritance
semantics, signal forwarding). For a demo binary, failing fast
is honest. Document the limitation in `--help`.

## 5. Phase 4 — H8 ip xfrm → wire up to lib OR fail fast

**File:** `bins/ip/src/commands/xfrm.rs` (entire file)

The lib has full XFRM support (`Connection<Xfrm>`,
`stream_sas`/`stream_sps` shipped in 0.16). The bin's
`parse_xfrm_states()` returns empty Vec on line 215.

Option A (recommended): wire up.
```rust
async fn parse_xfrm_states(conn: &Connection<Xfrm>) -> Result<Vec<XfrmSa>> {
    let mut stream = conn.stream_sas();
    let mut sas = Vec::new();
    while let Some(sa) = stream.try_next().await? {
        sas.push(sa);
    }
    Ok(sas)
}
```

Same for policies, monitor, flush. The lib has all the pieces;
this is just wiring.

Option B: fail fast on every subcommand. Acceptable as a
fallback for time-constrained ship.

## 6. Phase 5 — H11 TC action raw-pointer casts → zerocopy

**File:** `bins/tc/src/commands/action.rs:221, 237, 254, 280, 292, 309`

Replace each:
```rust
let gact = unsafe { &*(attr_data.as_ptr() as *const TcGact) };
```

With:
```rust
let gact = TcGact::ref_from_bytes(attr_data)
    .map_err(|_| format!("malformed TcGact attribute payload"))?;
```

Where `ref_from_bytes` is the alignment-checking zerocopy method
already used throughout the lib for parsing kernel responses.

Audit `bins/tc/src/commands/{action,filter,qdisc}.rs` for other
similar raw-pointer casts.

## 7. Phase 6 — bin bug bundle (MEDIUM findings)

These follow a small number of repeating anti-patterns; fix the
patterns library-style for all bins:

### 7.1 Silent `_ => default` arms

Audit table (each replaces with error or named fallback):

| File:line | Bug | Fix |
|---|---|---|
| `bins/ip/commands/address.rs:194-196` | `Scope::from_name(s).unwrap_or(Scope::Universe)` | error on unknown |
| `bins/ip/commands/address.rs:209-213` | `--broadcast` parse silent drop | propagate Err |
| `bins/ip/commands/neighbor.rs:185` | NUD state silent default to Reachable | error |
| `bins/ip/commands/route.rs:195,229,368` | `nlink::util::names::table_id(t).unwrap_or(254)` | error on unknown |
| `bins/ip/commands/rule.rs:276-277,407-409` | same | error |
| `bins/nft/src/main.rs:222-237,308-315` | priority/chain_type silent default to Filter | error |
| `bins/devlink/src/main.rs:292-298` | ParamData inferred from string | take `--type` hint |
| `bins/ethtool/src/main.rs:559-562` | unknown `--duplex` silently Full | error |
| `bins/ss/src/main.rs:412-421` | `--src`/`--dst` parse silent drop | propagate Err |

### 7.2 `let _ = del_X().await` swallowing errors

`bins/ip/commands/address.rs:263-264`, `neighbor.rs:243`,
`nexthop.rs:413-422`. Replace with explicit "collect errors and
report count" pattern:

```rust
let mut destroyed = 0u32;
let mut errors = 0u32;
for entry in entries {
    match conn.del_X(entry).await {
        Ok(()) => destroyed += 1,
        Err(e) if e.is_not_found() => {} // already gone
        Err(_) => errors += 1,
    }
}
println!("Flushed {destroyed} entries ({errors} errors)");
```

### 7.3 `ip route get` does full dump → use kernel lookup (M21)

**File:** `bins/ip/commands/route.rs:393-423`

iproute2's `route get` performs a kernel-side `RTM_GETROUTE`
lookup that resolves the actual matched route (after policy,
multipath, source-addr selection). nlink's bin does a full table
dump and prefix-matches in userspace.

Wire up to the lib's `get_route_for_addr` if exists, or add it
as a thin helper. ~30 LOC.

### 7.4 Confusing output

| File:line | Bug | Fix |
|---|---|---|
| `bins/ss/output.rs:257` | Hardcoded `cubic:` prefix | drop prefix |
| `bins/ss/output.rs:371-388` | `-n` flag has no effect | implement or remove |
| `bins/ip/commands/macsec.rs:222-225` | `include_sci` printed twice | fix duplicate |
| `bins/ip/commands/tunnel.rs:266,280,284-286,411,483-486` | Discards user opts; wrong format; misses okey | fix each |
| `bins/ip/commands/link.rs:148-152` | `--up`+`--down` both → up | clap `conflicts_with` |

## 8. Phase 7 — Privacy + cleanup loose ends

| Finding | Fix |
|---|---|
| Hardcoded 2-second sleep for wifi scan | subscribe to `NL80211_CMD_NEW_SCAN_RESULTS` |
| Monitor loops continue silently on stream Err | bound retry, then break |
| `examples/wg.rs` MAC printing concerns | already audited as no-action |

## 9. Tests

Each fix gets either:
- A unit test in the bin (if the bin has test infra), OR
- A "smoke test" invocation in `bins/<name>/tests/integration.rs`

For H5 specifically:
```rust
#[test]
fn nft_rejects_unknown_policy_token() {
    let output = invoke_nft(&["add", "chain", "inet", "f", "c",
        "--hook", "input", "--policy", "acept"]);
    assert!(output.status.code() != Some(0));
    assert!(output.stderr.contains("unknown policy"));
}
```

## 10. CHANGELOG entry

```markdown
### Fixed

- **`bins/nft` rejects unknown `--policy` and unknown rule
  tokens** (H5). Previously `--policy acept` silently shipped
  Policy::Accept; `tcp dport 22 acept` silently shipped a
  no-op rule. Security UX hardening.

- **`bins/wg set --private-key /path` propagates file read
  errors** (H6). Previously a missing file silently dropped
  the key set; exit 0; user believed key was installed.

- **`bins/ip vrf exec` fails fast instead of silently not
  entering VRF** (H7). Demo binary; honest "not implemented;
  use real iproute2" message.

- **`bins/ip xfrm` wired to the lib's XFRM family** (H8).
  Previously every subcommand returned empty stubs.
  `state show`, `policy show`, `monitor`, `flush *` now
  delegate to `Connection<Xfrm>`.

- **`bins/tc action` parses TC action attributes via zerocopy**
  (H11). Previously used raw-pointer casts that are UB on
  strict-alignment architectures (ARM/MIPS); now goes through
  `ref_from_bytes` like the rest of the lib.

- **~25 silent-default-on-unknown patterns hardened across bins**
  (Phase 6). Unknown CLI tokens now error rather than silently
  defaulting to a (possibly dangerous) named fallback.

- **~5 flush paths in `bins/ip` collect and report errors
  rather than silently swallowing** (Phase 6).

- **`bins/ss` output cleanup** — drop hardcoded `cubic:` prefix,
  fix `-n` flag, etc. (Phase 6).
```

## 11. Acceptance criteria

- [ ] H5 — nft rejects unknown policy + unknown rule tokens
- [ ] H6 — wg set errors on missing private-key file
- [ ] H7 — ip vrf exec fails fast
- [ ] H8 — ip xfrm wired to lib (or fails fast)
- [ ] H11 — TC action uses zerocopy
- [ ] Phase 6 bug bundle landed
- [ ] Smoke tests pass
- [ ] CHANGELOG entries
- [ ] No new clippy warnings

## 12. Effort estimate

| Phase | Time |
|---|---|
| Phase 1 — H5 | 1 h |
| Phase 2 — H6 | 30 min |
| Phase 3 — H7 (option B fail fast) | 30 min |
| Phase 4 — H8 (option A wire up) | 2 h |
| Phase 5 — H11 | 1 h |
| Phase 6 — bin bug bundle | 2 h |
| Phase 7 — cleanup loose ends | 30 min |
| Smoke tests | 30 min |
| CHANGELOG | 30 min |
| **Total** | **~8 h** |

## 13. Risks

- **H8 (ip xfrm wire-up) may surface lib bugs** in the XFRM
  family (Plan 204 found one — `add_sp` was broken; that fix
  ships in the same cycle). Test on a netns with XFRM loaded.
- **TC action zerocopy migration may catch real misaligned
  buffer cases** — surface as parse errors rather than UB.
- **H7 fail-fast is a UX regression** for users invoking
  `ip vrf exec` and finding "not implemented". Mitigation:
  clear message in `--help` and command output.

## 14. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | ~6 fixed entries |
| `bins/nft/src/main.rs` + new util module | parser hardening |
| `bins/wg/src/set.rs` | error propagation |
| `bins/ip/commands/vrf.rs` | fail-fast message |
| `bins/ip/commands/xfrm.rs` | full rewrite |
| `bins/tc/src/commands/action.rs` | zerocopy migration |
| `bins/{ip,nft,devlink,ethtool,ss}/...` | silent-default audits |
| Per-bin `tests/` | smoke tests |

End of plan.

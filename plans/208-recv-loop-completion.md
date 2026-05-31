---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 208 — recv-loop completion: 11 remaining hazards + GENL unification
status: queued for 0.19 — HIGH (indefinite-hang potential on 11 paths)
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §H9 + recv-loop agent §Phase 6
created: 2026-05-31
---

# Plan 208 — Recv-loop completion

## 1. Why this plan exists

Plan 172 (0.18 cycle) audit table hardened 9 recv-loops to the
canonical seq-filter + with_timeout + correct-terminator shape.
The first 0.19 bug-hunt (`5ef0808`) hardened 5 more
(batch.rs, audit.rs × 3, sockdiag.rs::destroy_tcp_socket).
**11 more sites remain** plus NLM_F_DUMP_INTR coverage in every
dump path that's not `send_dump_inner`.

This plan finishes the recv-loop completion AND refactors the 7
parallel GENL-family command methods (wireguard, macsec×2,
mptcp×3, ethtool_set) to delegate to the canonical
`send_request`/`send_dump` infrastructure — eliminating the
hazard class for all future GENL families too.

## 2. Phase 1 — Wrap 7 protocol-method recv loops

Apply the same pattern as the `5ef0808` audit.rs fixes: wrap the
existing body in `self.with_timeout(async move { ... }).await`,
add seq filter loop.

| File | Line | Method | Fix shape |
|---|---|---|---|
| `sockdiag.rs` | 413 | `query_inet_family` | `with_timeout` + seq filter on dump loop |
| `sockdiag.rs` | 511 | `query_unix_typed` | same |
| `sockdiag.rs` | 593 | `query_netlink_typed` | same |
| `xfrm.rs` | 1536 | `get_security_associations` | same |
| `xfrm.rs` | 1626 | `get_security_policies` | same |
| `netfilter.rs` | 890 | `get_conntrack_family` | same |
| `fib_lookup.rs` | 355 | `lookup_with_options` | same (single-recv) |

Concrete shape for each (template):

```rust
pub async fn query_X(&self, ...) -> Result<Vec<X>> {
    self.with_timeout(async move {
        let seq = self.socket().next_seq();
        // ... build request ...
        self.socket().send(&buf).await?;

        let mut results = Vec::new();
        loop {
            let data = self.socket().recv_msg().await?;
            let mut offset = 0;
            while offset + 16 <= data.len() {
                let nlmsg_len = u32::from_ne_bytes([
                    data[offset], data[offset+1], data[offset+2], data[offset+3]
                ]) as usize;
                let nlmsg_type = u16::from_ne_bytes([data[offset+4], data[offset+5]]);
                let nlmsg_seq = u32::from_ne_bytes([
                    data[offset+8], data[offset+9], data[offset+10], data[offset+11]
                ]);

                if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                    break;
                }
                if nlmsg_seq != seq {
                    offset += (nlmsg_len + 3) & !3;
                    continue;
                }

                // NLM_F_DUMP_INTR detection (Phase 2 of this plan):
                let flags = u16::from_ne_bytes([data[offset+6], data[offset+7]]);
                if flags & NLM_F_DUMP_INTR != 0 {
                    return Err(Error::DumpInterrupted);
                }

                match nlmsg_type {
                    NLMSG_DONE => return Ok(results),
                    NLMSG_ERROR if nlmsg_len >= 20 => {
                        let errno = i32::from_ne_bytes([
                            data[offset+16], data[offset+17],
                            data[offset+18], data[offset+19]
                        ]);
                        if errno != 0 {
                            return Err(Error::from_errno_with_context_ext_ack(
                                errno, "query_X", None, None,
                            ));
                        }
                    }
                    X_FAMILY => {
                        if let Some(item) = parse_X_msg(&data[offset..offset+nlmsg_len]) {
                            results.push(item);
                        }
                    }
                    _ => {}
                }

                offset += (nlmsg_len + 3) & !3;
            }
        }
    }).await
}
```

## 3. Phase 2 — NLM_F_DUMP_INTR detection in 15 dump paths

The `5ef0808` commit added `NLM_F_DUMP_INTR` detection to
`Connection::send_dump_inner` only. Every other dump loop silently
uses inconsistent snapshots.

| Dump loop | File:line | Action |
|---|---|---|
| `Connection::send_dump_inner` | connection.rs:496 | ✅ already done |
| `Connection<Generic>::dump_command` | connection.rs:2520 | add check |
| `Connection<Nftables>::nft_dump` | nftables/connection.rs:897 | add check |
| `sockdiag.rs::query_inet_family` | 413 | add check (during Phase 1 wrap) |
| `sockdiag.rs::query_unix_typed` | 511 | add check |
| `sockdiag.rs::query_netlink_typed` | 593 | add check |
| `xfrm.rs::get_security_associations` | 1536 | add check |
| `xfrm.rs::get_security_policies` | 1626 | add check |
| `netfilter.rs::get_conntrack_family` | 890 | add check |
| `genl/wireguard/connection.rs::dump_wg_command` | 277 | add check |
| `genl/macsec/connection.rs::dump_macsec_command` | 472 | add check |
| `genl/mptcp/connection.rs::dump_mptcp_command` | 449 | add check |
| `genl/ethtool/connection.rs::ethtool_get` | 1155 | add check |
| `genl/devlink/connection.rs::collect_dump_responses` | 629 | add check |
| `genl/nl80211/connection.rs::collect_dump_responses` | 591 | add check |
| `dump_stream.rs::drain_into_pending` | 133 | add check (streaming) |
| `macros/genl_dispatch.rs::GenlTypedDumpStream::drain_into_pending` | 272 | add check |

Pattern (matches the existing `send_dump_inner` shape):

```rust
// After seq filter, before is_done/is_error checks:
if header.is_dump_interrupted() {
    return Err(Error::DumpInterrupted);
}
```

For `dump_stream`/`drain_into_pending` (streaming context), the
Err is propagated through the Stream item; caller can react via
`is_dump_interrupted()` predicate (already shipped in
`5ef0808`).

## 4. Phase 3 — GENL command method unification (refactor)

The 7 hand-rolled GENL command methods all duplicate the same
recv-with-seq-filter shape:
- `wg_command` / `dump_wg_command` (wireguard)
- `macsec_command` / `dump_macsec_command`
- `mptcp_command` / `mptcp_query` / `dump_mptcp_command`
- `ethtool_set` / `ethtool_get`

These should delegate to `Connection::send_request` /
`Connection::send_dump` for unicast and dump paths. The canonical
machinery already does seq filter + timeout + NLM_F_DUMP_INTR
check + Plan 187 errno normalization.

The GENL-specific layer becomes:
1. Build a MessageBuilder (GENL header + attributes).
2. Call `self.send_request(builder)` or `self.send_dump(builder)`.
3. Parse the response bytes.

Concretely for wg_command:

```rust
// BEFORE (in genl/wireguard/connection.rs):
async fn wg_command(&self, cmd: WgCmd, attrs: ...) -> Result<Vec<u8>> {
    let seq = self.socket().next_seq();
    let pid = self.socket().pid();
    let msg = build_wg_msg(self.family_id(), cmd, seq, pid, attrs);
    self.socket().send(&msg).await?;
    let response = self.socket().recv_msg().await?;
    self.process_genl_response(&response, seq)?;
    Ok(response)
}

// AFTER:
async fn wg_command(&self, cmd: WgCmd, attrs: ...) -> Result<Vec<u8>> {
    let mut builder = self.new_genl_builder(cmd, NLM_F_REQUEST | NLM_F_ACK);
    encode_wg_attrs(&mut builder, attrs);
    // Delegate to canonical send_request: seq filter, timeout,
    // NLM_F_DUMP_INTR (n/a for unicast), errno normalization,
    // ext_ack parsing — all inherited.
    self.send_request(builder).await
}
```

Same for `dump_wg_command`:
```rust
async fn dump_wg_command(&self, cmd: WgCmd, attrs: ...) -> Result<Vec<Vec<u8>>> {
    let mut builder = self.new_genl_builder(cmd, NLM_F_REQUEST | NLM_F_DUMP);
    encode_wg_attrs(&mut builder, attrs);
    self.send_dump(builder).await
}
```

The `new_genl_builder` helper is added to whichever protocol
trait `Connection<P>` implements for GENL families; it sets
the family ID + GENL header.

After refactor:
- Delete `process_genl_response`, `wg_command`, `dump_wg_command`
  duplicates per family.
- Delete `mptcp_command`, `mptcp_query`, `dump_mptcp_command`
  duplicates.
- Delete `macsec_command`, `dump_macsec_command` duplicates.
- Delete `ethtool_set`/`ethtool_get` duplicates.
- Net code reduction: ~400 LOC.
- Cross-family fix safety: the next recv-loop hardening to
  `send_request`/`send_dump` benefits every GENL family.

## 5. Phase 4 — Family resolution unification

Current state (per audit M14): 5 parallel family-resolution paths:
- `__rt::resolve_genl_family[_with_groups]` (macros/mod.rs)
- `wireguard/connection.rs::resolve_wireguard_family`
- `macsec/connection.rs::resolve_macsec_family`
- `mptcp/connection.rs::resolve_mptcp_family`
- `Connection<Generic>::query_family` (connection.rs:2337)

Unify on `__rt::resolve_genl_family_with_groups` for all five.
WG/macsec/mptcp don't need mcast group resolution today (their
kernel modules ship zero groups), but the unified interface
accepts an empty group map.

```rust
// In genl/wireguard/connection.rs:
impl Connection<Wireguard> {
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(NETLINK_GENERIC)?;
        let (family_id, _mcast_groups) =
            __rt::resolve_genl_family_with_groups(&socket, "wireguard").await?;
        Ok(Self::from_parts(socket, Wireguard { family_id }))
    }
}
```

Delete the 4 hand-written resolvers. Update `Connection<Generic>::query_family`
to use the same helper (its existing single-recv code becomes the
helper's internal loop, with timeout + seq filter).

## 6. Tests

### 6.1 Unit — stale-seq filter contract

```rust
#[test]
fn query_inet_family_recv_loop_skips_stale_seq() {
    // Synthesize a 2-message buffer: stale-seq + valid-seq
    // matching the requested family. The handler must skip
    // the stale and process the valid.
    let buf = synth_two_messages(
        (stale_seq, RTM_NEWLINK, ...),
        (expected_seq, SOCK_DIAG_BY_FAMILY, ...),
    );
    let result = parse_loop_for_query_inet_family(&buf, expected_seq);
    assert_eq!(result.len(), 1);
}
```

### 6.2 Unit — NLM_F_DUMP_INTR detection

```rust
#[test]
fn dump_loops_return_dump_interrupted_on_intr_flag() {
    // For each dump method, synthesize a frame with NLM_F_DUMP_INTR
    // set in the flags field. The method should return
    // Err(Error::DumpInterrupted).
}
```

### 6.3 Integration (root-gated) — timeout behavior

```rust
#[tokio::test]
async fn xfrm_get_security_associations_times_out_on_silent_kernel() -> Result<()> {
    require_root!();
    // Tricky: hard to simulate a non-responsive kernel without
    // mocking. Realistic test: configure a 100ms timeout and
    // invoke the query against a netns where xfrm is not loaded
    // (or where the request is in a quiescent state). Verify
    // either: success in <100ms with empty list, OR
    // Error::Timeout after 100ms.

    let ns = LabNamespace::new("xfrm-timeout-test")?;
    let mut conn = ns.connection::<Xfrm>()?;
    conn = conn.timeout(Duration::from_millis(100));
    // ... run, observe behavior ...
}
```

### 6.4 Wire-shape — GENL refactor preserves wire bytes

```rust
#[test]
fn wg_command_post_refactor_wire_identical_to_pre_refactor() {
    // Build a SET_DEVICE request via the new send_request path.
    // Build the same request via the old hand-written path
    // (kept as `_legacy_wg_command` for one release).
    // Assert byte-identical wire bytes.
    let new_bytes = build_wg_set_via_send_request(/* args */);
    let old_bytes = build_wg_set_via_legacy(/* args */);
    assert_eq!(new_bytes, old_bytes);
}
```

## 7. CHANGELOG entry

```markdown
### Fixed

- **11 recv-loops hardened to canonical seq+timeout shape**
  (Plan 208 Phase 1). Completes the work Plan 172 started; the
  remaining sites were `sockdiag.rs` (3 dump loops),
  `xfrm.rs` (2 dump loops), `netfilter.rs::get_conntrack_family`,
  `fib_lookup.rs::lookup_with_options`, and 4
  `Connection<Generic>` GENL paths. Pre-0.19 each could hang
  indefinitely if the kernel dropped a response; now surface
  as `Error::Timeout` after the configured budget.

- **`NLM_F_DUMP_INTR` detected in 15 additional dump paths**
  (Plan 208 Phase 2). The `5ef0808` work added detection in
  `Connection::send_dump_inner` only. This extends to every
  protocol's dump path (nftables, sockdiag, xfrm, conntrack,
  wireguard, macsec, mptcp, ethtool, devlink, nl80211, generic
  GENL, and the streaming dump APIs). Callers retry via
  `Error::is_dump_interrupted()` (shipped in `5ef0808`).

### Changed

- **GENL command methods unified via `send_request` /
  `send_dump`** (Plan 208 Phase 3). The 7 hand-written
  `*_command` / `dump_*_command` methods in wireguard / macsec /
  mptcp / ethtool now delegate to `Connection::send_request` /
  `Connection::send_dump`, eliminating ~400 lines of duplicated
  recv-loop logic. Future protocol-level recv-loop hardening
  reaches every family automatically. Wire-format unchanged
  (byte-identical regression tests pin this).

- **GENL family resolution unified** (Plan 208 Phase 4). The 5
  parallel `resolve_*_family` paths now delegate to
  `__rt::resolve_genl_family_with_groups`. Fixes a latent recv-
  loop hazard in `Connection<Generic>::query_family`
  (single-recv with no timeout).
```

## 8. Acceptance criteria

- [ ] All 11 recv-loops from H9 wrapped in `with_timeout` + seq
      filter
- [ ] All 15 dump paths check `NLM_F_DUMP_INTR` and return
      `Error::DumpInterrupted`
- [ ] 7 GENL `*_command` methods delegate to `send_request` /
      `send_dump`; wire-format regression tests pass
- [ ] 5 family-resolution paths delegate to `__rt::resolve_genl_family_with_groups`
- [ ] CHANGELOG entries
- [ ] No new clippy warnings; existing tests still pass

## 9. Effort estimate

| Phase | Time |
|---|---|
| Phase 1 — 7 recv-loop wraps | 3 h |
| Phase 2 — 15 NLM_F_DUMP_INTR checks | 1.5 h |
| Phase 3 — GENL command unification | 2 h |
| Phase 4 — Family resolution unification | 1 h |
| Tests (4 unit + 1 integration + wire-shape) | 30 min |
| CHANGELOG | 30 min |
| **Total** | **~8 h** |

## 10. Risks

- **GENL unification (Phase 3) is a non-trivial refactor**.
  Wire-format regression tests are the safety net. Per-family
  byte-level assertion before/after the change is mandatory.
- **`Connection<Generic>::query_family` is high blast radius**
  (every macros-derived GENL family resolves through it). Touch
  carefully; add integration tests for each shipped family.
- **`dump_stream`/`drain_into_pending` is streaming**. Adding
  `NLM_F_DUMP_INTR` detection there means the Stream item type
  needs to surface the error — verify the Stream::Item is
  `Result<T, Error>` and consumers handle it.

## 11. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 1 fixed (recv-loops) + 1 fixed (dump_intr) + 2 changed entries |
| `docs/migration_guide/0.18.0-to-0.19.0.md` | §"Plan 208" — no breaking change; informational |
| 11 protocol files | recv-loop wraps |
| 15 dump-loop files | NLM_F_DUMP_INTR detection |
| 7 GENL connection files | delegation refactor |
| 5 family-resolution files | unification |
| `scripts/audit-recv-loop-error-handling.sh` | extend to assert every dump loop checks NLM_F_DUMP_INTR |

End of plan.

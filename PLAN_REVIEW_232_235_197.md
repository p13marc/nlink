# Plan review — Hygiene + discretionary cluster (232, 233, 234, 235, 197)

Reviewer: deep-review pass on 0.20 cycle pre-work, 2026-06-04.
Scope: 5 plans covering LOW-tier bug batch, DumpStream fuse policy,
NlRouter dispatcher, GENL command unification, and pre-existing
declarative ovpn. Verified inter-plan dependencies, test specifications,
root-gated test discipline, and external technical claims.

---

## Section 1 — Inter-plan consistency

### 1.1 Plan 234 ↔ Plan 235 dependency

The 234↔235 relationship is **described correctly but asymmetrically**.
Plan 235 §1 calls out that "if Plan 234 ships first, this plan reduces
to 'verify the dispatcher handles each family's command shape correctly'
plus the Phase 4 family-ID work" — accurate. Plan 235 §6 (Risks) and
§8 (Cross-references) repeat the dependency cleanly.

Plan 234, however, only mentions Plan 235 once (in §9 Cross-references)
and does not state in §5 (API surface) or §6 (Test plan) that **the
dispatcher's recv loop subsumes every per-family GENL command path**.
That's a load-bearing assertion that should appear at least in
the test plan: every Plan 235 §2 "TBD" family becomes a regression
target for the dispatcher.

**Concrete gap**: Plan 234's §6.1 says "existing `cargo test -p nlink
--lib` must pass unchanged". That's necessary but not sufficient — if
the dispatcher subsumes Phase 3, the dispatcher needs an explicit
per-family integration test pass against every GENL family (`wg`,
`macsec`, `mptcp`, `ethtool`, `nl80211`, `devlink`, `dpll`,
`net_shaper`, ovpn if landed). Otherwise a family with a unique
command shape — particularly ethtool's nested-set commands — could
break silently and not surface in the lib unit tests.

### 1.2 Plan 232 ↔ Plan 233 exclusion

Plan 232 §2.1 explicitly excludes B7 (→ Plan 233) and B12 (→ Plan 234).
The boundary is clean:

- B7 (DumpStream fuse) → 233
- B8 (`execute_in` namespace restore swallow) → next-cycle seed, not
  in this batch (justified — needs a typed-error discipline pass)
- B12 (stale-seq accumulation) → 234 (dispatcher) or
  documentation-only fallback on `Connection<P>` doc-comment
- B16 (DumpStream typed parse failure) → re-read as non-bug; Plan 233
  §1 mentions it as "structurally adjacent" but does NOT claim it as
  in-scope. Plan 232 §2.1 also says "Re-read confirms non-bug".

**Issue**: Plan 220 master §3.4 row for Plan 233 says "Closes B7,
**B16**" — but Plan 233 §1 says B16 is "re-read as a non-bug, but the
policy clarification in this plan makes the contract explicit". The
master plan overstates Plan 233's scope. **Recommend**: master plan
edit to "Closes B7; revisits B16 (non-bug)" or similar.

Plan 232 enumerates the LOW set as B6, B9-B11, B13-B15, B17-B19 (10
findings, not 11 — B16 and B20 dropped as non-bugs, B7 and B12
carved out). The plan's title says "11 LOW findings" — that's the
pre-cull count. The §2 table shows 10 rows. The mismatch between
the title ("batch of 10") and the YAML subject line ("11 small fixes")
is minor but a reviewer will flag it.

### 1.3 Plan 197 (ovpn) ↔ Plan 234 (dispatcher) compatibility

Plan 197 ships a `Connection<Ovpn>` GENL family using the `#[genl_family]`
macro (Plan 154 infrastructure). The macro-derived families already
route through `send_typed`, which Plan 235 §2 marks as already
template-conforming. Plan 234's dispatcher is wire-compatible with
`send_typed`. **No conflict**: if Plan 234 lands, Plan 197's
ovpn commands automatically inherit the pipelined dispatcher; if Plan
234 slides, ovpn ships on the F1-mutex baseline like every other
macro-derived family.

The only minor friction: Plan 197 is from 2026-05-30, originally
targeted at 0.19, then deferred. Its YAML still says
`target version: 0.19.0`. **This needs to be flipped to 0.20.0 (or
0.21.0)** — currently misleading.

Also: Plan 197 §1 references "the 0.19 'everything in 0.19' directive
(2026-05-30)" — that directive expired with the 0.19 ship. The plan
needs a rewrite of §1 to reflect "this plan was deferred from 0.19
and is now competing for a discretionary 0.20 slot".

### 1.4 Discretionary trio ship order (197, 234, 235)

The master plan §3.5 lists all three as "discretionary". The audit
report (referenced) does the same. **No tiebreaker rule is given**.

The right ordering, by leverage:

1. **Plan 234 (NlRouter)** first if any discretionary work happens.
   It eliminates the F1 lock contention, subsumes most of Plan 235
   Phase 3, makes the dispatcher available to ovpn for free.
   Single highest-leverage discretionary item. The cycle theme
   ("constants are part of the wire format too") doesn't apply, but
   the secondary theme ("defensive correctness sweep") does.
2. **Plan 235 (GENL unification)** second IF 234 doesn't land. Plan
   235 Phase 4 (family-ID resolution unification) is always-relevant —
   it doesn't depend on 234. Plan 235 Phase 3 collapses to a
   non-issue if 234 lands.
3. **Plan 197 (ovpn)** is the largest at ~1890 LOC + 17.5h estimate.
   It's net-new feature work, not bug-fix or robustness. It's the
   last one to land because the cycle theme is wire-format
   correctness, not net-new families.

**Recommend**: add a one-line tiebreaker to the master plan §3.5:
"If only one discretionary plan lands, prefer 234. If two, add 235
(Phase 4 always; Phase 3 only if 234 didn't land). 197 only if both
234 and 235 ship comfortably; otherwise slide to 0.21."

### 1.5 CHANGELOG / migration coordination

- **Plan 232**: §6 specifies "CHANGELOG `## [Unreleased]` carries one
  bullet per finding under the appropriate 'Fixed' / 'Changed' sub-
  heading". Good.
- **Plan 233**: §8 + §9 specify both the CHANGELOG entry and the
  CLAUDE.md update. Solid.
- **Plan 234**: §7 (Risks) mentions "CHANGELOG entry must call out:
  'the per-Connection mutex from F1 is replaced by an internal
  dispatcher task; shared `Arc<Connection>` requests no longer
  serialize, they pipeline.'" — good. Migration guide entry mentioned
  but not specified. **Recommend**: §6 add a "Migration guide
  required" sub-bullet listing the F1-era recommendation flip
  ("ConnectionPool is still preferred for true parallel fan-out;
  Arc<Connection> now pipelines instead of serializing").
- **Plan 235**: §7 acceptance line says "CHANGELOG `## [Unreleased]`
  calls out the recv-loop closure" — sparse. Missing migration guide
  entry (no API change, but the per-family-recv-loop deletion will
  surface in any downstream code that imported the internal
  helpers).
- **Plan 197**: §9 has a thorough cross-cutting artifacts table with
  CHANGELOG + migration guide + recipe + example + README rows.
  This is the most thorough of the five. (But targets the wrong
  migration guide — `0.18.0-to-0.19.0.md`, should be
  `0.19.0-to-0.20.0.md`.)

---

## Section 2 — Test-spec completeness

### 2.1 Plan 232 (LOW batch)

Per-finding tests are documented in the §2 table. The rubric check:

| Rubric | Plan 232 |
|---|---|
| Unit tests with concrete names | **Partial.** B10/B11/B13/B15/B18/B19 each have a one-line test description but no test function name. Convention: `mod tests { #[test] fn parse_string_from_bytes_lossy_replaces_invalid_utf8() { … } }`. Without the name, the reviewer can't grep that the test landed. |
| Integration tests (root-gated) | **None proposed.** Justification is correct — every LOW finding is pure-logic. |
| CI gate | §4 specifies `cargo test` + `cargo clippy --all-features -- --deny warnings` + `cargo machete`. Standard set. Adequate. |
| Adversarial inputs | B10 (invalid UTF-8 `b"foo\xff\xfebar\0"`), B13 (`what = 0xDEADBEEF`), B15 (synthetic 48-byte struct), B18 (`usize::MAX`), B19 (33 back-to-back WouldBlocks). Good coverage. |

Flag: §2's "Test" column for B6, B9, B14, B17 says "no new test
needed" / "existing tests cover" / "None — perf only". **Two of
these are weak**:

- **B6** (`from_errno_with_context`): the change is a behaviour
  change (error message format). The plan claims "no new test
  needed; existing tests cover" but the existing tests don't assert
  the operation tag is in the message. **Recommend**: spec a unit
  test `audit_error_carries_operation_tag` that constructs an audit
  failure and asserts `e.to_string().contains("audit_set_status")`.
- **B14** (nftables parsers `.unwrap()` → `attr::get::u32_be`): the
  refactor is "stylistic" but a `try_into().unwrap()` → `?` change
  could subtly differ on the truncation edge. **Recommend**: spec a
  unit test that feeds a 3-byte payload (length-guard rejects it)
  and asserts no panic.

### 2.2 Plan 233 (DumpStream fuse)

| Rubric | Plan 233 |
|---|---|
| Unit tests with concrete names | **Good.** Two tests named: `dump_stream::tests::fuses_on_malformed_by_default` and `dump_stream::tests::skip_malformed_continues`. |
| Integration tests (root-gated) | **None.** Justified — the policy is testable with synthetic input. |
| Adversarial inputs | Specified: two valid frames + one malformed + one valid. The "malformed" should be pinned more precisely — currently the plan says "synthetic stream" but doesn't define what malformed means in `MessageIter` terms. **Recommend**: §6 spec the exact byte pattern (e.g., "header.nlmsg_len < NLMSG_HDRLEN" or "header.nlmsg_len > remaining bytes"). |
| WARN log assertion | §6 mentions `tracing_subscriber::fmt::TestWriter` "or just count via a test-only counter". **The OR is imprecise** — pick one. Recommend the counter via a test-only callback (no global tracing-subscriber install which conflicts with parallel tests). |

Minor: §6's per-family event-stream verification step ("any
flatten-violators escalated to a separate fix") is vague. **Recommend**:
explicitly list the families to grep — wireguard, macsec, mptcp,
ethtool, nl80211, devlink, dpll, net_shaper, nftables — and produce a
checked-off table in the PR description.

### 2.3 Plan 234 (NlRouter dispatcher)

The most rigorous test plan, with three classes. Let me critique
each.

| Rubric | Plan 234 |
|---|---|
| Unit tests with concrete names | §6.1 says "existing `cargo test` must pass" — that's a regression check, not a positive test. **No new unit tests are specified.** A dispatcher refactor of this magnitude needs at least: `dispatcher_routes_request_to_correct_oneshot`, `dispatcher_routes_multicast_to_all_subscribers`, `dispatcher_drops_unknown_seq_with_warn`, `dispatcher_cleanup_on_cancelled_future`. |
| Integration tests (root-gated) | Yes — §6.2 specifies two stress tests under `crates/nlink/tests/stress/`. |
| Stress test specification | **Partially specified.** §6.2 names two tests but the parameters are loose: "32 tasks issuing `get_link_by_index` concurrently with one task running `dump_routes`" — 32 is small for stress; "10k-route table" needs a setup helper; "**latency distribution is not bimodal**" needs a concrete threshold ("p99 small-request latency < N × p50") not a hand-wave. |
| ENOBUFS recovery | §6.3 specifies `enobufs_fans_out_resync_marker`. Reasonable. |

**Recommended stress-test pinning** (Section 5 below has the exact
edit). The stress test must include:

- N agents (16 minimum, 32 nominal, 64 for soak), each issuing M
  requests (1000 each), running for T duration (60s minimum).
- One long-lived multicast subscriber alongside.
- One long dump running concurrently.
- Assertion: p99 small-request latency < 50ms (achievable on a
  laptop loopback netlink fd; conservative).
- Assertion: dispatcher's pending-map size stays bounded (<= number
  of in-flight requests + small constant).
- Assertion: zero dispatcher panics across the run.

The current §6.2 has the bones but not the gating numbers.

### 2.4 Plan 235 (GENL unification)

| Rubric | Plan 235 |
|---|---|
| Unit tests with concrete names | §5 names two: `send_genl_command_filters_stale_seq` and `resolve_family_id_filters_stale_seq`. Good — parameterized over every family. |
| Per-family regression tests | "Each migrated family needs a regression test" — §5 implies it via the parameterized H9 pattern but doesn't enumerate. **Recommend**: §5 add a table listing every TBD family with the specific command used in the regression test (e.g., macsec `MACSEC_CMD_GET_TXSC`, mptcp `MPTCP_PM_CMD_GET_ADDR`, ethtool `ETHTOOL_MSG_CHANNELS_GET`, …). |
| Audit script update | §5 specifies the script extension. |
| Behavioral-preservation tests | §6 (Risks) mentions per-family observable error shape preservation. **No test name specified.** Recommend: a wire-shape diff test that captures the kernel response bytes before migration, replays them through both old and new helpers, and asserts identical `Result<T>` output. |

### 2.5 Plan 197 (declarative ovpn)

| Rubric | Plan 197 |
|---|---|
| Unit tests with concrete names | **Excellent.** §4.1 names 6 diff-semantics tests + §4.2 names 3 wire-shape tests. |
| Integration tests (root-gated) | §4.3 specifies 3 root-gated tests with `nlink::require_modules!("ovpn")`. |
| Module gating | §4.3 specifies `require_modules!("ovpn")` — correct per CLAUDE.md "kernel module gating". |
| Adversarial inputs | The diff tests cover: new peer, changed endpoint, stale peer, idempotent re-diff, byte-counter drift, key swap. Comprehensive. |

One gap: the `attach_socket` fd-passing test is described as "Verify
the auxiliary cmsg shape" but no concrete cmsg byte pattern is given.
SCM_RIGHTS wire shape is `sizeof(cmsghdr) + sizeof(int)` and the
`cmsg_type = SCM_RIGHTS, cmsg_level = SOL_SOCKET` — recommend pinning
these in the test.

---

## Section 3 — Root-gated test specification quality

### 3.1 Plan 232 root-gating judgment

The plan's claim that "no integration tests needed; all findings are
unit-testable with synthetic inputs" is **correct for 9 of 10**:

- B6 (error context): unit
- B9 (pointer math): unit
- B10 (UTF-8 lossy): unit
- B11 (panic → InvalidMessage): unit
- B13 (ProcEvent::Unknown): unit (synthetic header.what)
- B14 (parser style): unit
- B15 (audit short-struct): unit (synthetic 48-byte input)
- B17 (perf): no test, just bench
- B18 (overflow): unit
- B19 (WouldBlock cap): unit (mock Socket::send)

**B19 is the only one where unit testing is marginal.** The mock
`Socket::send` requires a trait-shim or test-only abstraction.
Currently `NetlinkSocket` is not generic over a `Socket` trait. The
plan says "mock `Socket::send` returns WouldBlock 33 times" but
doesn't specify the test infrastructure. **Recommend**: §3 add a
sub-section noting B19 may require either (a) a `#[cfg(test)] impl`
on `NetlinkSocket` exposing a counter knob, or (b) deferral to an
integration test using a saturated kernel socket — pick one
explicitly.

### 3.2 Plan 233 (DumpStream) malformed-frame testing

The plan specifies synthetic unit tests via "feeding a synthetic
stream". Critically, **the plan does not explain how to construct a
synthetic stream that goes through `MessageIter::new(data)`**. The
straightforward path: hand-write the bytes of a valid `nlmsghdr` +
payload twice, then a header with `nlmsg_len = 3` (which is < min
header size, triggering the parse-error path in `MessageIter`),
then another valid frame.

The plan should pin this exact byte pattern. The alternative — a
mock-socket / fakery infrastructure — is overkill for this test;
direct byte-vector construction is the right tool.

**Recommend**: §6 spec the exact byte pattern in the test
(approximate: `let bytes = [valid_msg(), valid_msg(), bad_msg(),
valid_msg()].concat();`).

### 3.3 Plan 234 dispatcher stress

§6 says stress tests "can live under `crates/nlink/tests/stress/`
gated `#[ignore]` (long-running) plus a CI knob to run them under
the privileged-CI workflow". The privileged-CI workflow already
gates on `nlink::require_root!()` (CLAUDE.md). The stress test
infrastructure path is fine. But **the test names are specified
without the gating macro**. The integration test functions should
be:

```rust
#[tokio::test]
#[ignore = "stress; runs under privileged-CI"]
async fn stress_n_requests_with_long_dump() -> Result<()> {
    nlink::require_root!();
    // …
}
```

Plan 234 should make this explicit. Currently §6.2 reads as if
`#[ignore]` is the only gate; the `require_root!()` macro should
also be in the example.

### 3.4 Plan 235 per-family regression tests

§5 specifies the H9-pattern test is parameterized over every family.
**Each parameterization needs a root-gated integration test for the
actual kernel response** if the test asserts wire-correctness. The
unit test (synthetic stale-seq injection) is fine without root. But
the "behavior preservation" tests under §6 risks need root because
they replay kernel responses.

**Recommend**: §5 separate the two test layers explicitly:
- Unit (no root): synthetic stale-seq injection via mock socket.
- Integration (root-gated): real kernel call against each family,
  asserting the response shape matches the pre-migration helper's
  output. Plus the privileged-CI gate.

### 3.5 Plan 197 ovpn root + module gating

§4.3 specifies `require_root!()` + `require_modules!("ovpn")`.
**Both are correct**. The kernel-version threshold is 6.16+
(verified — see Section 4 below). The module name is `ovpn`
(verified — both the upstream patch series and the in-tree
documentation use this name).

One missing gate: the CI runner used by the privileged-CI workflow
(see `.github/workflows/integration-tests.yml`) needs a kernel
version check. **Recommend**: §7 add a row to the Risks table:
"CI runner kernel version must be >= 6.16; document fallback if
the runner is older (skip the integration tests cleanly, surface
the version in the run log)".

---

## Section 4 — Verification by external research

### 4.1 Plan 234's NlRouter design vs neli's reference

I fetched neli's [`asynchronous.rs`](https://github.com/jbaublitz/neli/blob/main/src/router/asynchronous.rs)
and compared against Plan 234's design.

**Matches:**
- Both spawn a single processing task that owns the socket and uses a
  `tokio::select!` loop on (cmd, recv) (Plan 234 §2 vs neli's
  `spawn_processing_thread`).
- Both use a `HashMap<seq, sender>` for per-seq dispatch (Plan 234
  uses `pending: HashMap<u32, ReplySink>`; neli uses
  `Arc<Mutex<HashMap<u32, Sender<...>>>>`).
- Both fan-out multicast to all subscribers via a separate channel
  per group.
- Both have a coordinated-exit mechanism (Plan 234 `Shutdown` enum
  variant; neli `exit_sender`).

**Gotchas Plan 234 should call out:**

1. **neli does NOT explicitly handle ENOBUFS** — per the fetched
   source, `socket.recv()` errors propagate to all pending senders
   via `RouterError`, but ENOBUFS is treated identically to any other
   socket error. Plan 234 §4 says the dispatcher "catches this at
   the recv-loop level and fans out a `ResyncMarker::ResyncStart`
   into every active multicast `broadcast::Sender`". **This is
   better than neli's design** but the plan should explicitly note
   that nlink improves on neli here. The man page
   [`netlink(7)`](https://www.man7.org/linux/man-pages/man7/netlink.7.html)
   describes ENOBUFS as kernel-side multicast queue overflow; only
   the multicast subscriber should care, not pending unicast
   requests. Plan 234's approach correctly routes the error.

2. **neli uses MPSC (not oneshot+broadcast)** for per-seq replies —
   capacity 1024. Plan 234 §2's `DispatcherCmd::Request` uses
   `oneshot::Sender` for the single-reply case, which is more
   efficient than MPSC (no allocation per send). Plan 234's
   `Dump` variant uses `mpsc::Sender<Result<Vec<Vec<u8>>>>` — that's
   the right shape for streaming dumps.

3. **neli's dispatcher-panic story is weak** — if the task exits, the
   sender map is dropped and receivers see `RecvError`, but there's
   no `ConnectionClosed` signal. Plan 234 §7 addresses this via
   `Error::ConnectionClosed { reason }` and the existing `is_closed()`
   predicate. **This is also better than neli.**

4. **PID mismatch handling** — neli broadcasts `BadSeqOrPid` to all
   waiting senders when the pid mismatches. Plan 234 §2 mentions
   PID-zero multicast detection but does NOT specify what happens
   when a unicast reply arrives with the wrong PID. **Recommend**:
   §2 add a "PID mismatch handling" sub-paragraph.

5. **neli's senders map uses `Arc<Mutex<HashMap>>`** because senders
   register from caller tasks. Plan 234's design implies the pending
   map is owned by the dispatcher task (no Mutex), with registrations
   coming through the `cmd_tx` channel. **Plan 234's design is
   simpler and avoids Mutex contention** but should be explicit:
   "the pending map is owned exclusively by the dispatcher task; no
   external synchronization needed".

### 4.2 Plan 235's family-resolution recv loop

Confirmed via the source. `connection.rs:2466-2504` shows `query_family`
as a recv-loop that:

- Builds `CTRL_CMD_GETFAMILY` request.
- Calls `socket.recv_msg()` (single recv, not a loop).
- Calls `parse_family_response(&response, seq, name)` which DOES
  filter by seq.

**Critical observation**: `query_family` does a **single
`recv_msg()`** then walks the buffer with `MessageIter`. If the
first `recv_msg()` returns a stale frame from a prior request, the
seq filter in `parse_family_response` skips it — but then there's
nothing else to recv (we already called recv once), and the
function returns `Err(Error::FamilyNotFound)`. This is a **latent
bug**: a stale frame in the buffer causes a spurious FamilyNotFound
error.

The Plan 208 comment in the source (lines 2477-2491) acknowledges
this: "A full loop+seq-filter refactor (Plan 208 Phase 4) is queued
separately because parse_family_response conflates 'stale frame' and
'real ENOENT' into the same FamilyNotFound error and disambiguating
that requires refactoring the parse side."

**Plan 235's Phase 4 needs to fix this disambiguation** — not just
dedup the per-family copies, but also wrap the single `recv_msg()`
in a loop until seq-matched (or timeout). The current plan §3 just
calls `send_genl_command(...)` which routes through
`send_request_and_wait` — that helper IS a proper loop. So the
fix is automatic if Phase 4 lands. Good. But the plan should
**explicitly call out the latent FamilyNotFound bug** as a side
benefit. Currently §1 mentions H9 (the wg_command race) but not
this related family-resolution bug.

### 4.3 Plan 197 ovpn kernel UAPI freshness

The plan was written 2026-05-30 against "kernel 6.16 ovpn netlink
spec". Verified via the upstream
[`Documentation/netlink/specs/ovpn.yaml`](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/netlink/specs/ovpn.yaml):

- **8 commands, not 11** — the YAML lists peer-{new,set,get,del} +
  key-{new,get,swap,del}. That's 8.
- **3 multicast notifications**: peer-del-ntf, key-swap-ntf,
  peer-float-ntf. Matches Plan 197.
- **3 ciphers**: None, AES-GCM, ChaCha20-Poly1305. Plan 197 lists 2
  ("AEAD-only ciphers: AES-GCM + ChaCha20-Poly1305") which is
  correct for the actually-encrypting ciphers; the kernel includes
  None as a debug/dev cipher.

**Plan 197 §1 says "11 GENL commands"; Plan 197 §2.1 lists 11
methods.** Those 11 methods include `new_iface` and `del_iface`,
which are RTNETLINK (not GENL) — already shipped via Plan 190 §2.3b
(the `IFLA_INFO_KIND = "ovpn"` link-half). And `attach_socket` (fd
passing). So the count breaks down as:

- 8 GENL commands (matches upstream)
- 2 link-half methods that should not be counted here (Plan 190
  shipped them)
- 1 fd-passing helper

**Recommend**: §1 reword to "8 ovpn GENL commands + 3 notifications
+ fd-passing helper. Iface create/delete uses the link-half from
Plan 190."

The plan's `OvpnCipher` enum lists `AesGcm | Chacha20Poly1305` —
verified correct. The `None` cipher should probably be added as a
fourth variant; it's used for testing.

[Source: ovpn.yaml on torvalds/linux master](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/netlink/specs/ovpn.yaml)
[Background: OpenVPN DCO landing in kernel 6.16](https://blog.openvpn.net/openvpn-dco-added-to-linux-kernel-2025)

### 4.4 Plan 232 LOW-finding cross-check

Spot-checked against `AUDIT_BUGS.md` and the source:

- **B6** (errno double-negate): verified at `audit.rs:458` and
  `sockdiag.rs`. The fix is sound (Plan 212 convention).
- **B9** (`msg_start = ptr - HDRLEN`): verified at
  `connection.rs:632-639`. The fragility is real. The fix proposal
  (refactor `MessageIter` to yield full msg bytes) is correct but
  **larger than one finding** — it touches every consumer of
  `MessageIter`. The plan's "no new test needed" is OK if the change
  is purely a refactor with identical observable behavior, but
  **the scope mismatch should be noted**.
- **B10** (UTF-8 lossy): verified at `parse.rs:180-183`. Fix is
  sound, behavioral change is documented in §3.2.
- **B11** (panic in `wireguard/config.rs`): verified at lines 304/334.
  Fix sound.
- **B13** (`ProcEvent::Unknown`): verified — matches existing
  `Event::Unknown` precedent.
- **B14** (`unwrap` after length guard): verified — style nit, fix
  sound but no behavior change.
- **B15** (32-byte short-struct fallback): verified at `audit.rs:486-510`.
  Fix correctly invokes Parser Robustness rule 1.
- **B17** (BytesMut churn): verified at `socket.rs:367-383`. Perf,
  not correctness.
- **B18** (`nlmsg_align` overflow): verified at `message.rs:15-17`.
  Theoretical but cheap fix.
- **B19** (`WouldBlock` spin): verified at `socket.rs:352-364`. The
  proposed `Error::Backpressure` variant is a public API addition;
  the plan correctly invokes `#[non_exhaustive]` on `Error`.

All 10 findings cross-check as sound. No false-positive in the batch.

### 4.5 Master plan claim cross-check

Plan 220 §3.4 lists Plan 233 as closing "B7, B16". As noted in §1.2
above, B16 is a non-bug. **The master plan is overstating Plan 233's
scope** and should be edited to "B7; revisits B16".

---

## Section 5 — Recommended edits

### Plan 232 — Bug-hunt LOW-tier batch

- **§2 table** — for each finding, add the concrete test function
  name (`mod tests { fn parse_string_from_bytes_lossy_replaces_invalid_utf8() }`
  etc.). Without names, the §6 acceptance line can't be grep-verified.
- **§2 row B6** — add a test: `audit_error_carries_operation_tag`
  that asserts `e.to_string().contains("audit_set_status")`.
- **§2 row B14** — add a 3-byte-payload safety test to prove the
  refactor doesn't change behavior on truncated inputs.
- **§3 add subsection 3.4** — "B19's test infrastructure": pick
  explicitly between (a) `#[cfg(test)]` knob on `NetlinkSocket` or
  (b) integration test against a saturated socket. Currently §2 says
  "mock `Socket::send`" but `NetlinkSocket` isn't trait-bounded.
- **YAML / title** — reconcile "11 findings" vs "10 in table". Pick
  the post-cull count (10) consistently.

### Plan 233 — DumpStream fuse policy

- **§6 first test** — pin the exact byte pattern for the synthetic
  stream (e.g., 2 valid + 1 malformed + 1 valid). Currently
  underspecified.
- **§6 WARN log assertion** — pick one mechanism (test-only counter
  via a callback channel preferred over `TestWriter` for parallel
  tests).
- **§6 per-family verification** — enumerate the 9 families
  explicitly (wg, macsec, mptcp, ethtool, nl80211, devlink, dpll,
  net_shaper, nftables) and produce a checked-off table in the PR.
- **Cross-ref** Plan 220 master §3.4 needs editing to "B7;
  revisits B16" since B16 is a non-bug.

### Plan 234 — NlRouter dispatcher

- **§2 add PID-mismatch sub-paragraph** — what happens when a unicast
  reply arrives with the wrong PID. neli broadcasts `BadSeqOrPid`;
  Plan 234 needs an explicit policy.
- **§2 clarify pending-map ownership** — "pending map is owned
  exclusively by the dispatcher task; no external synchronization
  needed" (Plan 234's design is simpler than neli's, worth noting).
- **§4 ENOBUFS note** — explicitly compare against neli ("neli
  propagates ENOBUFS to pending unicast senders; nlink routes it
  only to multicast subscribers as designed"). This is a positive
  delta worth marketing in the migration guide.
- **§6.1 add concrete unit tests** — `dispatcher_routes_request_to_correct_oneshot`,
  `dispatcher_routes_multicast_to_all_subscribers`,
  `dispatcher_drops_unknown_seq_with_warn`,
  `dispatcher_cleanup_on_cancelled_future`.
- **§6.2 pin stress-test parameters** — "16 concurrent agents × 1000
  requests + 1 long-lived multicast subscriber + 1 long-running
  `dump_routes`; assert p99 request latency < 50ms, dispatcher's
  pending-map size < N+constant, zero dispatcher panics across the
  run". Add a `--soak` variant for 64 agents × 60s.
- **§6.2 explicit gating** — show the full `#[tokio::test]
  #[ignore = "stress; privileged-CI"] async fn` with
  `nlink::require_root!()` inline.
- **§8 add migration guide row** — "Plan 194 → Plan 234: F1 mutex
  removed; shared `Arc<Connection>` requests pipeline instead of
  serializing; `ConnectionPool` recommendation refined".

### Plan 235 — GENL command unification

- **§1 add latent FamilyNotFound bug** — note that `query_family`'s
  single-recv pattern causes a spurious FamilyNotFound on stale-frame
  contention; Phase 4's helper fixes it as a side benefit.
- **§5 separate test layers** — unit (synthetic stale-seq injection,
  no root) vs integration (root-gated per-family wire-shape
  preservation).
- **§5 add per-family table** — enumerate each TBD family with the
  specific command used in its regression test (macsec
  `MACSEC_CMD_GET_TXSC`, mptcp `MPTCP_PM_CMD_GET_ADDR`, ethtool
  `ETHTOOL_MSG_CHANNELS_GET`, …).
- **§7 add migration guide entry** — even though there's no public
  API change, downstream code importing the per-family
  `resolve_family_id` internals (if any) will break. Document.

### Plan 197 — Declarative ovpn

- **YAML front matter** — flip `target version: 0.19.0` to
  `0.20.0 (or 0.21.0)`. Plan is now discretionary for 0.20.
- **§1 rewrite** — remove the "0.19 'everything in 0.19' directive"
  framing; replace with "deferred from 0.19; competing for a
  discretionary 0.20 slot". Cite Plan 220 §3.5.
- **§1 fix command count** — "8 GENL commands + 3 multicast
  notifications + fd-passing helper. Iface create/delete via the
  link-half from Plan 190".
- **§2.2 OvpnCipher enum** — add `None` variant for parity with
  upstream YAML (debug/dev cipher; non-encrypting).
- **§4.2 attach_socket test** — pin the exact SCM_RIGHTS cmsg byte
  shape (cmsg_level = SOL_SOCKET, cmsg_type = SCM_RIGHTS,
  cmsg_len = `sizeof(cmsghdr) + sizeof(int)`).
- **§7 add kernel-version gate** — runner kernel must be 6.16+;
  document fallback (skip cleanly if older).
- **§9 migration guide row** — flip from `0.18.0-to-0.19.0.md` to
  `0.19.0-to-0.20.0.md`.

### Plan 220 master plan (cross-references)

Not in scope for this review's edits but flagged here for the
consolidating reviewer:

- **§3.4 Plan 233 row** — currently "Closes B7, B16"; should be
  "Closes B7; revisits B16 (re-read as non-bug)".
- **§3.5 add tiebreaker** — "If discretionary budget allows one,
  ship 234. If two, add 235 (Phase 4 always, Phase 3 only if 234
  didn't land). 197 only if 234 + 235 both ship comfortably."

### Plans that are solid as-is

- **Plan 233 §1-§5** — the policy framing (dump = hard-fail, event
  = skip+log) is well-justified and the asymmetry is well-defended.
  Only the §6 test-spec refinements (above) are needed.
- **Plan 232 §3** — the per-finding rationale (B6 wontfix-or-roll,
  B10 lossy-switch, B17 scratch-buffer) is thorough.
- **Plan 234 §3 + §4** — multicast handling + ENOBUFS interaction
  with Plan 151 is the cleanest section across all five plans.

---

## Closing notes

The 232/233 hygiene pair is mechanically sound and ready to land
with the §5 edits above. The 234/235 discretionary pair has good
bones but underspecified stress-test parameters and missing
per-family test enumeration. Plan 197 is the riskiest — it carries
the most LOC (~1890), depends on a kernel-version gate (6.16+),
and was written for a different cycle so its framing needs a
rewrite. The audit table cross-check found no false-positive
findings in Plan 232's LOW batch.

**Sources cited:**
- [neli `router/asynchronous.rs`](https://github.com/jbaublitz/neli/blob/main/src/router/asynchronous.rs) — dispatcher design reference
- [neli on crates.io](https://crates.io/crates/neli) — version + multicast subscription docs
- [`netlink(7)` man page](https://www.man7.org/linux/man-pages/man7/netlink.7.html) — `NETLINK_NO_ENOBUFS` flag semantics
- [Linux ovpn.yaml UAPI spec](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/netlink/specs/ovpn.yaml) — 8 commands + 3 notifications
- [OpenVPN DCO in kernel 6.16](https://blog.openvpn.net/openvpn-dco-added-to-linux-kernel-2025) — version landing confirmation
- [OpenVPN/ovpn-net-next](https://github.com/OpenVPN/ovpn-net-next) — upstream development tree

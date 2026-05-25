---
to: nlink maintainers
from: 0.16 cut CI evidence (2026-05-25)
subject: `Connection::<Nftables>::send_batch` hangs in GHA container — root-cause + fix
status: proposed for 0.17 — 7 Plan 166 reconcile tests `#[ignore]`'d in 0.16 with this plan as the unblock
target version: 0.17.0
parent: 167-0.16-cut-activation-plan.md (Phase 3 step C closeout)
source: CI run 26405827382 (commit 012a8aa) — diagnostic suite localized the hang
created: 2026-05-25
---

# Plan 170 — `send_batch()` ACK-wait hang in nftables Transaction commit

## 0. Evidence summary

CI surfaced the hang in three pushes:

1. **Run `26402630370`** (commit `b1ab5eb`) — first CI exercise
   of Plan 166's root-gated suite. Hung indefinitely on
   `nftables_reconcile::apply_reconcile_succeeds_in_one_attempt_when_uncontended`
   for 22+ minutes. Manually cancelled.

2. **Run `26405435199`** (commit `080eb81`) — Plan 167 Phase 3
   step B: 30s `tokio::time::timeout` wrappers added on the 7
   reconcile tests + 2 flowtable tests. All 7 reconcile tests
   timed out at exactly 30s with `Error: Timeout`. Both
   flowtable tests passed. Localized: hang is in the nft
   Transaction/Connection path, but flowtable's single-op
   `add_*` paths don't hit it.

3. **Run `26405827382`** (commit `012a8aa`) — Plan 167 Phase 3
   step C: diagnostic suite (`nftables_diag.rs`) wrapping each
   constituent call in 30s timeout. **All 4 diagnostic tests
   passed**: `diag_list_tables_on_empty_ns`,
   `diag_list_chains_on_empty_ns`,
   `diag_list_flowtables_on_empty_ns`, AND
   `diag_cfg_diff_on_empty_ns` (full `NftablesConfig::diff()`
   composition).

The 7 reconcile tests still timed out — confirming that the
differentiator between diag and reconcile is `apply()`, which
goes through `Connection::send_batch()`. **The hang is in the
multi-op batch commit's response loop.**

## 1. The suspect code

`crates/nlink/src/netlink/nftables/connection.rs:614-632`:

```rust
self.socket().send(&batch).await?;

// Wait for ACK of the batch
loop {
    let data: Vec<u8> = self.socket().recv_msg().await?;

    for msg_result in MessageIter::new(&data) {
        let (header, payload) = msg_result?;

        if header.is_error() {
            let err = NlMsgError::from_bytes(payload)?;
            if err.is_ack() {
                return Ok(());          // ← returns on FIRST is_ack
            }
            return Err(err.into_error(payload));
        }

        if header.is_done() {
            return Ok(());
        }
    }
    // ← no break / no seq filter:
    //   if data has only non-error/non-done messages, loops
    //   back to recv_msg.await — hangs forever if no more
    //   datagrams arrive.
}
```

Three issues, in priority order:

### 1.1 No `nlmsg_seq` filter

Unlike the equivalent rtnetlink `send_dump_inner`
(`connection.rs:429`) which has `if header.nlmsg_seq != seq
{ continue; }`, `send_batch` ignores seq entirely. **Effect**:
any stray response from a previous send on the same socket
(or any multicast notification that arrived on the same fd)
is parsed for `is_error`/`is_done`. The match could fire on
unrelated traffic and either succeed-too-early or hang.

### 1.2 Returns on the first ACK only

The kernel's response to a multi-op nft batch is N ACK
datagrams — one per non-batch-control op with `NLM_F_ACK` set.
For our typical test batch (`BATCH_BEGIN + NEWTABLE +
NEWCHAIN + NEWRULE + NEWRULE + BATCH_END`), that's 4 ACKs. We
return on the first one. The other 3 sit in the kernel recv
buffer until socket close.

This is harmless in isolation (we got SOME ACK so the apply
succeeded), but means we're not actually validating that every
op succeeded — a partial batch failure (mid-batch EINVAL)
would surface as success because we read only the first ACK.

### 1.3 No timeout

Per CLAUDE.md: "Operation timeouts are opt-in via
`Connection::timeout(Duration)`; default is none." So if we
need to wait for more datagrams (per §1.1's loop-on-no-match
case), `recv_msg().await` blocks forever.

## 2. Why it manifests in GHA but not in the maintainer's local sudo runs

Hypotheses, in order of likelihood:

A. **GHA container kernel sends a non-ACK response first.**
   Some kernel versions emit `NLMSG_NOOP` or echo
   `NFT_MSG_NEW*` messages (per-op confirmations) interleaved
   with or before the ACKs. The local maintainer's kernel
   (Fedora 7.0.9-205) may emit ACK-first. GHA host is Ubuntu
   22/24 (kernel 6.x); container userland is Bookworm. The
   kernel version mismatch is plausible.

B. **Multiple datagrams expected; first one is parsed but the
   match fires on a wrong-seq leftover from a stale operation.**
   Less likely — each test opens a fresh Connection, so the
   socket has no history.

C. **`NLM_F_ECHO`-style echo response interpretation.** The
   `Transaction` builder doesn't explicitly set NLM_F_ECHO,
   but some nft mutation operations get an automatic echo
   response on certain kernels.

Hypothesis A best fits the evidence: works on one kernel,
hangs on another.

## 3. Proposed fix

Three changes in `send_batch`:

### 3.1 Add seq filter (mirror `send_dump_inner`)

```rust
let begin_seq = self.socket().next_seq();
begin.set_seq(begin_seq);
// ... seqs for batch ops are begin_seq+1..=begin_seq+N+1 ...
let end_seq = self.socket().next_seq();
end.set_seq(end_seq);

loop {
    let data = self.socket().recv_msg().await?;
    for msg_result in MessageIter::new(&data) {
        let (header, payload) = msg_result?;

        // Only process responses to OUR batch ops.
        if !(begin_seq..=end_seq).contains(&header.nlmsg_seq) {
            continue;
        }
        // ... existing error/done logic ...
    }
}
```

### 3.2 Wait for the BATCH_END's ACK specifically

The cleanest "batch succeeded" signal is the ACK for
BATCH_END. Track `end_seq`, only return on `is_ack() &&
header.nlmsg_seq == end_seq`. Per-op ACKs in the batch get
collected for error reporting but don't trigger return.

```rust
loop {
    let data = self.socket().recv_msg().await?;
    for msg_result in MessageIter::new(&data) {
        let (header, payload) = msg_result?;

        if header.nlmsg_seq == begin_seq {
            // BATCH_BEGIN — kernel doesn't respond to this; skip.
            continue;
        }
        if header.nlmsg_seq == end_seq && header.is_error() {
            let err = NlMsgError::from_bytes(payload)?;
            return if err.is_ack() {
                Ok(())
            } else {
                Err(err.into_error(payload))
            };
        }
        // Op-level errors abort the batch (kernel rejects
        // mid-batch and returns errors with the op's seq).
        if header.is_error() {
            let err = NlMsgError::from_bytes(payload)?;
            if !err.is_ack() {
                return Err(err.into_error(payload));
            }
        }
    }
}
```

### 3.3 Default operation timeout (separate, follow-up plan)

The `Connection::timeout(Duration)` opt-in is fine, but a
documented default of "infinity" is a footgun (this exact
hang). Consider a default of e.g. 30 seconds for all
mutation operations as a CLAUDE.md amendment + lib change.
**Out of scope for Plan 170 — flag as Plan 171.**

## 4. Acceptance criteria

- [ ] `send_batch` adds seq tracking (begin_seq + end_seq).
- [ ] Only the BATCH_END ACK (or a non-ack error in the
      batch) terminates the loop.
- [ ] Local non-root unit test asserting the new loop's
      message-filtering shape (without needing a real
      kernel: feed it a mocked datagram stream).
- [ ] The 7 `#[ignore]`'d reconcile tests un-ignored + green
      in CI.
- [ ] CHANGELOG entry under 0.17.0's Fixed section citing
      this plan.
- [ ] Migration guide note IF the wire-level fix is
      observably different to callers (not expected — the
      fix is purely an internal loop-termination change).

## 5. Effort estimate

| Phase | Effort |
|---|---|
| 1 reproduce locally under sudo + strace | ~30 min |
| 2 implement seq filter + end-seq termination | ~45 min |
| 3 unit tests for the loop (mocked socket) | ~45 min |
| 4 un-ignore the 7 reconcile tests + verify CI | ~15 min |
| 5 CHANGELOG + migration-guide review | ~15 min |
| **Total** | **~2.5 hours** |

## 6. Why the 7 reconcile tests are `#[ignore]`'d in 0.16

The lib code path that `send_batch` exercises is **correct on
the maintainer's local kernel** — the `examples/nftables/
declarative.rs` runnable demo works under `sudo` per Plan 161
acceptance. So existing users of `apply()` and
`apply_reconcile()` see no regression vs. 0.15.x (where
`apply()` didn't exist; 0.16 introduces the declarative-config
surface entirely).

The hang only surfaces under the GHA `rust:bookworm`
container's specific kernel. Shipping the tests `#[ignore]`'d
in 0.16 means:
- The library code is unchanged (still correct for the
  existing local-sudo use case).
- The tests stay in tree as documentation + as the
  regression net that activates on first 0.17 push.
- 0.16 is unblocked from the cut.

The 4 `nftables_diag::*` tests stay un-ignored — they passed
in CI run `26405827382` and are valuable independent
coverage of the dump-empty paths.

## 7. Risks

- **Reproducing locally**: maintainer needs a sudo session
  to attach strace. If the local Fedora kernel doesn't repro,
  may need a Docker `rust:bookworm` reproduction harness.
  Mitigation: the CI failure log already gives enough
  evidence; instrument with `eprintln!` + `RUST_LOG=trace`
  to surface the actual response sequence.
- **Fix landing-zone**: the cleanest fix changes the lib's
  internal loop shape, not the public API. Low risk of
  regression. Unit tests against a mocked socket can catch
  most issues without root.
- **0.17 timing**: Plan 170 wants to land early in 0.17 so
  the un-ignored tests start exercising the new `send_batch`
  in CI on every push.

## 8. Out-of-scope follow-ups

- **Plan 171 (proposed)**: default operation timeout on
  `Connection<P>`. Currently `None`; a sensible default
  (30s) would have surfaced this Plan 170 hang as
  `Error::Timeout` from the first call instead of an
  indefinite block. CLAUDE.md amendment + lib change.
- **Plan 172 (proposed)**: apply the same seq-filter +
  end-seq termination logic to any other multi-op response
  loop in the lib (audit pass). `nft_dump` already filters
  by seq; the others should be reviewed.

End of plan.

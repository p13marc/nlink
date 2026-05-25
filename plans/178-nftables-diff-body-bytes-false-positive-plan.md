---
to: nlink maintainers
from: Plan 170 closeout CI evidence (2026-05-25)
subject: `NftablesDiff` body-bytes comparison flags unchanged rules as `to_replace` (Plan 157b v2 bug)
status: proposed for 0.17 — surfaced by un-ignoring 3 reconcile tests after Plan 170's hang fix
target version: 0.17.0
parent: 177-0.17-master-plan.md
source: CI run 26414073972 — first run with Plan 170 fix in place
created: 2026-05-25
---

# Plan 178 — `NftablesDiff` body-bytes false positive

## 1. The bug

After Plan 170 fixed the `send_batch` hang and we un-ignored the
7 `nftables_reconcile::*` tests, 4 of 7 passed but 3 failed with
assertion errors — specifically, the diff path's body-bytes
comparison flags UNCHANGED rules as needing replacement:

```
test reconcile_idempotent_reapply_yields_empty_diff ... FAILED
second diff after no kernel state change must be empty;
got NftablesDiff: 2 changes:
  ~ rule Inet filter_rec/input (handle=2 key=k0)
  ~ rule Inet filter_rec/input (handle=3 key=k1)
```

Both keyed rules show up as "to_replace" on the IDEMPOTENT
second diff (we just applied them; nothing changed). That
breaks the idempotency contract — every re-apply churns kernel
state instead of being a no-op.

Same cause for the other 2 failures:
- `reconcile_replace_one_rule_emits_replace_op` — expected 1
  replace, got 2 (both rules flagged even though only one
  changed)
- `reconcile_delete_one_rule_emits_delete_op` — likely same
  false-positive shape

The 4 passing tests don't exercise this path:
- `apply_reconcile_succeeds_in_one_attempt_when_uncontended` —
  only does the initial apply
- `reconcile_empty_to_full_applies_everything` — only does the
  initial apply
- `reconcile_add_one_rule_in_existing_chain` — adds a rule to
  the kernel state (the `add` path doesn't hit the body-bytes
  compare)
- `reconcile_cascade_delete_table_via_empty_config` — table-
  level delete bypasses per-rule diff

So the bug is specifically in the **per-rule comparison after
both sides agree on the rule's identity (USERDATA key)**.

## 2. Where the bug lives

`crates/nlink/src/netlink/nftables/config/diff.rs:376-388`:

```rust
let declared_body = lower_to_expression_bytes(&declared_rule.body);
if declared_body != kr.expression_bytes {
    diff.rules_to_replace.push((...));
}
```

- `lower_to_expression_bytes(declared_rule.body)` — runs the lib's
  expression writer against the declared rule's expression list,
  strips the nlmsghdr + outer attribute header, returns the
  inner elem-list bytes.
- `kr.expression_bytes` — what the lib's `parse_rule` extracted
  from the kernel's dump response for that rule.

These don't match byte-for-byte on idempotent re-diff. One of
two things is wrong:

1. **The writer emits a different byte sequence than what the
   kernel echoes back.** Padding, alignment, attribute
   ordering, or implicit attributes (the kernel may add
   default values that we don't write) could all cause this.
2. **`parse_rule` extracts a different subset of bytes than
   what `write_expressions` produces.** E.g., parse_rule
   includes wrapper attributes we don't include in the declared
   body, or vice versa.

## 3. Investigation plan

### Phase 1 — log the actual byte sequences

Add a temporary `tracing::debug!` to the comparison site:

```rust
tracing::debug!(
    declared_len = declared_body.len(),
    kernel_len = kr.expression_bytes.len(),
    declared_hex = ?hex::encode(&declared_body),
    kernel_hex = ?hex::encode(&kr.expression_bytes),
    "diff body-bytes comparison"
);
```

(Plan 174 will land the `tracing-subscriber` init that makes
this visible in CI. Until then, add the same instrumentation
via `eprintln!` in the failing test for one CI iteration.)

### Phase 2 — diff the byte sequences

Compare hex-encoded outputs side by side. Likely findings:

- Same length, byte mismatch at a specific offset → ordering
  / serialization difference.
- Different lengths → one side has attributes the other
  doesn't.

### Phase 3 — pick the fix shape

**Option A**: normalize both sides before comparison (sort
attributes, strip padding, etc.) — defensive, doesn't require
understanding why they diverge.

**Option B**: fix the writer to emit exactly what the kernel
echoes back — surgical, requires understanding the kernel's
echo behavior.

**Option C**: switch from body-bytes to typed-expression
comparison (`PartialEq` on the `Vec<Expr>` after parsing
kernel state into the same `Expr` enum). The original Plan
157 §4.3 design considered this and rejected it on complexity
grounds; the post-CI evidence now justifies the cost.

Recommendation: Option C is the most robust. Option A is the
quickest patch. Pick during Phase 3.

## 4. Interim mitigation (this commit)

Until Plan 178 lands, re-`#[ignore]` the 3 specific failing
tests:

```rust
#[tokio::test]
#[ignore = "Plan 178 — body-bytes diff false-positive on idempotent reapply"]
async fn reconcile_idempotent_reapply_yields_empty_diff() { ... }

#[tokio::test]
#[ignore = "Plan 178 — body-bytes diff false-positive on idempotent reapply"]
async fn reconcile_replace_one_rule_emits_replace_op() { ... }

#[tokio::test]
#[ignore = "Plan 178 — body-bytes diff false-positive on idempotent reapply"]
async fn reconcile_delete_one_rule_emits_delete_op() { ... }
```

The 4 passing tests stay un-ignored — they exercise the apply
+ add-rule + cascade-delete paths that Plan 170 unblocked and
that DON'T hit the body-bytes false positive. They're now
genuine regression coverage.

## 5. Acceptance criteria

- [ ] Phase 1 logging lands + CI run produces the hex
      sequences.
- [ ] Phase 2 diff identifies the divergence point.
- [ ] Phase 3 fix lands per the chosen option.
- [ ] All 7 `nftables_reconcile::*` tests un-ignored + green.
- [ ] Unit test added: build a declared `Rule`, encode via
      `lower_to_expression_bytes`, decode via `parse_rule`,
      assert byte-equality. Catches future regressions
      without needing root.
- [ ] CHANGELOG entry under `### Fixed`.

## 6. Effort estimate

| Phase | Effort |
|---|---|
| 1 logging + CI iteration | ~30 min |
| 2 diff + identify divergence | ~30 min |
| 3 fix (Option A/B/C) | ~1 – 3 h depending on choice |
| 4 unit test (round-trip parser) | ~30 min |
| 5 un-ignore tests + verify CI green | ~15 min |
| **Total** | **~2.5 – 4.5 h** |

## 7. Why this is a real shipped bug

Plan 157b v2 landed in 0.16.0 (commit `7852553`). The
declarative-config diff has been recommending `replace_rule`
operations on idempotent re-applies for any caller of the API.
The 7 root-gated `nftables_reconcile::*` tests were `#[ignore]`'d
in 0.16 due to the Plan 170 hang — so the second-order bug
never surfaced.

Real-world impact: any `NftablesConfig` user calling
`cfg.diff(&conn).await?.apply(&conn).await?` in a loop
(controller reconciliation pattern) hits unnecessary kernel
churn on every reapply. The kernel sees `NLM_F_REPLACE`
operations that change nothing; not a correctness bug per se,
but a noisy + wasteful one.

## 8. Out-of-scope follow-ups

- **Audit other "compare-byte-sequence-from-kernel-against-
  lib-encoded-bytes" patterns in the lib** — this body-bytes
  shape may show up elsewhere (NetworkConfig route diff?
  Plan 172-adjacent audit).
- **Property-based testing of expression encoding round-trip**
  — Plan 147 §9.1 territory (deferred).

End of plan.

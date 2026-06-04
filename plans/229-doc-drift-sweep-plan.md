---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: Doc-drift sweep + compile-tested examples — close the 0.19 async-ification gap
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_API.md](../AUDIT_API.md) Findings A4, A5, A18, A22
created: 2026-06-04
---

# Plan 229 — Doc-drift sweep + compile-tested examples

## 1. Why this plan exists

0.19 F1 made `Connection::events()`, `Connection::into_events()`,
`Connection::dump_stream`, and the `*_with_resync` constructors
**`async`** — they acquire the per-Connection mutex on first
poll so concurrent callers serialize cleanly. The Finding A
fix-up was correct at the implementation site, but the
**rustdoc examples** + **recipe walkthroughs** + **module-level
landing-page docs** were not swept.

The audit found four classes of drift:

- **A4** — `let mut events = conn.events();` (sync usage) at
  `crates/nlink/src/lib.rs:122-125`,
  `crates/nlink/src/netlink/mod.rs:31,34`,
  `crates/nlink/src/netlink/events.rs:12,15`. Copy-pasting these
  yields a compile error: `events()` returns a Future, not a
  Stream. Worse, the same examples use `let mut conn = ...`
  where `subscribe()` is now `&self` — obsolete on two axes
  at once.

- **A5** — `NetemConfig::new().loss(1.0)` shown across many docs
  but doesn't compile because `loss` takes `Percent`. Six sites
  enumerated under Plan 228 §4; Plan 228 fixes them at the
  imperative-API flip.

- **A18** — Stale CakeConfig docstring pointing at
  `tc/options/cake.rs` as the "legacy string-args interface" —
  that module was deleted in 0.15.0
  (`docs/migration_guide/0.14.0-to-0.15.0.md`).

- **A22** — `connection_for_path_async` doc-comment points at
  `Connection::from_parts` (a `pub(crate)` seam) instead of
  `Connection::for_namespace`.

Plus two known-but-not-yet-audited classes the cycle's PR merges
introduced:

- WG `get_device` private-key behaviour changed in
  merged PR #9 (commit `c571bef`). Any rustdoc or recipe saying
  "private_key always returns None" is now wrong.
- nftables canonical wire form changes (PR #10, commit `9f6bf20`)
  may have made some expr-level examples emit a different byte
  sequence than the recipe asserts. Audit needed.
- 0.19 Plan 211 split `Hook::Ingress` into `NetdevIngress` and
  `InetIngress`. Recipes / examples using `Hook::Ingress` need a
  sweep.
- 0.19 Plan 205 removed `with_purge` /
  `ApplyOptions::with_purge`. Any leftover example references
  need deletion.

## 2. The sweep checklist

A single sweep commit covers every site. The mechanical
substitutions, ordered by leverage:

| Pattern | Replacement | Sites (estimated) |
|---|---|---|
| `conn.events()` (no `.await`) | `conn.events().await` | 4 |
| `conn.into_events()` (no `.await`) | `conn.into_events().await` | 3 |
| `conn.dump_stream::<T>(...)` (no `.await?`) | `conn.dump_stream::<T>(...).await?` | several |
| `let mut conn = Connection::...` (then subscribe/events only) | `let conn = Connection::...` | 5+ |
| `addr.address` (field access on `pub(crate)`) | `addr.address()` (accessor) | 1 confirmed |
| `.loss(1.0)` (on `NetemConfig`) | `.loss(Percent::new(1.0))` | 6 (Plan 228 owns these) |
| `tc/options/cake.rs` reference | remove paragraph or point at `ParseParams` | 1 + sibling configs |
| `Hook::Ingress` | `Hook::NetdevIngress` or `Hook::InetIngress` | sweep needed |
| `with_purge` / `ApplyOptions::with_purge` | delete | sweep needed |
| `Connection::from_parts` in public docs | `Connection::for_namespace(...)` | 1 |
| `private_key: None` claim in WG examples | update to "read-back present" | sweep needed |
| `ConnectionPool::<P>::new(N)?` (in CLAUDE.md) | `ConnectionPoolBuilder::new().size(N).build().await?` | 1 (A9) |

Each pattern is a fixed string substitution. Sweep the workspace:

```bash
# Pre-sweep audit grep (manual; check each hit):
rg -F '.events()' crates/nlink/src/ docs/ crates/nlink/examples/
rg -F '.into_events()' crates/nlink/src/ docs/ crates/nlink/examples/
rg -F '.loss(' --type rust --type md   # cross-check against Plan 228
rg -F 'tc/options/' --type rust --type md
rg -F 'Hook::Ingress' --type rust --type md
rg -F 'with_purge' --type rust --type md
rg -F 'from_parts' --type rust --type md
rg -F 'ConnectionPool::<' --type rust --type md
```

## 3. The doc-test CI gate

The drift surfaced in this audit slipped through because **no CI
gate compiles the rustdoc examples in the lib**. The 0.19 F1
async-ification flipped the underlying signatures and the
implementation tests + integration tests passed (they didn't
exercise the docstring snippets). Doctests are the cheap
prevention.

```yaml
# .github/workflows/ci.yml — new job

doctest-nlink:
  name: doctest (nlink)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    - run: cargo test --doc -p nlink
      env:
        # Plan 173: keep parse-error tests deterministic
        CARGO_INCREMENTAL: 0
```

Plan-of-action for the rollout:

1. **Land §2 sweep first** (this commit goes red against current
   doctest CI if landed concurrently with the gate — sequence
   matters).
2. **Add the CI job as non-blocking for the first week** of the
   0.20 cycle. Use GHA `continue-on-error: true` while the
   sweep stabilises. Surface results in PR comments via the
   existing CI-observability story (Plan 174 / `RUST_LOG`
   conventions).
3. **Promote to blocking** once one cycle's worth of PRs have
   merged with it green.

Scope decision: **only `cargo test --doc -p nlink`** in the
required gate, not `--workspace`. Workspace doctests pull in
bins + examples + nlink-macros + lab. The lab crate's doctests
need root for many of their setup steps; lifting them into CI
would require the privileged-CI runner. Keep nlink-only as the
required gate; let workspace doctests run nightly or behind
`cargo nextest --doc` if/when that's stable.

## 4. Recipe-compile harness

The recipe markdown under `docs/recipes/` is more important than
rustdoc snippets — users land on it first when looking up "how
do I do X." Each recipe walks an end-to-end scenario with a
worked example block. The pattern: extract each `~~~rust` fence
into a synthetic source file under `crates/nlink/tests/recipes/`
and compile (not run) it. This is the same approach `mdbook
test` uses for The Cargo Book.

Implementation sketch:

```rust
// crates/nlink/tests/recipes/main.rs
//
// Synthesised compile-only fixtures from the docs/recipes/*.md
// fenced code blocks. The script that materialises this file is
// scripts/sync-recipe-tests.sh — wired into the
// `audit-recipe-drift.sh` CI gate.
//
// Each recipe's worked example becomes:
//   #[allow(dead_code)]
//   mod _per_peer_impairment {
//       use nlink::*;
//       async fn _example() -> nlink::Result<()> {
//           // … recipe body verbatim …
//           Ok(())
//       }
//   }
//
// The function never runs; the test framework only confirms it
// compiles. Root-gated steps (`nlink::lab::LabNamespace::new`)
// compile fine outside root; they just can't run.

#[cfg(test)]
mod recipes {
    // generated content goes here
}
```

Two halves:

- `scripts/sync-recipe-tests.sh` regenerates the synthesized
  file. Run pre-commit or in CI.
- `scripts/audit-recipe-drift.sh` confirms the synthesized file
  is in sync with the markdown. Fails the build if a recipe was
  edited but the test file wasn't regenerated.

Both feed the existing audit-script-in-CI convention (see
`.github/workflows/ci.yml` and Plan 222's
`audit-uapi-constants.sh`).

## 5. Coordination with Plan 228

Plan 228 (typed `Percent` on declarative builders) flips the
imperative `NetemConfig::loss` already-typed signature's
**callers** to the typed form everywhere. Plan 228 fixes its own
doctests in the same commit. Plan 229's sweep then needs to
confirm Plan 228 caught them all — the doc-test CI gate (§3)
goes red if anything was missed.

Ordering: **228 lands before 229's gate goes blocking**.
228 can ship first; 229's sweep+gate ships either in the same
PR or the next one. If they conflict on the same files (likely
— both touch `tc.rs` rustdoc blocks), 228 wins the rebase since
its API change is the load-bearing one.

## 6. Test plan

1. **Local validation before merge**: run the full sweep,
   then `cargo test --doc -p nlink` clean. Run
   `scripts/sync-recipe-tests.sh && cargo build --workspace
   --all-targets` clean.

2. **CI**: the new `doctest-nlink` job + the new
   `audit-recipe-drift.sh` audit script wired into
   `.github/workflows/ci.yml`.

3. **One-cycle bake**: leave `doctest-nlink` non-blocking
   (`continue-on-error: true`) for 7 days. Promote to blocking
   at end of week if no drift fires.

4. **CHANGELOG entry** under `[Unreleased]`:
   ```markdown
   ### Documentation
   - Doc-drift sweep: rustdoc + recipe + lib.rs examples now
     compile under `cargo test --doc -p nlink` (new CI gate).
     Fixes the 0.19 F1 async-ification gap where `events()`,
     `into_events()`, and `dump_stream*` became `async` but
     example code stayed sync.
   ```

## 7. Risks

- **CI runtime**. `cargo test --doc -p nlink` on a cold CI
  runner takes 4-6 minutes for nlink (rough estimate from the
  existing test-build's cargo-cache hit rate). Acceptable as a
  separate job paralleling the existing 14 gates. Mitigation:
  Swatinem cache + the job's own incremental build kept in the
  GHA cache between PRs.

- **Recipe-test churn**. Every recipe edit will require running
  `sync-recipe-tests.sh`. The audit-drift gate makes the
  forgetfulness loud. Document the workflow in CLAUDE.md's
  `## Documentation` section (a new subsection).

- **Sweep miss**. If §2's mechanical substitutions skip a site,
  the CI gate catches it — but only after merge if the gate is
  non-blocking. The week-long bake (§3 step 3) is the safety
  net.

- **A22 doc says "see another function"**. The minimal A22 fix
  (point at `Connection::for_namespace`) doesn't actually open up
  a new public path; it just stops users from chasing a
  `pub(crate)` constructor. The proper fix — exposing a documented
  public custom-namespace-path constructor — is a separate API
  decision deferred to 0.21. This plan only updates the docstring.

- **PR #9 / PR #10 audit is open-ended**. The 0.20 cycle just
  absorbed two feature PRs whose doc surface I haven't fully
  audited. Mitigation: the doctest gate goes red if either PR's
  examples don't compile; one sweep pass over their changed
  docs is in this plan's scope.

## 8. Acceptance

This plan ships when:

- ✅ Every pattern in §2's table is swept from the workspace.
- ✅ `cargo test --doc -p nlink` passes locally.
- ✅ The `doctest-nlink` CI job is wired (non-blocking initially).
- ✅ The `audit-recipe-drift.sh` audit script is wired into CI.
- ✅ Each recipe's worked example compiles via the synthesized
  `crates/nlink/tests/recipes/main.rs` fixture.
- ✅ One full PR cycle passes with the gate non-blocking and
  green; promote to blocking.
- ✅ CHANGELOG `[Unreleased]` gains the §6 entry.

## 9. Cross-references

- [Plan 220 master](220-0.20-master-plan.md) §3.4 — robustness
  hygiene + doc cluster
- [AUDIT_API.md](../AUDIT_API.md) Findings A4, A5, A18, A22
  (this plan's source)
- [Plan 228 — typed Percent](228-typed-percent-builders-plan.md)
  — coordinates on the `.loss(1.0)` sites
- 0.19 Finding F1 (the async-ification this plan closes the
  drift on) — see `docs/migration_guide/0.18.0-to-0.19.0.md`
- 0.19 Plan 211 (`Hook::Ingress` split) and Plan 205
  (`with_purge` removal) — drift sources this plan sweeps
- 0.19 Plan 214 — prior doc-drift sweep; this plan is the
  follow-on closing what 214 didn't have time for
- CLAUDE.md `## Cookbook` — recipe index this plan adds the
  test fixture for

---
to: nlink maintainers
from: nlink maintainers
subject: CI integration tests harness — privileged GitHub Actions runner for root-gated `lab`-feature tests
target version: 0.15.0 (or whenever the team commits to ongoing CI maintenance)
date: 2026-04-25
status: draft — gating dependency for Plan 137 integration tests, recipe smoke tests, and any future root-gated test addition
related: unblocks Plan 137 integration tests (currently parked); referenced by every "integration test" deferral note in Plans 135 / 137.
---

# CI integration tests harness

## 0. Summary

nlink's integration tests in `crates/nlink/tests/integration*` need
root + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` (network-namespace work,
TC, conntrack mutation, etc.). The maintainer runs `cargo test` as
a regular user, so these tests **don't run by default and bit-rot
between intentional runs**. The Plan 137 roadmap row currently
parks PRs A+B's integration tests "until the CI-with-privileged-
containers backlog row lands"; this plan is that backlog row.

Net effect when this lands:

- Every push triggers a CI job that runs the root-gated tests in a
  privileged container with a known kernel.
- New plans (Plan 137 PRs A+B integration tests, recipe smoke
  tests, Plan 138 PR B golden-hex fixtures, etc.) can land
  `#[tokio::test]`-shaped tests without worrying about bit-rot.
- The `--apply`-style example runners can stay as the
  interactive-validation channel; CI is the always-on belt-and-
  braces backstop.

## 1. Goals & non-goals

### Goals

1. **A GitHub Actions workflow** that runs the integration tests
   under root in a privileged container.
2. **A documented kernel version matrix.** Pin at least two
   versions that we promise to test against (e.g. the latest LTS
   and one rolling) so kernel-version-specific behaviour is
   surfaced.
3. **Skip-if-not-root patterns** in test code, so the same tests
   keep working when run as a regular user (returning
   `Ok(())` early via the existing `nlink::require_root!` macro).
4. **Skip-if-modules-missing patterns** for tests that need
   specific kernel modules (`nf_conntrack`, `nf_conntrack_netlink`,
   `cls_flower`, etc.). Tests log the missing module and skip,
   rather than failing.
5. **Cargo machete clean and clippy clean** in the same CI
   workflow — so the workflow is the single quality gate.

### Non-goals

1. **Non-Linux CI.** nlink is Linux-only by design; macOS/Windows
   CI runners are out of scope.
2. **Cross-architecture testing.** GHA's free tier doesn't expose
   ARM64 reliably; defer until there's a downstream user reporting
   an arch-specific bug.
3. **Performance regression tests.** That's a different kind of
   CI workload (long-running, baselines, statistical analysis).
   Out of scope.
4. **End-to-end fuzzing.** Worth doing eventually but on a
   different cadence than per-push CI.

---

## 2. The constraint that drives the design

GitHub-hosted runners can't run `--privileged` containers
directly, but they can run a container with `--cap-add=NET_ADMIN
--cap-add=SYS_ADMIN --cap-add=NET_RAW` and a `--device=/dev/net/tun`
(the minimum set nlink's integration tests need). Or, the entire
job can run in a Docker container via the `container:` job key.

The simplest route: **declare a `container: { image: ... }` on the
job**, install `cargo`/`rust` inside, and let the GHA runner give
us root inside the container automatically. No matrix-of-VMs
needed; Linux kernel headers are exposed via `/proc/sys` /
`/proc/net/...` from the runner kernel.

The catch: **the kernel version is whatever GHA's runner OS uses**
(usually a fairly recent Ubuntu LTS kernel, currently around
6.11+). If we want to test against an older kernel (say 5.15 LTS)
or against a newer rolling kernel (Linux 6.19 like the maintainer's
Fedora 43), we need either:

- A self-hosted runner pinned to that kernel, or
- A kernel-version matrix using `actions-vmtools` or a similar
  community action that boots VMs.

**Lean: start with the GHA-default kernel only.** Catches most
regressions, no infrastructure cost. Add a matrix later if a
specific kernel version produces a real bug.

---

## 3. Workflow shape

`.github/workflows/integration-tests.yml`:

```yaml
name: Integration tests (root-gated)

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

jobs:
  integration:
    runs-on: ubuntu-latest
    container:
      image: rust:1.85-bookworm
      options: --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=NET_RAW
    steps:
      - uses: actions/checkout@v4
      - name: Install kernel modules + iproute2 (for nf_conntrack autoload + ip netns)
        run: |
          apt-get update
          apt-get install -y iproute2 kmod conntrack
          # nf_conntrack typically auto-loads on first netlink request,
          # but explicit modprobe surfaces missing-module errors early.
          modprobe nf_conntrack || echo "nf_conntrack autoload at first use"
          modprobe nf_conntrack_netlink || echo "nf_conntrack_netlink autoload"
      - name: Run integration tests as root
        env:
          # nlink's integration tests use --test-threads=1 to avoid
          # namespace-name collisions; respect that.
          CARGO_TERM_COLOR: always
        run: |
          cargo test -p nlink --features lab --test integration -- \
              --test-threads=1
      - name: Run unit tests too (just to keep one CI job authoritative)
        run: cargo test -p nlink --lib
      - name: Workspace clippy
        run: cargo clippy --workspace --all-targets -- --deny warnings
      - name: cargo machete
        run: |
          cargo install cargo-machete --locked
          cargo machete
```

Caveats:
- `apt-get install kmod` for `modprobe`. The container runs with
  read-only `/lib/modules` from the host, so `modprobe` may fail
  without bind-mounting; if it does, **rely on the kernel's
  autoload-on-first-netlink-request** behaviour and let the test
  itself detect a missing module via the `is_not_supported()`
  error helper.
- `--test-threads=1` is mandatory for namespace-naming-collision
  reasons (per CLAUDE.md). Don't parallelise.
- `CAP_NET_RAW` is needed for the `ping` invocations inside some
  recipe lab demos.

---

## 4. Skip-if-not-root pattern

Already in place — `nlink::require_root!` returns early with
`Ok(())` when `geteuid() != 0`. Every `#[tokio::test]` that needs
root starts with:

```rust
#[tokio::test]
async fn ct_inject_query() -> nlink::Result<()> {
    nlink::require_root!();
    // ... real test body ...
    Ok(())
}
```

When run as a regular user, the test passes vacuously. When run
under CI (root), it executes for real. **No test should be
unconditionally root-required** — make sure every Plan 137 / Plan
138 / etc. integration test starts with this macro.

---

## 5. Skip-if-modules-missing pattern

Add a small helper `nlink::lab::require_module(name) -> Result<()>`
that reads `/proc/modules` (or tries `socket(NETLINK_NETFILTER)`
and inspects the error) and bails early if the module isn't
loaded. Each integration test that needs a specific module calls
it after `require_root!`:

```rust
#[tokio::test]
async fn ct_inject_query() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::lab::require_module("nf_conntrack")?;
    nlink::lab::require_module("nf_conntrack_netlink")?;
    // ...
    Ok(())
}
```

`require_module` returns `Ok(())` on a successful skip (logged via
`tracing` so CI output shows what was skipped). This is **stricter
than the kernel autoload behaviour** because it gives a clean test
output ("skipped: nf_conntrack module not present") rather than
a cryptic EPROTONOSUPPORT later in the test.

---

## 6. Tests in scope (the inventory CI will start running)

Currently in-tree under `crates/nlink/tests/`:

- `link::*` — interface creation (dummy, veth, bridge, vlan,
  macvlan, etc.)
- `address::*` — IPv4/IPv6 address management
- `route::*` — routing table manipulation
- `tc::*` — qdisc / class / filter
- `events::*` — netlink event monitoring

Future additions blocked on this plan:

- Plan 137 PRs A+B integration tests (4 mutation + 2 events tests
  per Plan 137 §2.3 + §3.3)
- Plan 135 recipe smoke tests (`tests/integration/recipes.rs`)
- Plan 138 u32 filter golden-hex regression tests (Phase 2)

---

## 7. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `.github/workflows/integration-tests.yml` | New workflow file | ~60 |
| `crates/nlink/src/lab/mod.rs` | Add `require_module(name)` helper | ~30 |
| `crates/nlink/src/lab/mod.rs::tests` | Unit tests for `require_module` | ~30 |
| `crates/nlink/tests/integration*` | Audit existing tests, add `require_module` calls where applicable | ~50 across files |
| `CLAUDE.md` | Document the CI workflow + skip-if-not-root + skip-if-modules-missing patterns | ~20 |
| `CHANGELOG.md` | Entry | ~10 |

Total ~200 LOC + ongoing CI maintenance.

---

## 8. Phasing (single PR, no real way to split)

This is a single-PR landing. The workflow file, the helper macro,
and the existing-test audits all need to land together for the CI
job to actually pass on first run. Sub-tasks within the PR:

1. Add `nlink::lab::require_module` helper + tests.
2. Audit existing integration tests, add `require_module` calls.
3. Write the workflow file.
4. Test the workflow on a draft PR, iterate on container-image
   choice / cap-add / module loading until green.
5. Update CLAUDE.md with the new test conventions.

---

## 9. After this lands

The Plan 137 integration tests un-park immediately. Suggested
follow-up plan order:

1. Plan 137 §2.3 mutation integration tests — easiest, validated
   templates already exist in the `--apply` runners.
2. Plan 137 §3.3 events integration tests — same shape, slightly
   trickier (multicast subscription + traffic generation).
3. Plan 135 recipe smoke tests — run each recipe's lab demo
   end-to-end and assert the documented invariants.
4. Plan 138 PR B golden-hex tests — fixtures captured under sudo,
   compared against parser-emitted bytes.

Each of these is its own follow-up commit, ~150-300 LOC each, low
risk because the wire format is already proven by the `--apply`
runners.

---

## 10. Open questions

1. **Kernel module mounting.** If `apt-get install kmod` +
   `modprobe nf_conntrack` doesn't work in the GHA container
   (because `/lib/modules` is read-only from the host), the
   fallback is to rely on autoload. Confirm during PR drafting;
   if autoload is unreliable, the workflow needs
   `--volume /lib/modules:/lib/modules:ro --volume /usr/lib/modules:/usr/lib/modules:ro`
   on the container.
2. **Test runtime budget.** The integration suite is currently
   small (under a minute even with namespace-setup overhead per
   test). Once Plan 137 + Plan 138 tests land, runtime might
   approach 5 minutes. Set a soft ceiling — tests over 30
   seconds individually want investigation.
3. **Kernel version matrix.** Defer until at least one
   kernel-specific bug surfaces. The lift to add a matrix is
   modest (community actions exist) but the maintenance cost
   isn't zero.
4. **Self-hosted runner option.** If the maintainer wants to test
   against Fedora 43's Linux 6.19 specifically (matches the
   `--apply` validation environment), a self-hosted runner is the
   cleanest answer. Cost: one machine + GHA self-hosted runner
   token. Defer until we know whether GHA-default kernel + the
   Linux 6.19 `--apply` runners cover the same ground.

---

## 11. Definition of done

- [ ] `.github/workflows/integration-tests.yml` lands and the job
      goes green on a no-op PR
- [ ] `nlink::lab::require_module` helper + tests
- [ ] All existing root-gated tests use both `require_root!` and
      `require_module(...)` consistently
- [ ] CLAUDE.md `## Integration Tests` section updated with the
      new pattern
- [ ] CHANGELOG entry under `## [Unreleased]` describing the CI
      workflow + the test-author conventions
- [ ] Plan 137 status header updated to remove the "parked" note
      and link to this plan as the unblocker
- [ ] Roadmap "CI integration tests" backlog row removed (replaced
      by this plan reference in the active table)

---

## 12. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| GHA container kernel doesn't expose required modules | Medium | Workflow autoloads on first netlink call; `require_module` skips cleanly otherwise |
| `--cap-add` set isn't enough for some test | Medium | Add caps incrementally; if `--privileged` becomes necessary the workflow needs a dedicated runner |
| Test runtime balloons after Plan 137 + 138 land | Low | Soft 30s per-test ceiling; profile and split if exceeded |
| Maintenance fatigue (new tests fail in CI for kernel-version reasons the maintainer doesn't see locally) | Medium | Document the GHA kernel version in CLAUDE.md so authors know what they're testing against |

End of plan.

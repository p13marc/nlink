# Ignored integration tests — catalog

Every `#[ignore]` in `crates/nlink/tests/integration/*` MUST appear
in this file. The CI audit script `scripts/audit-ignored-tests.sh`
fails on any ignored test missing a catalog entry — see
`CHANGELOG.md ## [0.17.0]` "CI observability" for the original
rationale.

Three legitimate reasons for `#[ignore]`:

1. **Kernel-build-dependent**: works on some kernels, hangs/zero-
   events on others. The lib code is fine; only the *test
   assertion* is fragile. Use `--ignored` locally on a kernel where
   it works.
2. **Tracking-plan-deferred**: a known bug, tracked by a specific
   plan, will be un-ignored when the plan ships.
3. **Migration candidate**: pre-existing `#[ignore]` on a test
   that should use `nlink::require_root!()` instead. Tracked for
   bulk migration; un-ignore when the migration lands.

If you're adding a new `#[ignore]`, prefer a `reason = "…"` string
(syntax: `#[ignore = "reason"]`) and reference the tracking plan
or this catalog.

## conntrack.rs

| Test | Reason | Tracking |
|---|---|---|
| `ct_subscribe_observes_destroy_event_on_del` | kernel-build-dependent | Synthetic ctnetlink-injected entries don't reliably generate visible Destroy events on every kernel build/config; the lib path works (other conntrack tests cover delete + subscribe independently). Run with `--ignored` locally to verify on a kernel where it works. |

## nftables_reconcile.rs

All entries here were un-ignored when the `NftablesDiff` body-
bytes false-positive was fixed in 0.17 (see
`CHANGELOG.md ## [0.17.0]` "NftablesConfig::diff body-bytes
false-positive"). The catalog section is kept as a marker —
if a future regression in this
file is `#[ignore]`'d, add a row here with a tracking plan.

## diagnostics.rs

All 12 tests below carry `#[ignore] // Requires root privileges
for network namespaces`. They're **migration candidates** — the
conventional pattern across the rest of the suite (see
`conntrack.rs`, `nftables_reconcile.rs`, `pool.rs`, …) is to
gate with `nlink::require_root!()` so the test skips on a non-
root developer machine but runs for real in the privileged CI
job. Migrating means: drop the `#[ignore]`, add
`nlink::require_root!();` as the first line of the test body.

Deferred from Plan 174 to keep the observability plan scope-tight.
Open a small follow-up plan to migrate in bulk (12 mechanical
edits + one CI iteration to confirm they pass under root).

| Test | Reason | Tracking |
|---|---|---|
| `test_diagnostics_scan` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_scan_interface` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_scan_interface_not_found` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_check_connectivity_no_route` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_check_connectivity_with_route` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_find_bottleneck` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_with_tc` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_link_down_detection` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_no_address_detection` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_route_summary` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_custom_config` | migration candidate | `#[ignore]` → `nlink::require_root!()` |
| `test_diagnostics_skip_loopback` | migration candidate | `#[ignore]` → `nlink::require_root!()` |

## How to run locally

Run a specific ignored test on a machine where it's safe:

```bash
sudo cargo test -p nlink --features lab --test integration -- \
    --ignored ct_subscribe_observes_destroy_event_on_del
```

Run *all* ignored tests:

```bash
sudo cargo test -p nlink --features lab --test integration -- --ignored
```

## What the audit script checks

`scripts/audit-ignored-tests.sh`:

1. Greps every `#[ignore]` in `crates/nlink/tests/integration/`.
2. Extracts the test function name following each ignore.
3. Cross-references against the test names in this file.
4. Fails (exit 1) if any ignored test isn't catalogued.

This keeps `#[ignore]` from becoming a backdoor for hidden gaps:
every ignore is either fixed (un-ignored), tracked (in a plan),
or explicitly accepted (in this catalog).

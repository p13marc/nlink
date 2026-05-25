# Release-validation manual

Pre-cut checklist for hardware-only features — paths that no CI
runner can exercise. Plan 176 §3.3 deliverable for the 0.17
cycle.

Read this before running `scripts/cut-release.sh` — the cut
script prints a one-liner pointer at start, but the actual
exercise here is on the maintainer.

## Why this exists

Some lib paths require real NIC hardware that no GitHub-hosted
runner has:

- **XFRM IPsec offload** (`XfrmSaBuilder::offload()`) — needs a
  NIC with crypto offload (mlx5, cxgb4, hns3, …).
- **Devlink rate limits** + **port function state** — need a
  devlink-capable NIC, typically a Mellanox ConnectX with
  SR-IOV.
- **`net_shaper` capabilities + set/get** — needs a NIC whose
  driver implements the `net-shaper` family (kernel 6.13+;
  sparse driver list as of late 2025).

The lib code is hand-traced against kernel UAPI and unit-tested
at the wire-format level, but the only way to confirm
end-to-end correctness on these is to run the `--apply` example
against real hardware. The 0.16 pre-cut audit caught a wire-
format bug in `set_port_function_state` (attribute ID 174 vs.
the correct 2) — code-inspection-only ≠ tested.

## Cutoff convention

Features in this category get a CHANGELOG annotation at ship:

> ⚠ No CI coverage — manually validated YYYY-MM-DD against
> `<hardware description>` running `<kernel version>`. Update
> this annotation on every subsequent cut that touches the path.

If the feature ships without an annotation, the cut script
should treat that as a defect (Plan 176 §7 mitigation).

## Pre-cut checklist

Tick each box on the cut PR before merging. If you don't have
hardware for a path, write "skipped: no hardware this cycle" —
that's a known gap, not a silent regression.

### XFRM IPsec offload

Hardware: any NIC with `crypto offload` support (mlx5,
chelsio cxgb4, hisilicon hns3, …). Confirm via `ethtool -k
<iface> | grep -i ipsec`.

```bash
# Should succeed; an SA is added with HW offload, then deleted.
sudo cargo run --example xfrm_ipsec_monitor --features lab -- --apply
```

Expected: SA added, listed via `ip xfrm state`, dump confirms
`offload dev <iface>` attribute present, then deleted. Failure
mode to watch: `EOPNOTSUPP` from `add_sa` indicates the NIC
driver doesn't actually accept the offload request — re-run
against a different model to isolate driver vs. lib path.

### Devlink rate limits

Hardware: devlink-capable NIC, typically Mellanox ConnectX-4+
in SR-IOV mode. Confirm via `devlink dev show`.

```bash
# Quick exercise: add a rate node, set tx_max, list, delete.
# (Adapt the example invocation; no canonical --apply runner yet.)
sudo cargo run --example genl_devlink -- list-rates <pci-addr>
```

Expected: rate listing matches `devlink port function rate show`.
If the lib reports rates `devlink` doesn't, the wire-format
parsing is over-eager.

### Devlink port function state

Same hardware. **High-risk path** — the 0.16 audit found a wire-
format bug here.

```bash
sudo cargo run --example genl_devlink -- \
    set-port-function-state <pci-addr> active
```

Expected: `devlink port show <pci-addr>` reports `function.state
active`. The lib's request must use attribute ID 2 (NOT 174,
which is what an older revision used).

### `net_shaper` capabilities

Hardware: NIC with `net_shaper` driver support. Kernel 6.13+
minimum. As of late 2025, only a handful of mlx5 driver
revisions ship this; check via `cat /proc/modules | grep mlx5`
and run a probe.

```bash
sudo cargo run --example genl_net_shaper -- get-caps <iface>
```

Expected: capabilities response parses cleanly; bandwidth,
burst, priority, weight all decode. If the parser hits an
"unknown attribute" surface, the driver may be reporting a
newer attribute set than the lib models.

### Per-cycle smoke pass

Beyond the targeted hardware paths above, run the full `--apply`
example suite on a dev host as a regular user (no root). They
should all skip cleanly:

```bash
for ex in crates/nlink/examples/*.rs; do
    name=$(basename "$ex" .rs)
    cargo run --example "$name" -- --apply 2>&1 | tail -3
done
```

Each should print either "skipping: requires root" or actual
output. None should crash.

## Documenting validation in the CHANGELOG

For every hardware-only feature touched in a cycle, append the
annotation under its entry:

```markdown
- **`XfrmSaBuilder::offload()` now sets …** (Plan 18X)
  > ⚠ No CI coverage — manually validated 2026-09-15 against
  > Mellanox ConnectX-6 Dx (mlx5_core) on Linux 6.10.
```

The annotation is informational for users; the cut script
doesn't enforce its presence (yet). Repeat-validation each cycle
even if the code path didn't change — driver behavior shifts
across kernel revisions.

## Future paths (not 0.17)

Plan 176 §3.1 and §3.2 sketch two real-CI options that don't
exist today:

- **Self-hosted hardware runner** (~$1000 used NIC, colo,
  maintenance time): a future plan if nlink picks up downstream
  adopters with critical-infrastructure requirements.
- **Vendor cloud lab cycle** (~$50/cycle, runs once per cut
  rather than per PR): a future plan if 0.17 surfaces a
  hardware-touching regression that this manual process misses.

Until one of those lands, this checklist IS the test plan.

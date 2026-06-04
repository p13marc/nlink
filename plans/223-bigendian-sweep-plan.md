---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit findings B1-B3 (2026-06-04)
subject: Big-endian wire-parsing sweep + s390x CI compile gate
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_BUGS.md](../AUDIT_BUGS.md) B1, B2, B3
created: 2026-06-04
---

# Plan 223 — Big-endian wire-parsing sweep + s390x CI compile gate

## 1. Why this plan exists

The 0.19 N3 fix swapped `from_le_bytes` for `from_ne_bytes` on
NLA TLV-header parsing in **one** file (`xfrm.rs`). The fix
shipped with an explicit code comment flagging the bug class:

```rust
// xfrm.rs:1955-1960 — 0.19 N3, currently in tree
// native-endian (per `struct nlattr` in include/uapi/linux/netlink.h
// and nlink's canonical `NlAttr` in `attr.rs` using zerocopy
// native-endian). Was `from_le_bytes` — silently broken on
// BE platforms.
let len = u16::from_ne_bytes([input[0], input[1]]) as usize;
let attr_type = u16::from_ne_bytes([input[2], input[3]]);
```

The comment named the class; the sweep was scoped to one file.
Three more files have the identical broken shape and were not
touched:

| File:line | What it parses |
|---|---|
| `crates/nlink/src/netlink/netfilter.rs:1085-1086` | conntrack NLA header in `parse_nla` |
| `crates/nlink/src/netlink/action.rs:3541-3542` (+ `3660`, `3672`) | TC-action TLV walker + `tc_action_index` |
| `crates/nlink/src/netlink/nftables/config/diff.rs:84-88, 737-738` | declarative-diff canonicalizer NLA walk |

NLA headers are kernel-**native** endian — `struct nlattr` in
`include/uapi/linux/netlink.h` is `__u16 nla_len; __u16 nla_type;`
with no endianness annotation, and nlink's canonical zerocopy
`NlAttr` matches. On x86 and aarch64 the bug is invisible
(everything is LE). On s390x and PowerPC-BE, every conntrack
parse, every TC-action walk, and every nftables reconcile pass
silently parses garbage.

Two pieces of audit-time work close the class for good:

- **The sweep itself** — three one-line edits.
- **`scripts/audit-bytes-le.sh`** — CI gate that fails the
  build if `from_le_bytes` reappears in
  `crates/nlink/src/netlink/` outside an explicitly allowed
  list. Same shape as `scripts/audit-sysfs-in-lib.sh` (CLAUDE.md
  `## util::ifname sysfs reads — namespace policy`).
- **`cargo check --target s390x-unknown-linux-gnu`** as a new CI
  job. No tests run (no BE hardware in CI); compile-only
  verification that the structural fix doesn't introduce
  BE-only regressions and that future changes don't break the
  target.

## 2. The change

### 2.1 The three file edits

```rust
// crates/nlink/src/netlink/netfilter.rs:1085-1086 — corrected
// Was `from_le_bytes`; NLA headers are native-endian
// (Plan 223 — 0.19 N3 sweep follow-up).
let len = u16::from_ne_bytes([input[0], input[1]]) as usize;
let attr_type = u16::from_ne_bytes([input[2], input[3]]);
```

```rust
// crates/nlink/src/netlink/action.rs:3541-3542 — corrected
let len = u16::from_ne_bytes([input[0], input[1]]) as usize;
let attr_type = u16::from_ne_bytes([input[2], input[3]]);

// action.rs:3660 — corrected (tc_action_index u32)
index = u32::from_ne_bytes([
    payload[0], payload[1], payload[2], payload[3],
]);

// action.rs:3672 — same shape, same fix
```

```rust
// crates/nlink/src/netlink/nftables/config/diff.rs:84-88 — corrected
let len  = u16::from_ne_bytes([bytes[pos], bytes[pos + 1]]) as usize;
let raw_type = u16::from_ne_bytes([bytes[pos + 2], bytes[pos + 3]]);

// diff.rs:737-738 — same shape, same fix
```

`action.rs` has three more `from_le_bytes` reads at lines 4074,
4090, 4092 — all inside `#[cfg(test)]` fixture-builder code that
only runs in tests (which only run on x86). Flip those too for
hygiene; they're identical one-line edits and keep the file
greppable-clean.

### 2.2 The audit script

```bash
#!/usr/bin/env bash
# scripts/audit-bytes-le.sh
# Plan 223 — block `from_le_bytes` re-entry in the netlink lib.
# NLA headers + attribute payloads are kernel-native endian per
# include/uapi/linux/netlink.h. The few documented
# LE-on-the-wire cases (none today) belong in ALLOWED.

set -euo pipefail

# Explicitly allowed sites. Add new entries with a comment
# explaining why the byte stream is LE-on-the-wire (rare).
ALLOWED=(
    # (intentionally empty as of 0.20 — every NLA / TC / nft /
    # xfrm / conntrack TLV the kernel emits is native-endian.)
)

# Build a grep exclude list from ALLOWED.
exclude_args=()
for path in "${ALLOWED[@]}"; do
    exclude_args+=(--exclude="$path")
done

# Search the production lib tree only — test fixtures may have
# legitimate hardcoded LE readers (cross-arch test data).
hits=$(
    grep -rn --include='*.rs' \
        "${exclude_args[@]}" \
        'from_le_bytes' \
        crates/nlink/src/netlink/ || true
)

if [[ -n "$hits" ]]; then
    echo "ERROR: from_le_bytes found in netlink lib outside ALLOWED:" >&2
    echo "$hits" >&2
    echo "" >&2
    echo "NLA headers and attribute payloads are kernel-native" >&2
    echo "endian. If your case is genuinely LE-on-the-wire, add" >&2
    echo "the file path to ALLOWED in scripts/audit-bytes-le.sh" >&2
    echo "with a comment explaining the kernel-side wire contract." >&2
    echo "See Plan 223 and CLAUDE.md `## Parser robustness`." >&2
    exit 1
fi
```

### 2.3 The s390x compile job

```yaml
# .github/workflows/ci.yml — new job
big-endian-check:
  name: cargo check (s390x, BE)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Install Rust + s390x target
      run: |
        rustup toolchain install stable
        rustup target add s390x-unknown-linux-gnu
        sudo apt-get update
        sudo apt-get install -y gcc-s390x-linux-gnu
    - name: Configure cross-linker
      run: |
        mkdir -p .cargo
        cat >> .cargo/config.toml <<'EOF'
        [target.s390x-unknown-linux-gnu]
        linker = "s390x-linux-gnu-gcc"
        EOF
    - name: cargo check --target s390x-unknown-linux-gnu
      run: cargo check --target s390x-unknown-linux-gnu -p nlink
```

The job is fast (compile-only, no link of binaries, no test
run). It guards against three classes:

1. Any new `[u8; N]::try_from(...).unwrap()` that depends on
   byte width but is silently fine on LE — surfaces as size /
   alignment mismatches.
2. Any new `u32`/`u64` byte transmute that pretends to be
   endian-neutral but isn't.
3. Any future struct-field type-width change that compiles on
   LE but trips struct-size assertions on BE (zerocopy is
   strict about layout).

`cargo check` is enough — we're not running tests against
qemu-s390x because the cycle's prevention budget doesn't
include kernel-on-BE hardware. The compile gate is the cheap
guard; reproducing real BE behaviour is out of scope.

## 3. Test plan

### 3.1 Unit test that locks the policy

```rust
// crates/nlink/src/netlink/attr.rs — new test module
#[cfg(test)]
mod nla_header_endianness_tests {
    /// Lock the policy: NLA headers round-trip through
    /// `from_ne_bytes` / `to_ne_bytes` and the bytes the
    /// kernel saw are the bytes we get out. This test
    /// fails the moment anyone reintroduces `from_le_bytes`
    /// for an NLA header.
    #[test]
    fn nla_header_round_trips_native_endian() {
        let len: u16 = 0x0102;
        let kind: u16 = 0x0304;
        let bytes = [
            len.to_ne_bytes()[0],
            len.to_ne_bytes()[1],
            kind.to_ne_bytes()[0],
            kind.to_ne_bytes()[1],
        ];
        let parsed_len  = u16::from_ne_bytes([bytes[0], bytes[1]]);
        let parsed_kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        assert_eq!(parsed_len, len);
        assert_eq!(parsed_kind, kind);
    }
}
```

### 3.2 Per-site regression tests

For each of the three fixed files, add a unit test that builds
an attribute chain by hand using `to_ne_bytes` and asserts the
parser extracts the same `len` / `type` back. No-op on LE,
diagnostic on BE.

### 3.3 CI gates that must pass

1. `cargo build --workspace --all-targets` — unchanged.
2. `cargo test -p nlink --lib` — covers the new unit tests.
3. `bash scripts/audit-bytes-le.sh` — new gate.
4. `cargo check --target s390x-unknown-linux-gnu -p nlink` —
   new gate.

## 4. Migration

Pure-internal correctness fix. No public API changes. The user
opting into BE platforms (s390x, PowerPC-BE) finds nlink works.
On LE (the common case) nothing observable changes.

If a downstream consumer maintains an out-of-tree netlink
parser and reads NLA headers via `from_le_bytes` directly,
they're broken on BE already; the migration guide will mention
the convention so they know to flip.

CHANGELOG entry under `[Unreleased]`:

```markdown
### Fixed

- **`from_le_bytes` on NLA TLV headers in `netfilter.rs`,
  `action.rs`, `nftables/config/diff.rs`** — same bug class
  0.19 N3 fixed in `xfrm.rs`; the sweep was scoped to one
  file in 0.19 and missed three more sites. NLA headers are
  kernel-native endian; the broken sites silently mis-parsed
  every conntrack / TC-action / nftables-diff frame on s390x
  and PowerPC-BE. On x86 / aarch64 the bug was invisible.
  Plan 223.

### Added

- `scripts/audit-bytes-le.sh` CI gate — fails the build if
  `from_le_bytes` appears in `crates/nlink/src/netlink/`
  outside an explicitly allowed list. Future drift impossible.
- `cargo check --target s390x-unknown-linux-gnu` CI job —
  compile-only verification that the lib builds clean on BE.
  No tests run (no BE hardware in CI).
```

## 5. Risks

- **No live BE testing**. The compile job catches structural
  defects but not behavioural ones. A future bug where `to_ne_bytes`
  is used on a field that's spec'd LE-on-the-wire (rare; not
  netlink-shaped) would compile clean on s390x but ship wrong
  bytes. Mitigation: the per-site regression tests in §3.2 walk
  the parse path explicitly. If someone has access to a real
  s390x box they can manually run `cargo test --target
  s390x-unknown-linux-gnu`; not gated in CI.

- **`scripts/audit-bytes-le.sh` false-positive surface**. If a
  legitimate LE-on-the-wire case appears (e.g., a new GENL
  family with documented LE wire), the script blocks it
  without nuance. The `ALLOWED` list is the escape hatch;
  reviewers will see ALLOWED additions in PR diffs and can
  push back if the justification doesn't hold.

- **s390x toolchain churn**. The cross-linker
  (`gcc-s390x-linux-gnu`) is an apt package; Ubuntu LTS keeps
  it stable across cycles. If the runner image swaps to a
  distro without it, the job fails until the install step is
  updated. Acceptable cost.

- **Conflict with `action.rs` test fixtures**. The test-cfg
  `from_le_bytes` reads at lines 4074/4090/4092 are inside
  test data that's only consumed on x86. Flipping them to
  `from_ne_bytes` keeps the file greppable-clean and doesn't
  change behaviour anywhere. No risk; mentioned for clarity.

## 6. Acceptance

- ✅ All three file edits land in one PR.
- ✅ `scripts/audit-bytes-le.sh` exists, is executable, and
  passes against the fixed tree.
- ✅ `.github/workflows/ci.yml` includes the s390x compile job;
  it's green on the cut head.
- ✅ The per-site unit tests in §3.1 / §3.2 pass on x86 and
  the `nla_header_round_trips_native_endian` test compiles
  clean on s390x.
- ✅ The migration-guide bullet (§4) is in
  `docs/migration_guide/0.19.0-to-0.20.0.md` at cut time.

## 7. Cross-references

- [`AUDIT_BUGS.md`](../AUDIT_BUGS.md) B1 (netfilter.rs),
  B2 (action.rs), B3 (nftables/config/diff.rs) — full
  reproducers and analysis.
- 0.19 N3 fix at `crates/nlink/src/netlink/xfrm.rs:1955-1961`
  — the comment that named the bug class but didn't sweep it.
- [`scripts/audit-sysfs-in-lib.sh`](../scripts/audit-sysfs-in-lib.sh)
  — same audit-script shape Plan 223 mirrors.
- [Plan 220 master](220-0.20-master-plan.md) §2 "Cycle theme"
  — endianness drift as a recurring class the cycle closes
  systemically.
- [Plan 222](222-sizeof-gate-constants-plan.md) — sibling
  prevention plan; both Plan 222 (constants) and Plan 223
  (endianness) are the durable build-time guards for 0.20.
- Kernel `include/uapi/linux/netlink.h` `struct nlattr` —
  the native-endian wire contract.

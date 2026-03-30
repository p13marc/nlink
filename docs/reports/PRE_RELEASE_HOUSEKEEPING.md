# Pre-Release Housekeeping Report

**Date:** 2026-03-30
**Current version:** 0.12.0 (unreleased changes pending)

---

## Code Quality

The codebase is in excellent shape:
- Zero `TODO`/`FIXME`/`HACK` comments
- Zero `.unwrap()` in production code
- Zero `#[allow()]` suppressions
- Zero `#[deprecated]` markers
- All dependencies up-to-date

---

## Issues Found

### 1. README.md Version Mismatch

README still says `nlink = "0.11"` (3 places). Should be `"0.12"`.

**Files:** `README.md` lines 25, 28, 31

### 2. Five Doc Link Warnings

```
warning: unresolved link to `get_interface_names`     → connection.rs:715
warning: unresolved link to `Connection::timeout`     → error.rs:356
warning: unresolved link to `BpfInfo`                 → filter.rs:2302
warning: unresolved link to `get_phys`                → nl80211/connection.rs:483
warning: unclosed HTML tag `Mptcp`                    → mptcp/connection.rs:1
```

### 3. CLAUDE.md Missing Documentation

Two recently added features have no CLAUDE.md entries:
- `set_wiphy_netns()` / `set_wiphy_netns_pid()` — nl80211 PHY namespace movement
- `spawn_with_etc()` — already partially documented (added during Plan implementation)

### 4. Missing Integration Tests for Plan A Methods

| Method | Test? |
|--------|-------|
| `enslave()` | No |
| `add_address_by_name()` | No |
| `replace_address_by_name()` | No |
| `del_netem()` | Yes (renamed) |
| nftables match expressions | No |

### 5. Prelude Module Too Minimal

Current exports: `Connection`, `Error`, `Result`, `Route`, `Generic`, `NetworkEvent`,
`RtnetlinkGroup`, `LinkMessage`.

Missing high-frequency types: `Ipv4Route`, `Ipv6Route` (used in nearly every routing
example).

### 6. Root Directory Clutter

Four external feedback/request files in the repo root:
- `NLINK_FEEDBACK_REPORT.md`
- `NLINK_FEATURE_REQUEST_MOUNT_NS.md`
- `NLINK_FEATURE_REQUEST_WIPHY_NETNS.md`
- `ANALYSIS.md`

Should be moved to `docs/external/` or removed.

### 7. Remaining nlink-lab Feedback Items (Lower Priority)

Not blocking release but worth tracking:
- `get_netem_config()` readback — return structured config from existing qdisc
- `namespace::interface_exists()` — lightweight check without full connection
- VRF support in `NetworkConfig`

---

## Recommended Actions Before Release

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | Fix README version (0.11 → 0.12) | 1 min | High |
| 2 | Fix 5 doc link warnings | 15 min | Medium |
| 3 | Add `set_wiphy_netns` to CLAUDE.md | 5 min | Medium |
| 4 | Expand prelude with `Ipv4Route`, `Ipv6Route` | 5 min | Medium |
| 5 | Move external .md files to docs/external/ | 5 min | Low |
| 6 | Add integration tests for enslave, address_by_name | 30 min | Medium |

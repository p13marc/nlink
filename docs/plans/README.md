# Binary Improvement Plans

This directory contains implementation plans for improving nlink binaries and creating new ones.

## Plan Index

### Existing Binary Improvements

| Plan | Binary | Feature | Effort | Priority |
|------|--------|---------|--------|----------|
| [017](017-ip-nexthop-command.md) | `ip` | Add `nexthop` command | Half day | **High** |
| [018](018-ip-mptcp-command.md) | `ip` | Add `mptcp` command | Half day | **High** |
| [019](019-tc-chain-command.md) | `tc` | Add `chain` command | Half day | **High** |
| [024](024-ip-sr-command.md) | `ip` | Add `sr` command (SRv6) | 1 day | Medium |
| [025](025-ip-macsec-command.md) | `ip` | Add `macsec` show | Half day | Medium |
| [026](026-ss-improvements.md) | `ss` | Summary, kill, netlink | 1 day | Medium |

### New Binaries

| Plan | Binary | Description | Effort | Priority |
|------|--------|-------------|--------|----------|
| [020](020-nlink-bridge-binary.md) | `nlink-bridge` | Bridge FDB + VLAN management | 2-3 days | **High** |
| [021](021-nlink-wg-binary.md) | `nlink-wg` | WireGuard management | 2-3 days | Medium |
| [022](022-nlink-diag-binary.md) | `nlink-diag` | Network diagnostics | 2 days | Medium |
| [023](023-nlink-config-binary.md) | `nlink-config` | Declarative configuration | 2 days | Medium |

## Recommended Implementation Order

### Phase 1: Quick Wins (1 week)
Expose existing library functionality via CLI:

1. **Plan 017** - `ip nexthop` - Full nexthop support exists in library
2. **Plan 018** - `ip mptcp` - Full MPTCP support exists in library
3. **Plan 019** - `tc chain` - Full chain support exists in library

### Phase 2: New High-Value Binary (1 week)

4. **Plan 020** - `nlink-bridge` - FDB and VLAN management (popular use case)

### Phase 3: Extended Features (2 weeks)

5. **Plan 021** - `nlink-wg` - WireGuard management
6. **Plan 022** - `nlink-diag` - Network diagnostics (unique value)
7. **Plan 023** - `nlink-config` - Declarative configuration (unique value)

### Phase 4: Polish (ongoing)

8. **Plan 024** - `ip sr` - SRv6 support
9. **Plan 025** - `ip macsec` - MACsec display
10. **Plan 026** - `ss` improvements

## Summary by Binary

### `nlink-ip` Improvements

| Command | Plan | Status | Library Support |
|---------|------|--------|-----------------|
| `ip nexthop` | 017 | Planned | ✓ Complete |
| `ip mptcp` | 018 | Planned | ✓ Complete |
| `ip sr` | 024 | Planned | ✓ Complete |
| `ip macsec` | 025 | Planned | ✓ Complete |

### `nlink-tc` Improvements

| Command | Plan | Status | Library Support |
|---------|------|--------|-----------------|
| `tc chain` | 019 | Planned | ✓ Complete |

### `nlink-ss` Improvements

| Feature | Plan | Status | Library Support |
|---------|------|--------|-----------------|
| Summary mode | 026 | Planned | ✓ Complete |
| Kill mode | 026 | Planned | Partial |
| Netlink sockets | 026 | Planned | Needed |

### New Binaries

| Binary | Plan | Status | Library Support |
|--------|------|--------|-----------------|
| `nlink-bridge` | 020 | Planned | ✓ Complete |
| `nlink-wg` | 021 | Planned | ✓ Complete |
| `nlink-diag` | 022 | Planned | ✓ Complete |
| `nlink-config` | 023 | Planned | ✓ Complete |

## Library Coverage Analysis

All planned binary features have **existing library support** from Plans 001-014:

- **Plan 005** (Nexthops) → `ip nexthop`
- **Plan 009** (MPTCP) → `ip mptcp`
- **Plan 010** (TC Chains) → `tc chain`
- **Plan 007** (SRv6) → `ip sr`
- **Plan 008** (MACsec) → `ip macsec`
- **Plan 002** (FDB) → `nlink-bridge fdb`
- **Plan 003** (VLAN) → `nlink-bridge vlan`
- **Plan 012** (Config) → `nlink-config`
- **Plan 014** (Diagnostics) → `nlink-diag`
- WireGuard GENL → `nlink-wg`

The library is ahead of the binaries - these plans catch up the CLI.

## Effort Estimates

| Effort | Plans |
|--------|-------|
| Half day | 017, 018, 019, 025 |
| 1 day | 024, 026 |
| 2 days | 022, 023 |
| 2-3 days | 020, 021 |
| **Total** | ~15-18 days |

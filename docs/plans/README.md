# Implementation Plans

This directory contains detailed implementation plans for nlink improvements and new features.

## Priority 0: Compliance Fixes

These should be addressed immediately before implementing new features.

| # | Plan | Effort | Status | Report |
|---|------|--------|--------|--------|
| 0 | [Zerocopy Compliance](./000-zerocopy-compliance.md) | Low | Completed | [Report](../reports/000-zerocopy-compliance.md) |

## Priority 1: High Impact, Low-Medium Effort

These should be implemented first as they provide the most value for common use cases.

| # | Plan | Effort | Status | Report |
|---|------|--------|--------|--------|
| 1 | [Expose TC Class API](./001-tc-class-api.md) | Low | Completed | [Report](../reports/001-tc-class-api.md) |
| 2 | [Bridge FDB Management](./002-bridge-fdb.md) | Medium | Completed | [Report](../reports/002-bridge-fdb.md) |
| 3 | [Bridge VLAN Filtering](./003-bridge-vlan.md) | Medium | Completed | [Report](../reports/003-bridge-vlan.md) |
| 4 | [HTB Class Typed Builder](./004-htb-class-builder.md) | Low | Completed | [Report](../reports/004-htb-class-builder.md) |

## Priority 2: High Impact, High Effort

Important features that require more substantial work.

| # | Plan | Effort | Status | Report |
|---|------|--------|--------|--------|
| 5 | [Nexthop Groups](./005-nexthop-groups.md) | High | Completed | [Report](../reports/005-nexthop-groups.md) |
| 6 | [MPLS Routes](./006-mpls-routes.md) | High | Completed | [Report](../reports/006-mpls-routes.md) |
| 7 | [Segment Routing (SRv6)](./007-srv6.md) | High | Completed | [Report](../reports/007-srv6.md) |

## Priority 3: Medium Impact

Useful features for specific use cases.

| # | Plan | Effort | Status | Report |
|---|------|--------|--------|--------|
| 8 | [MACsec Configuration](./008-macsec.md) | Medium | Completed | [Report](../reports/008-macsec.md) |
| 9 | [MPTCP Endpoints](./009-mptcp.md) | Medium | Completed | [Report](../reports/009-mptcp.md) |
| 10 | [TC Filter Chains](./010-tc-chains.md) | Low | Planned | |

## Priority 4: Feature Ideas

Cool features that would enhance the library's capabilities.

| # | Plan | Effort | Status |
|---|------|--------|--------|
| 11 | [Integration Tests Infrastructure](./011-integration-tests.md) | Medium | Planned |
| 12 | [Declarative Network Config](./012-declarative-config.md) | High | Planned |
| 13 | [Rate Limiting DSL](./013-rate-limit-dsl.md) | Medium | Planned |
| 14 | [Network Diagnostics](./014-network-diagnostics.md) | Medium | Planned |

## Implementation Guidelines

**All implementations must follow the project guidelines** documented in [GUIDELINES.md](./GUIDELINES.md):

1. **Strongly Typed**: Use enums and typed builders, not raw integers or strings
2. **High Level API**: Hide netlink complexity, provide `Connection<Protocol>` methods
3. **Async (Tokio)**: All I/O methods must be `async`
4. **Zerocopy**: Kernel structures use `#[repr(C)]` + zerocopy derives
5. **Winnow**: Message parsing implements `FromNetlink` trait with winnow combinators

## How to Use These Plans

1. Read [GUIDELINES.md](./GUIDELINES.md) first
2. Pick a plan from the list above
3. Read through the implementation details
4. Create a feature branch: `git checkout -b feature/plan-XXX-name`
5. Implement following the plan's steps
6. Verify compliance with guidelines checklist
7. Run tests: `cargo test -p nlink`
8. Run clippy: `cargo clippy -p nlink --all-targets -- -D warnings`
9. Create a report in `docs/reports/XXX-plan-name.md`
10. Update this README to mark the plan as "Completed" with a link to the report
11. Submit for review

## Plan Template

Each plan follows this structure:

```markdown
# Feature Name

## Overview
Brief description of what this feature does.

## Motivation
Why this feature is needed.

## Design
### API Design
### Implementation Details
### File Changes

## Implementation Steps
Step-by-step guide.

## Testing
How to test the implementation.

## Documentation
What docs need updating.

## Future Work
Optional enhancements.
```

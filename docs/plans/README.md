# Plans

Implementation plans for nlink features and improvements.

## Active Plans

No active plans. The nlink library is feature-complete for the nlink-lab use case.

nlink-lab development is tracked in its own repository:
[github.com/p13marc/nlink-lab](https://github.com/p13marc/nlink-lab)

## Reference Documents

| File | Description |
|------|-------------|
| [GUIDELINES.md](GUIDELINES.md) | Implementation guidelines (zerocopy vs winnow, coding patterns) |

## Backlog

| Item | Priority | Notes |
|------|----------|-------|
| CI integration tests | Medium | GitHub Actions with privileged containers |
| MACsec enhancements | Medium | Device creation, stats, hardware offload |
| SRv6 advanced features | Low | HMAC, policy, uSID, counters |
| Additional edge case tests | Low | Error conditions, race conditions |
| `ss` binary remaining features | Low | Kill mode, expression filters, DCCP/VSOCK |
| VRF in NetworkConfig | Low | Add `DeclaredLinkType::Vrf` variant |

## Completed Plans (removed)

Plans 000-039 have been implemented and their files removed.
See git history for reference.

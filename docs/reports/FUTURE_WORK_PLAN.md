# Future Work Plan

## nlink-lab

nlink-lab development has moved to its own repository:
[github.com/p13marc/nlink-lab](https://github.com/p13marc/nlink-lab)

## Recently Completed (Plans A-D, based on nlink-lab feedback)

| Item | Plan | Status |
|------|------|--------|
| `add_address_by_name` / `replace_address_by_name` | A | Done |
| `enslave()` / `enslave_by_index()` | A | Done |
| `OperState` Display impl | A | Done |
| Interface name validation in `add_link` | B | Done |
| Typed error promotion (InterfaceNotFound, QdiscNotFound) | B | Done |
| KernelWithContext enrichment for key operations | B | Done |
| Async GENL namespace connections (`connection_for_async`) | C | Done |
| nftables match expressions (l4proto, ICMP, sport, mark, negation) | D | Done |

## nlink Backlog

| Item | Priority | Notes |
|------|----------|-------|
| CI integration tests | Medium | GitHub Actions with privileged containers |
| SRv6 advanced features | Low | HMAC, policy, uSID, counters |
| Additional edge case tests | Low | Error conditions, race conditions |
| VRF in NetworkConfig | Low | Add `DeclaredLinkType::Vrf` variant |
| `get_netem_config` readback | Medium | Return `NetemConfig` from current qdisc state |
| Two-sample diagnostic scan | Low | One-shot rate measurement with configurable sleep |
| `namespace::interface_exists` | Low | Lightweight check without full connection |

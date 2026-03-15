# Plans

Implementation plans for nlink features and improvements.

## Plan Index

### Tier 1: Quick Wins (Days)

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [028](028-tunnel-link-types.md) | Library | GRE/GRETAP, IPIP, SIT tunnel link types with typed builders | 1 day |
| [032](032-operation-timeouts.md) | Library | Configurable timeouts for netlink operations | 1 day |
| [035](035-code-quality.md) | Library/Bins | SAFETY comments, optional serde_json, ip6gre fix, unwrap cleanup | 1 day |

### Tier 2: Medium-Term (Weeks)

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [026](026-ss-improvements.md) | Binary | Kill mode, expression filters, netlink/VSOCK/TIPC sockets | 1 week |
| [030](030-netlink-batching.md) | Library | Bulk operations via batched sendmsg with per-op results | 1.5 weeks |
| [031](031-bond-support.md) | Library | Complete bond mode/slave management with typed enums | 1 week |
| [034](034-bpf-tc-attachment.md) | Library | BPF program attachment to TC hooks, info parsing | 1 week |

### Tier 3: Strategic (Months)

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [033](033-nftables.md) | Library | nftables firewall (tables, chains, rules, expressions) | 4+ weeks |
| [036](036-nl80211-wifi.md) | Library | WiFi configuration via nl80211 GENL | 2-3 weeks |
| [037](037-devlink.md) | Library | Hardware device management via devlink GENL | 2-3 weeks |

## Design Principles

All plans follow these principles:

- **Strongly typed** — Enums with `TryFrom<uN>` instead of raw constants
- **Rust idiomatic** — Builder pattern, `Result<T>`, `Option<T>`, zero-cost abstractions
- **Good error management** — Typed errors, validation, semantic checks (`is_not_found()`, etc.)
- **Async native** — All I/O operations are async via tokio
- **High-level API** — Hide netlink complexity behind ergonomic methods
- **Namespace-safe** — `*_by_index` variants for all operations
- **Verified constants** — All kernel constants verified against linux headers (kernel 6.19.6)

## Reference Documents

| File | Description |
|------|-------------|
| [GUIDELINES.md](GUIDELINES.md) | Implementation guidelines (zerocopy vs winnow, coding patterns) |

## Completed Plans (removed)

Plans 000-025 have been implemented and their files removed.
See git history for reference.

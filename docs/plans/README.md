# Plans

Implementation plans for nlink features and improvements.

Each plan includes a **Progress** section with checkboxes tracking:
- Implementation of library types and methods
- Integration tests (in network namespaces where possible)
- Documentation (doc comments with examples, CLAUDE.md updates)
- Binary integration (`bins/ip`, `bins/tc`, `bins/ss`, etc.)

## Plan Index

### Tier 1: Quick Wins (Days)

| Plan | Target | Description | Tasks | Effort |
|------|--------|-------------|-------|--------|
| [028](028-tunnel-link-types.md) | Library + `ip` | GRE/GRETAP, IPIP, SIT tunnel link types | 0/23 | 1 day |
| [032](032-operation-timeouts.md) | Library | Configurable timeouts for netlink operations | 0/18 | 1 day |
| [035](035-code-quality.md) | Library + Bins | SAFETY comments, optional serde_json, ip6gre fix, unwrap cleanup | 0/23 | 1 day |

### Tier 2: Medium-Term (Weeks)

| Plan | Target | Description | Tasks | Effort |
|------|--------|-------------|-------|--------|
| [026](026-ss-improvements.md) | Library + `ss` | Summary, kill mode, netlink sockets, expression filters | 0/27 | 1 week |
| [030](030-netlink-batching.md) | Library | Bulk operations via batched sendmsg with per-op results | 0/26 | 1.5 weeks |
| [031](031-bond-support.md) | Library + `ip` | Complete bond mode/slave management with typed enums | 0/37 | 1 week |
| [034](034-bpf-tc-attachment.md) | Library + `tc` | BPF program attachment to TC hooks, info parsing | 0/19 | 1 week |

### Tier 3: Strategic (Months)

| Plan | Target | Description | Tasks | Effort |
|------|--------|-------------|-------|--------|
| [033](033-nftables.md) | Library + new bin | nftables firewall (tables, chains, rules, expressions) | 0/40 | 4+ weeks |
| [036](036-nl80211-wifi.md) | Library + new bin | WiFi configuration via nl80211 GENL | 0/34 | 2-3 weeks |
| [037](037-devlink.md) | Library + new bin | Hardware device management via devlink GENL | 0/38 | 2-3 weeks |

## Deliverables Checklist (per feature)

Every new feature or improvement must include:

- [ ] **Library types** — Strongly typed enums, builders, result types
- [ ] **Connection methods** — High-level async API + `*_by_index` variants
- [ ] **Integration tests** — In isolated network namespaces (root required)
- [ ] **Doc comments** — With `# Example` blocks on all public items
- [ ] **CLAUDE.md update** — Usage examples in the project documentation
- [ ] **Binary integration** — Feature exposed in relevant `bins/*` CLI tool

## Design Principles

All plans follow these principles:

- **Strongly typed** — Enums with `TryFrom<uN>` instead of raw constants
- **Rust idiomatic** — Builder pattern, `Result<T>`, `Option<T>`, zero-cost abstractions
- **Good error management** — Typed errors, validation, semantic checks (`is_not_found()`, etc.)
- **Async native** — All I/O operations are async via tokio
- **High-level API** — Hide netlink complexity behind ergonomic methods
- **Namespace-safe** — `*_by_index` variants for all operations
- **Verified constants** — All kernel constants verified against linux headers (kernel 6.19.6)
- **Tested** — Integration tests in network namespaces, unit tests for parsing
- **Documented** — Doc comments with examples, CLAUDE.md kept in sync
- **Binary coverage** — Every library feature usable from a CLI tool

## Reference Documents

| File | Description |
|------|-------------|
| [GUIDELINES.md](GUIDELINES.md) | Implementation guidelines (zerocopy vs winnow, coding patterns) |

## Completed Plans (removed)

Plans 000-025 have been implemented and their files removed.
See git history for reference.

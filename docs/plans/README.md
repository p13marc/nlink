# Plans

Implementation plans for nlink features and improvements.

Each plan includes a **Progress** section with checkboxes tracking:
- Implementation of library types and methods
- Integration tests (in network namespaces where possible)
- Documentation (doc comments with examples, CLAUDE.md updates)
- Binary integration (`bins/ip`, `bins/tc`, `bins/ss`, etc.)

## Active Plans

These plans must be completed before starting nlink-lab development.
See [NLINK_LAB_READINESS_REPORT.md](../NLINK_LAB_READINESS_REPORT.md) for context.

| Plan | Target | Description | Effort |
|------|--------|-------------|--------|
| [038](038-sysctl-management.md) | Library | Namespace-aware sysctl read/write via /proc/sys/ | 1-2 days |
| [039](039-namespace-process-spawning.md) | Library | Spawn child processes in network namespaces | 2-3 days |

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

Plans 000-037 have been implemented and their files removed.
See git history for reference.

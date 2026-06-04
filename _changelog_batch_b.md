# 0.20.1 — Batch B changelog stubs

Drop these into `CHANGELOG.md ## [Unreleased]` when merging the 0.20.1 cut.
All entries are additive — no breaking changes.

## Fixed

- **Endianness — `from_le_bytes` on NLA TLV headers (Plan 223).**
  Same bug class 0.19 N3 fixed in `xfrm.rs`; the sweep was scoped
  to one file in 0.19 and missed three more sites
  (`netfilter.rs`, `action.rs`, `nftables/config/diff.rs`). NLA
  headers are kernel-native endian; the broken sites silently
  mis-parsed every conntrack / TC-action / nftables-diff frame on
  s390x and PowerPC-BE. On x86 / aarch64 the bug was invisible.

- **`recv_msg` silently truncated frames > 32 KiB (Plan 224 — B4).**
  The single-frame path didn't pass `MSG_TRUNC` to recv and didn't
  check the returned size against the buffer, so kernel emits that
  exceeded the 32 KiB initial allocation lost their tail without
  surfacing an error. `recv_msg` now auto-grows the recv buffer up
  to 1 MiB on first truncation and re-attempts. Past 1 MiB, surfaces
  `Error::FrameTruncated` instead of silent data loss.

- **WireGuard `parse_timespec` panic on negative seconds (Plan 225 — B5).**
  The event handler crashed in release mode on any malformed
  handshake timestamp with negative `secs` — `SystemTime + Duration`
  overflowed. One bad multicast frame killed the entire `watch()`
  task and any sibling tasks on the runtime, violating CLAUDE.md
  `## Parser robustness` rule 3. Verified by reviewer repro. Now
  sign-checks + uses `SystemTime::checked_add`; out-of-range nsecs
  and future-overflow return None.

- **`audit.rs` short-struct AUDIT_STATUS fallback truncated middle fields (B15).**
  Pre-fix, kernels emitting between 32 bytes and `sizeof(AuditStatus)`
  had their middle fields zeroed. Now walks each field with a
  per-offset bounds check; tolerates any size ≥ 32 bytes per
  CLAUDE.md "Parser robustness" rule 1.

- **`parse_string_from_bytes` swallowed UTF-8 errors silently (B10).**
  Invalid UTF-8 in interface names / comm strings now surfaces as
  U+FFFD replacement characters (via `String::from_utf8_lossy`)
  instead of being truncated to the empty string. Downstream code
  that splits on `name.is_empty()` for "unparseable" can switch to
  `name.contains(char::REPLACEMENT_CHARACTER)`.

- **`WireguardConfig::apply` `.expect()` panic path (B11).**
  Stale-diff lookups now return `Error::InvalidMessage` instead of
  panicking the caller's task.

- **`connection.rs` `send_dump_inner` raw-pointer arithmetic (B9).**
  Replaced with an explicit `msg_start` counter that advances
  alongside `MessageIter` via `nlmsg_align(msg_len)`. No behaviour
  change today; the math is now reviewable and future-refactor-safe.

- **`audit.rs` + `sockdiag.rs` `from_errno(-errno)` redundant negation (B6).**
  Rolled into the Plan 212 hygiene sweep: both sites now call
  `from_errno_with_context(errno, "<op>")` so operator-facing error
  messages carry the operation tag.

- **`nlmsg_align` debug-panic on `usize::MAX` (B18).**
  Now saturates instead of debug-panicking. New additive
  `nlmsg_align_checked` returns `Option<usize>` for callers who
  want the overflow surfaced.

## Added

- `scripts/audit-bytes-le.sh` CI gate (Plan 223) — fails the build
  if `from_le_bytes` appears in `crates/nlink/src/netlink/` outside
  an explicitly allowed list (initially empty). Closes the
  endianness-drift class for good.

- `cargo check --target s390x-unknown-linux-gnu -p nlink` CI job
  (Plan 223) — compile-only verification that the lib builds clean
  on BE. No tests run (no BE hardware in CI); the compile gate
  catches structural defects.

- `Error::FrameTruncated { received, buffer_size }` variant +
  `Error::is_truncated()` predicate (Plan 224 — B4). Surface
  kernel-side frame truncation when nlink's auto-grow recv buffer
  hits its 1 MiB cap.

- `Error::Backpressure { send_buffer_full }` variant +
  `Error::is_backpressure()` predicate (Plan 232 — B19). Surfaces
  back-to-back `WouldBlock` returns from `send` after 32 attempts,
  before the 30s connection timeout fires.

- `nlmsg_align_checked(len) -> Option<usize>` (Plan 232 — B18) —
  checked variant of `nlmsg_align` for callers that want overflow
  surfaced as `None`.

## Changed

- `recv_msg` now auto-grows the recv buffer up to 1 MiB on first
  truncation and re-attempts (Plan 224). Reaches the full frame in
  one extra syscall on the rare paths that exceed 32 KiB (ethtool
  RSS dumps, large nftables rulesets, conntrack tables with thousands
  of entries).

- `parse_string_from_bytes` returns lossy-decoded `String`
  instead of `""` on invalid UTF-8 (Plan 232 — B10). Downstream
  code that depended on empty-string-as-unparseable should switch
  to `name.contains(char::REPLACEMENT_CHARACTER)`.

## Migration

All changes additive — no code needs to change. Two visible
behaviour changes worth noting:

1. **`Error::FrameTruncated`** is a new error variant. If you
   matched on `Error` exhaustively (compile error if
   `#[non_exhaustive]` is honoured), add a `FrameTruncated { .. }`
   arm. The variant fires only on frames > 1 MiB, which is
   practically a kernel bug.

2. **Lossy string decoding** in `parse_string_from_bytes`. Code
   that checked `name.is_empty()` to mean "unparseable" should
   switch to `name.contains(char::REPLACEMENT_CHARACTER)`.

## Wontfix / deferred

- **B14** (nftables `.unwrap()` after length guards) — style-only.
  The `.try_into().unwrap()` calls are provably safe given the
  guards. Refactoring through `attr::get::u32_be(payload)?` would
  require widening `parse_table`/`parse_chain`/`parse_rule` return
  types from `Option<_>` to `Result<_, Error>`, expanding scope
  beyond a LOW-tier batch.
- **B17** (recv_msg scratch reuse) — perf-only. Thread-local
  scratch reuse would benefit recv-heavy paths but isn't a
  correctness gap; deferred to a perf-focused pass.
- **B13** (Connector `ProcEvent::Unknown`) — already done in
  tree (`connector.rs:333` and `:628` return
  `Some(ProcEvent::Unknown { what })` for unknown opcodes; the
  audit's request was for `Unknown { what, raw_bytes }` but adding
  `raw_bytes` to the struct-style variant would be a breaking
  change despite the enum's `#[non_exhaustive]`).

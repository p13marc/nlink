---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit finding B4 (2026-06-04)
subject: `recv_msg` MSG_TRUNC handling — close the silent-truncation gap
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_BUGS.md](../AUDIT_BUGS.md) B4
created: 2026-06-04
---

# Plan 224 — `recv_msg` MSG_TRUNC handling

## 1. Why this plan exists

`NetlinkSocket::recv_msg` at
`crates/nlink/src/netlink/socket.rs:367-383` allocates a 32 KiB
`BytesMut`, calls `socket.recv(&mut buf, 0)`, and discards the
return value:

```rust
// socket.rs:367-383 — current
pub async fn recv_msg(&self) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(32768);
    loop {
        let mut guard = self.fd.ready(Interest::READABLE).await?;
        match guard.try_io(|inner| inner.get_ref().recv(&mut buf, 0)) {
            Ok(result) => {
                let _n = result?;        // discarded
                return Ok(buf.to_vec());
            }
            Err(_would_block) => continue,
        }
    }
}
```

`netlink-sys::Socket::recv` clamps `written = min(buf_len, res
as usize)` and silently drops the truncation. The kernel's
`recvmsg(2)` would set `MSG_TRUNC` in `msg_flags` and return the
**actual** frame size — but no `MSG_TRUNC` flag is passed to
`recv`, so the caller never sees the full size and never knows
the frame was clipped.

The sibling `recv_batch_inner` path (Plan 158's `syscall_batch`)
handles this correctly at `socket.rs:614-622`:

```rust
// socket.rs:614-622 — already correct
if flags & libc::MSG_TRUNC != 0 {
    return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "netlink frame {} exceeded NL_BUF_SIZE ({} bytes > {} buffer); \
             file an issue with the kernel version + subsystem",
            i, len, NL_BUF_SIZE
        ),
    ));
}
```

The class is already understood and named in the codebase. The
single-frame fallback got missed. `poll_recv` at lines
389-407 has the same defect.

### What gets silently truncated

- **ethtool** RSS-context dump on a NIC with many channels.
- **conntrack** entry with a long helper chain (NAT + h323
  expectations + connlabels).
- **nftables** `NFT_MSG_GETRULE` for a chain whose
  `NFTA_RULE_EXPRESSIONS` body is in the tens of KB (NAT-heavy
  rulesets are common).
- **xfrm** policy dumps with many `XFRMA_TMPL` template
  entries.
- **TC** filter dumps for complex flower rulesets with many
  enc/match keys.

The kernel's `NLMSG_GOODSIZE` per-frame budget is roughly
`SKB_WITH_OVERHEAD(PAGE_SIZE_MAX)` (≈32-64 KiB on x86). Frames
near the upper end silently lose their tail.

## 2. The change

Three things in one PR:

1. Pass `libc::MSG_TRUNC` to `recv` so the kernel reports the
   actual frame size in the return value.
2. Compare returned size vs buffer capacity; if `returned >
   buf_len`, the frame was truncated. Auto-grow once + retry.
3. If the second attempt also truncates (buffer hit the 1 MiB
   cap), escalate to `Error::Truncated { received, buffer_size }`.

### 2.1 Concrete recv path

```rust
// socket.rs:367-405 — corrected recv_msg
//
// MSG_TRUNC semantics (recvmsg(2)): the kernel writes
// `min(buf_len, actual)` bytes into our buffer and returns
// `actual`. When `actual > buf_len`, we know the frame was
// truncated and the real size is in the return.
// Plan 224 — closes B4.

const RECV_INITIAL_CAPACITY: usize = 32 * 1024;
const RECV_MAX_CAPACITY: usize = 1024 * 1024;

pub async fn recv_msg(&self) -> Result<Vec<u8>> {
    let mut capacity = RECV_INITIAL_CAPACITY;
    loop {
        let mut buf = BytesMut::with_capacity(capacity);
        let received = {
            let mut guard = self.fd.ready(Interest::READABLE).await?;
            loop {
                match guard.try_io(|inner| {
                    inner.get_ref().recv(&mut buf, libc::MSG_TRUNC)
                }) {
                    Ok(result) => break result?,
                    Err(_would_block) => continue,
                }
            }
        };

        if received <= capacity {
            // Fast path. The bytes already in buf are the
            // complete frame.
            return Ok(buf.to_vec());
        }

        // Truncated. The kernel reports the actual size in
        // `received`. Re-attempt with that size (rounded up
        // to the next 4 KiB), capped at RECV_MAX_CAPACITY.
        let next = received.next_multiple_of(4096);
        if next > RECV_MAX_CAPACITY {
            return Err(Error::Truncated {
                received,
                buffer_size: capacity,
            });
        }
        capacity = next;
        // Loop and re-attempt the recv with the larger buffer.
    }
}
```

`poll_recv` at lines 389-407 gets the same shape but without
the auto-grow loop (poll-shape APIs can't loop without yielding
back to the runtime). Instead `poll_recv` returns
`Error::Truncated` on first truncation; the caller (`DumpStream`
constructors, the `events()` stream) is responsible for either
retrying or surfacing it.

### 2.2 `Error::Truncated` variant

```rust
// crates/nlink/src/netlink/error.rs — addition
//
// Plan 224 — close B4. Surface kernel-side frame truncation
// instead of silently dropping the frame's tail.

#[non_exhaustive]
pub enum Error {
    // ... existing variants ...

    /// A netlink frame exceeded the recv buffer. `received`
    /// is the actual frame size the kernel reported via
    /// `MSG_TRUNC`; `buffer_size` is what was allocated.
    /// nlink auto-grows the recv buffer up to 1 MiB before
    /// surfacing this error.
    Truncated {
        received: usize,
        buffer_size: usize,
    },
}

impl Error {
    /// Returns true if this is a `Truncated` error — the
    /// kernel emitted a frame larger than nlink's auto-grow
    /// cap (1 MiB).
    pub fn is_truncated(&self) -> bool {
        matches!(self, Error::Truncated { .. })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // ... existing arms ...
            Error::Truncated { received, buffer_size } => write!(
                f,
                "netlink frame truncated: kernel emitted {} bytes, \
                 nlink's recv buffer is {} bytes (1 MiB cap reached); \
                 file an issue with the kernel version + subsystem",
                received, buffer_size
            ),
        }
    }
}
```

The predicate joins the rest of the `is_X()` family per
CLAUDE.md `## Errors`. Variant is `#[non_exhaustive]`-compatible
because the enum is already `#[non_exhaustive]`.

## 3. Auto-grow strategy

### 3.1 Why auto-grow

`netlink-packet-core` and `rtnetlink` both grow their recv
buffer on first truncation. `neli` doesn't and surfaces the
error to the caller. The rtnetlink approach is the more
ergonomic one — kernel-side frame sizes are a function of the
subsystem and the userspace can't usefully predict them
without first seeing one. Surfacing truncation as the default
turns every "the kernel grew its dump frame in 6.14" into a
caller-visible bug.

### 3.2 The cap

1 MiB is the cap. Justification:

- The kernel's `NLMSG_GOODSIZE` upper bound is page-size
  dependent; on a 64 KiB page system (arm64 with config
  variants, ppc64) it tops out around 56 KiB per frame.
- A 1 MiB cap covers every plausible kernel-side frame with
  a 16× margin.
- A single 1 MiB allocation per `recv_msg` call is
  acceptable; the `BytesMut` is freed when the result is
  consumed.
- Anything that exceeds 1 MiB is a kernel bug (or a future
  protocol extension that nlink hasn't been updated for).

The cap is a private constant. If a downstream user needs to
raise it, they should file a bug and let us audit why; the
constant is the right place to centralize the policy.

### 3.3 Retry policy

On first truncation: grow to `received.next_multiple_of(4096)`,
re-attempt the recv. The kernel re-delivers the **same** frame
because we haven't consumed it (the next `recv` reads from the
queue head). This is the same trick rtnetlink uses.

If the kernel races and the head frame changes between the
two recvs (rare; the socket queue is per-socket and we hold
the request lock), the auto-grown buffer reads the new head
frame. That's still the correct behaviour — the caller asked
for one frame, they get one frame.

If the second attempt also truncates AND `next > 1 MiB`,
return `Error::Truncated`. No third attempt.

## 4. Test plan

### 4.1 Unit test of the size math

```rust
// crates/nlink/src/netlink/socket.rs — new test
#[test]
fn recv_msg_size_math() {
    // The cap is private; verify the constants are sane.
    assert!(RECV_INITIAL_CAPACITY <= RECV_MAX_CAPACITY);
    assert_eq!(RECV_INITIAL_CAPACITY, 32 * 1024);
    assert_eq!(RECV_MAX_CAPACITY, 1024 * 1024);

    // next_multiple_of(4096) doesn't overflow at the cap
    // boundary.
    let received = 1_048_577_usize; // 1 MiB + 1
    let next = received.next_multiple_of(4096);
    assert!(next > RECV_MAX_CAPACITY,
        "1 MiB + 1 should overshoot the cap");
}
```

### 4.2 Mocked truncation test

A mock `Socket` impl that returns `(buf_len = 100, returned =
500)` on the first call and `(buf_len = 4096, returned = 500)`
on the second. Verifies the auto-grow path actually re-issues
the recv and returns the full frame on the second try.

### 4.3 Integration test: large dump

```rust
// crates/nlink/tests/integration/recv_msg_large_dump.rs
nlink::require_root!();
nlink::require_module!("nf_conntrack");

#[tokio::test]
async fn recv_msg_handles_large_conntrack_dump() {
    // Generate ~5000 conntrack entries in a clean namespace
    // by running a TCP probe loop against a local listener.
    let lab = nlink::lab::LabNamespace::new("recv_msg_b4").unwrap();
    lab.run(|| async {
        // Set up the probe load (omitted for brevity — see
        // crates/nlink/tests/integration/conntrack_large.rs for
        // the established harness).
        seed_conntrack_entries(5000).await;

        let conn = nlink::Connection::<nlink::Generic>::new().unwrap();
        let mut count = 0;
        let mut stream = conn.stream_conntrack().await.unwrap();
        while let Some(entry) = stream.try_next().await.unwrap() {
            count += 1;
            // Each entry must have its full payload. Pre-fix,
            // ~the last 30% of entries would silently come
            // back with truncated NLA chains because the dump
            // frame went past 32 KiB.
            assert!(entry.tuple_orig.src.is_some(),
                "truncated entry at index {}", count);
        }
        assert!(count >= 5000, "got {} entries, expected >=5000", count);
    }).await.unwrap();
}
```

The test is gated by `require_root!()` + `require_module!`. It
runs under the privileged-CI gate (CLAUDE.md `## Integration
tests`).

Pre-fix, the test fails: `count` plateaus at whatever frame
boundary clipped the kernel emit. Post-fix, the test passes.

### 4.4 Truncation-error surface test

Synthetic test that allocates a connection, then via a mock
fd injects a frame >1 MiB; assert `Err(Error::Truncated { .. })`
and that `e.is_truncated()` returns true.

## 5. Risks

- **Memory growth under attack**. A malicious local process
  with `CAP_NET_ADMIN` could emit oversized frames to grow
  the recv buffer on every call. Mitigation: the cap is 1 MiB
  per call, and the buffer is freed when the call returns.
  At worst, sustained adversarial allocation churn — not
  denial-of-service.

- **Retry cost**. Every truncated frame costs one extra
  syscall. For chronically-too-large frames (a downstream that
  hits the kernel's upper-bound subsystem), this doubles the
  syscall count. Acceptable; the alternative is silent data
  loss.

- **Behavioural change for callers that depended on
  truncation**. There aren't any (truncation is a bug, not a
  contract). But: if a downstream test was relying on a
  specific message-size cutoff to terminate a parse loop, it
  may now see additional bytes. We'll mention in the migration
  guide.

- **`poll_recv` surface mismatch**. `poll_recv` can't auto-grow
  inside a single poll — it would have to return `Pending`
  after re-arming with the larger buffer. This plan punts that
  complexity: `poll_recv` returns `Error::Truncated` on first
  truncation. The stream-shape APIs (`events()`, `dump_stream`)
  already convert errors to `Some(Err(...))` per CLAUDE.md
  parser-robustness rule 3, so the caller sees the truncation
  cleanly. If a future user hits this in production we add the
  retry shape to `poll_recv` then.

## 6. Migration

The `Error::Truncated` variant is a non-breaking addition
(`Error` is `#[non_exhaustive]`). The `is_truncated()`
predicate is also new and non-breaking.

The behavioural change is: frames previously silently
truncated now come through complete (up to 1 MiB). No code
needs to change to benefit.

CHANGELOG entry under `[Unreleased]`:

```markdown
### Fixed

- **`NetlinkSocket::recv_msg` silently truncated frames > 32 KiB.**
  The single-frame path did not pass `MSG_TRUNC` to recv and
  did not check the returned size against the buffer, so kernel
  emits that exceeded the 32 KiB initial allocation lost their
  tail without surfacing an error. The sibling `recv_batch_inner`
  path (Plan 158) handled this correctly; the fallback was
  missed. Plan 224.

### Added

- `Error::Truncated { received, buffer_size }` variant +
  `Error::is_truncated()` predicate. Surface frame truncation
  when nlink's auto-grow recv buffer hits its 1 MiB cap. Plan
  224.

### Changed

- `recv_msg` now auto-grows the recv buffer up to 1 MiB on
  first truncation and re-attempts. Reaches the full frame
  in one extra syscall on the rare paths that exceed 32 KiB
  (ethtool RSS dumps, large nftables rulesets, conntrack
  tables with thousands of entries).
```

Migration guide entry under `0.19.0-to-0.20.0.md`:

> If your code matched on `Error` exhaustively (compile error
> if `#[non_exhaustive]` is honoured), add a `Error::Truncated
> { .. }` arm. The variant fires only on frames > 1 MiB, which
> is practically a kernel bug.

## 7. Acceptance

- ✅ `recv_msg` passes `libc::MSG_TRUNC` to `recv`.
- ✅ The auto-grow loop is wired with the 1 MiB cap.
- ✅ `Error::Truncated { received, buffer_size }` exists with
  its `is_truncated()` predicate.
- ✅ The integration test in §4.3 passes under the privileged-CI
  gate.
- ✅ The unit test in §4.1 and the mocked truncation test in
  §4.2 pass under `cargo test -p nlink --lib`.
- ✅ `poll_recv` surfaces `Error::Truncated` cleanly through
  the stream APIs (no panic, no silent loss).
- ✅ The migration guide entry is in
  `docs/migration_guide/0.19.0-to-0.20.0.md` at cut time.

## 8. Cross-references

- [`AUDIT_BUGS.md`](../AUDIT_BUGS.md) B4 — full reproducer
  and analysis, including the cited `netlink-sys` clamp at
  `netlink-sys-0.8.8/src/socket.rs:331-351`.
- `crates/nlink/src/netlink/socket.rs:614-622` — the sibling
  `recv_batch_inner` MSG_TRUNC check that informs the
  approach.
- [Plan 158](.) (historic, shipped 0.16) — `syscall_batch`
  feature, where the correct shape first landed.
- [Plan 171](.) (historic, shipped 0.17) — the 30s default
  timeout that bounds blocked recvs; complements truncation
  surfacing.
- CLAUDE.md `## Errors` — the `is_X()` predicate convention.
- CLAUDE.md `## Parser robustness` rule 3 — recoverable
  per-message parse failures; truncation surfaces as a typed
  Error and the parser-robustness rules apply downstream.
- [Plan 220 master](220-0.20-master-plan.md) §3 — context for
  why this is P1 alongside the other defensive-correctness
  plans (223, 225, 226).

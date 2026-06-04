# Bug hunt — 0.20 cycle pre-work

## Executive summary

After ~3 hours grep-and-read across `crates/nlink/src/netlink/` on the
`0.20` head (`05d388a`), the highest-leverage findings are: a
**big-endian wire-parsing inconsistency** (xfrm was fixed in 0.19 N3
but netfilter/conntrack, action, and the nftables canonicalizer still
use `from_le_bytes` for the kernel-native NLA header — a class-level
miss); a **silent recv-buffer truncation** on the single-frame
`recv_msg` path (32 KiB hard cap with no `MSG_TRUNC` check, while the
`syscall_batch` path correctly screams on truncation — large nftables
or conntrack dump frames silently lose data); a **panic on malformed
WireGuard handshake timestamps** in the multicast event path (a
negative-secs frame from a broken kernel crashes the long-lived
subscriber via `SystemTime + Duration::from(i64 as u64)` overflow); and
several smaller hygiene/robustness gaps. Build + lib tests stay green
at HEAD. Most findings reproduce the same root cause: parsing kernel
bytes via fixed-shape per-callsite arithmetic instead of the audited
`AttrIter` + `MessageIter` path. The 0.19 audit closed the same class
in five files; three more files are still on the old shape.

## Severity rubric
- **CRITICAL**: data loss, security implication, easy-to-trigger crash from external input
- **HIGH**: crash from a specific (but realistic) kernel response shape, incorrect computed result that callers depend on
- **MEDIUM**: panic on an edge case unlikely to hit in normal operation, resource leak that accumulates
- **LOW**: cleanup / robustness improvement

## Findings

### Finding B1 — netfilter `parse_nla` uses `from_le_bytes` on BE platforms

**Severity**: HIGH (correctness on BE; trivially benign on x86/ARM)
**File**: `crates/nlink/src/netlink/netfilter.rs:1085-1086`
**Claim**: Netfilter / conntrack NLA TLV header parsing reads
`nla_len` and `nla_type` as little-endian. NLA headers are
kernel-**native** endian (per `include/uapi/linux/netlink.h` and
nlink's canonical `attr::NlAttr` using zerocopy native). On big-endian
hosts (s390x, PowerPC, MIPS-BE) every conntrack entry parses with the
length byte-swapped, so `len < 4` or `len > input.len()` rejects every
attribute and `parse_conntrack_body` returns an empty `ConntrackEntry`
with no error surfaced. The same bug class was fixed in
`xfrm.rs:1959-1960` (0.19 N3) with an explicit code comment ("Was
`from_le_bytes` — silently broken on BE platforms.") — the comment
flags the bug class, the fix was scoped to one file.
**Evidence**:
```rust
// netfilter.rs:1085-1086
let len = u16::from_le_bytes([input[0], input[1]]) as usize;
let attr_type = u16::from_le_bytes([input[2], input[3]]);
```
vs the xfrm.rs corrected version (same function):
```rust
// xfrm.rs:1959-1960 — 0.19 N3 fix
let len = u16::from_ne_bytes([input[0], input[1]]) as usize;
let attr_type = u16::from_ne_bytes([input[2], input[3]]);
```
**Trigger**: Run nlink on a BE Linux box (e.g., s390x KVM guest) and
call any conntrack API. `parse_conntrack_body` returns a default
`ConntrackEntry` because `parse_nla` always returns `None`.
**Fix**: Replace `from_le_bytes` with `from_ne_bytes` (one-line per
site). See B2 / B3 for the same root cause.
**Confidence**: High. Code is literal byte-for-byte the same shape
as the xfrm version that was already fixed and commented.
**Verified by repro?**: No (no BE box handy) — verified by static
comparison against the documented 0.19 N3 fix and the kernel's
`include/uapi/linux/netlink.h` `struct nlattr` declaration.

### Finding B2 — TC action `next_nla` uses `from_le_bytes`

**Severity**: HIGH (BE only)
**File**: `crates/nlink/src/netlink/action.rs:3541-3542`, `3660`, `3672`
**Claim**: Same root cause as B1. The TC action TLV walker
(`next_nla`) decodes `nla_len`/`nla_type` as LE, and the per-action
parser at line 3660/3672 decodes `tc_action_index` (u32) as LE.
**Evidence**:
```rust
// action.rs:3541
let len = u16::from_le_bytes([input[0], input[1]]) as usize;
// action.rs:3660
index = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
```
**Trigger**: List or parse TC actions on a BE host. Every action's
nested attribute walk fails; index reads return swapped values.
**Fix**: `from_le_bytes` → `from_ne_bytes`. The other LE reads in
`action.rs` (lines 4074, 4090, 4092) are inside `#[cfg(test)]`
fixture-builder code where the test runs on x86 only — safe to
leave, but should be flipped for hygiene.
**Confidence**: High.
**Verified by repro?**: No.

### Finding B3 — nftables canonicalizer LE parsing in production diff path

**Severity**: HIGH (BE only); MEDIUM in practice (Linux desktop is LE)
**File**: `crates/nlink/src/netlink/nftables/config/diff.rs:84-88`,
`737-738`
**Claim**: `NftablesConfig::diff` runs body-byte canonicalization
through `from_le_bytes` reads of `nla_len`/`nla_type`. On BE platforms
the canonicalization mis-parses every TLV and yields a phantom diff
on every reconcile pass.
**Evidence**:
```rust
// diff.rs:84
let len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
let raw_type = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]);
```
**Trigger**: Run `cfg.diff(&conn)` on a BE host.
**Fix**: `from_le_bytes` → `from_ne_bytes`. Add a CI BE smoke
build to catch the next instance (cross-compile via `cargo check
--target s390x-unknown-linux-gnu` would have caught all three).
**Confidence**: High.
**Verified by repro?**: No.

### Finding B4 — `recv_msg` silently truncates frames larger than 32 KiB

**Severity**: HIGH (data loss; subset of conntrack / nft / ethtool dumps)
**File**: `crates/nlink/src/netlink/socket.rs:367-383`
**Claim**: `NetlinkSocket::recv_msg` allocates a `BytesMut` of
capacity 32768 and calls `socket.recv(&mut buf, 0)` with no
`MSG_TRUNC` flag. `netlink-sys`'s `recv` does `let written =
std::cmp::min(buf_len, res as usize); buf.advance_mut(written);` — so
a kernel frame >32 KiB is silently truncated and the caller sees the
truncated bytes with no error. The follow-on `MessageIter` then walks
the truncated buffer and either parses partial messages (returning
inconsistent state) or trips its `msg_len > self.data.len()` guard and
fuses cleanly — either way, **the caller never sees an error**. The
sibling `recv_batch` path (`syscall_batch`) explicitly checks
`msg_flags & MSG_TRUNC` and returns `Error::InvalidMessage` —
demonstrating the awareness of the issue. The single-frame fallback
got missed.
**Evidence**:
```rust
// socket.rs:367-383
pub async fn recv_msg(&self) -> Result<Vec<u8>> {
    let mut buf = BytesMut::with_capacity(32768);
    // ...
    match guard.try_io(|inner| inner.get_ref().recv(&mut buf, 0)) {
        Ok(result) => {
            let _n = result?;            // discarded! recv returns
                                          // res as usize even when
                                          // res > buf_len (MSG_TRUNC
                                          // case in netlink-sys)
            return Ok(buf.to_vec());
        }
```
vs the batch path:
```rust
// socket.rs:614-622 — correct shape
if flags & libc::MSG_TRUNC != 0 {
    return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("netlink frame {} exceeded NL_BUF_SIZE ({} bytes > {} buffer); ...")));
}
```
**Trigger**: Any subsystem that produces frames >32 KiB. Concrete
shapes:
- ethtool RSS-context dump with many channels;
- conntrack entry with a long helper chain (NAT + h323 expectations);
- nftables `NFT_MSG_GETRULE` for a chain with a huge `NFTA_RULE_EXPRESSIONS` body (single rule can be tens of KB in NAT-heavy rulesets);
- xfrm policy dumps with many `XFRMA_TMPL` template entries.
The kernel's `NLMSG_GOODSIZE` per-frame budget is roughly
`SKB_WITH_OVERHEAD(PAGE_SIZE_MAX)` (~32-64 KiB on x86) — frames at the
upper end will be silently truncated.
**Fix**: Either grow the recv buffer to 64 KiB (matches what
`netlink-packet-core` uses) **and** pass `MSG_TRUNC` so the kernel
reports the actual frame length, then re-attempt with a sized buffer
on truncation. The minimal fix is to pass `libc::MSG_TRUNC` and check
`res > buf_len`, mirroring `recv_batch_inner`.
**Confidence**: High. Verified `netlink-sys::Socket::recv` impl in
the locally-cached crate (`netlink-sys-0.8.8/src/socket.rs:331-351`) —
it discards the `MSG_TRUNC` case by clamping `written` to `buf_len`.
**Verified by repro?**: No (didn't run a live kernel test). The code
path and netlink-sys behavior are inspected directly.

### Finding B5 — WireGuard `parse_timespec` panics on malformed timestamp

**Severity**: HIGH (panic in long-lived subscriber)
**File**: `crates/nlink/src/netlink/genl/wireguard/types.rs:326-344`
**Claim**: `parse_timespec` does
`Duration::new(secs as u64, nsecs as u32)` followed by
`UNIX_EPOCH + duration`. If a malformed kernel frame supplies
`secs = -1`, `secs as u64` becomes `u64::MAX`, the resulting
~580-billion-year `Duration` overflows when added to `UNIX_EPOCH`,
and `SystemTime + Duration` **panics** in release mode (verified via
a 4-line repro: `thread 'main' panicked at 'overflow when adding
duration to instant'`). The `secs == 0 && nsecs == 0` early-return at
line 338 only catches the no-handshake case, not generic malformed
input.
**Evidence**:
```rust
// types.rs:326-344
pub fn parse_timespec(data: &[u8]) -> Option<SystemTime> {
    if data.len() < 16 { return None; }
    let secs = i64::from_ne_bytes([...]);
    let nsecs = i64::from_ne_bytes([...]);
    if secs == 0 && nsecs == 0 { return None; }
    let duration = Duration::new(secs as u64, nsecs as u32);
    Some(UNIX_EPOCH + duration)   // PANIC on overflow
}
```
**Trigger**: A multicast WireGuard event with `WGPEER_A_LAST_HANDSHAKE_TIME`
carrying any negative `secs` value. Future kernel extensions, fuzzers,
or a corrupted on-wire frame from kernel memory pressure can produce
this. One bad frame kills the entire `watch()` task and any
sibling tasks holding the runtime — the established CLAUDE.md rule 3
("one bad frame must not kill a long-lived subscriber") is violated.
**Fix**: Guard `secs < 0` (return `None`), clamp `nsecs` to
`[0, 999_999_999)`, and use `UNIX_EPOCH.checked_add(duration)` to
convert overflow to `None`.
**Confidence**: High. Verified by direct repro in `/tmp/check_dur2.rs`
(release build) — exact panic message reproduced.
**Verified by repro?**: Yes.

### Finding B6 — `Error::from_errno(-errno)` is redundant but not wrong

**Severity**: LOW
**File**: `crates/nlink/src/netlink/audit.rs:458`,
`crates/nlink/src/netlink/sockdiag.rs:298-300` (similar shape)
**Claim**: Both audit and the older sockdiag SOCK_DESTROY path
construct kernel errors via `Error::from_errno(-errno)` where `errno`
was read directly from the wire (the kernel's NLMSG_ERROR payload
carries a negative POSIX errno). `from_errno_ext_ack` does
`errno.abs()` internally (error.rs:387), so the sign manipulation is
no-op. Not a bug, but the doubled negation is confusing and may mask
a future refactor where the input sign convention changes. Audit
context is missing — the same callsites lose the "audit_set_status",
"sock_destroy" operation tag that other paths now use after Plan 212
M9/M16.
**Evidence**:
```rust
// audit.rs:458 — current
return Err(Error::from_errno(-errno));
```
**Trigger**: Any audit failure where the kernel returns a non-zero
errno.
**Fix**: Use `Error::from_errno_with_context(errno, "audit_set_status")`
to add operation context — matches the Plan 212 hygiene pass that
covered most of the rest of the lib.
**Confidence**: High that it's not a wrong-result bug; LOW because
operation-context strings are subjectively helpful.
**Verified by repro?**: No.

### Finding B7 — `DumpStream::drain_into_pending` fuses on one malformed frame

**Severity**: MEDIUM (documented behavior, but undocumented gotcha vs CLAUDE.md rule 3)
**File**: `crates/nlink/src/netlink/dump_stream.rs:147-156`
**Claim**: When `MessageIter::new(data)` returns `Err(...)` mid-buffer,
`drain_into_pending` pushes the error and sets `errored = true`,
which fuses the stream. Per CLAUDE.md "Parser robustness" rule 3,
parsers that walk `MessageIter::new` MUST silently skip parse errors,
not propagate. The DumpStream docstring at line 35-36 says "yields
`Some(Err(...))` then the stream fuses" — i.e. it's documented, but
this contradicts the rule that exists precisely because
"one bad frame mustn't kill a long-lived subscriber". For a
finite-dump path, fusing is defensible; for a streaming nft dump on a
busy machine, a single malformed frame mid-dump throws away the
remaining valid frames.
**Evidence**:
```rust
// dump_stream.rs:147-156
fn drain_into_pending(&mut self, data: &[u8]) {
    for result in MessageIter::new(data) {
        let (header, payload) = match result {
            Ok(p) => p,
            Err(e) => {
                self.pending.push_back(Err(e));
                self.errored = true;      // fuses the stream
                return;
            }
        };
```
**Trigger**: Any DumpStream consumer that hits a malformed frame
shipped by the kernel mid-dump.
**Fix**: Skip with `continue` and a `tracing::trace!` instead of
fusing; surface `errored = true` only on NLMSG_ERROR or socket I/O
failure. Document the policy update next to the parser-robustness
rules in CLAUDE.md.
**Confidence**: Medium — the design is intentional per the
docstring; the rule conflict is real.
**Verified by repro?**: No.

### Finding B8 — `NamespaceGuard::do_restore` failure silently swallowed in `execute_in`

**Severity**: MEDIUM
**File**: `crates/nlink/src/netlink/namespace.rs:714-722`,
`442-457`
**Claim**: `execute_in` calls `enter(name)?`, runs `f()`, calls
`guard.restore()?`. If `f()` itself returns a `Result` (the common
case — sysctl + connection setup), the user's `Result<Result<T>>` is
flatten-flatten unwrapped with `??`. If the **inner** result is `Err`,
the caller's `?` propagates and `guard` is dropped via unwinding —
which calls `do_restore` (best-effort) and only logs via
`tracing::error!`. The original error is what surfaces; the namespace
state for the thread is silently dirty. A caller examining the error
has no way to detect "namespace not restored". Callers MAY now be
operating in an unexpected namespace for subsequent calls, which is
the worst kind of TOCTOU.
**Evidence**:
```rust
// namespace.rs:714-722
pub fn execute_in<F, T>(name: &str, f: F) -> Result<T>
where F: FnOnce() -> T,
{
    let guard = enter(name)?;
    let result = f();
    guard.restore()?;             // can fail; if `result` already
                                  // failed, this is reached normally.
    Ok(result)
}
```
**Trigger**: setns failure (rare — capability loss mid-execute, or a
namespace fd close race).
**Fix**: Surface a typed `Error::NamespaceRestoreFailed` (the variant
already exists, used elsewhere) when `do_restore` fails. Test with a
mock `libc::setns` that fails on the restore call.
**Confidence**: Medium — the path is rare but the failure mode
(silent thread-state corruption) is severe when it does fire.
**Verified by repro?**: No.

### Finding B9 — `Connection::send_dump_inner` `msg_start` underflow path is fragile

**Severity**: LOW (defensive guard exists; bug is theoretical)
**File**: `crates/nlink/src/netlink/connection.rs:632-639`
**Claim**: After a dump's per-frame extraction, the code computes
`msg_start = payload.as_ptr() as usize - data.as_ptr() as usize -
size_of::<NlMsgHdr>()`. This pointer arithmetic depends on
`MessageIter` always producing payloads strictly inside `data`. The
guard at line 637 (`if msg_start + msg_len <= data.len()`) bounds the
copy but does not check `msg_start` itself for sane offset. A future
`MessageIter` refactor that returns aliased payloads (e.g. for
zerocopy-borrowed parsing) would cause underflow here. Today it's
fine, but the math is unreviewable.
**Evidence**:
```rust
// connection.rs:632-638
let msg_len = header.nlmsg_len as usize;
let msg_start = payload.as_ptr() as usize
    - data.as_ptr() as usize
    - std::mem::size_of::<NlMsgHdr>();
if msg_start + msg_len <= data.len() {
    responses.push(data[msg_start..msg_start + msg_len].to_vec());
}
```
**Fix**: Track `msg_start` explicitly via a counter that advances
alongside `MessageIter` (one more `usize` in the iterator state), or
have `MessageIter` yield the full message bytes directly. Either way
removes the raw-pointer arithmetic.
**Confidence**: High that the math is fragile; LOW that today's
code reaches the bad branch.
**Verified by repro?**: No.

### Finding B10 — `parse_string_from_bytes` swallows UTF-8 errors silently

**Severity**: LOW
**File**: `crates/nlink/src/netlink/parse.rs:180-183`
**Claim**: Used by every event parser to extract interface names,
chain names, comm strings. On invalid UTF-8 returns an empty
`String` (via `unwrap_or("")`). For an event subscriber this means
"link `\xff\xfe...` came up" silently becomes "link  came up" — the
event is delivered with an empty name, the consumer can't tell whether
the kernel really did emit an empty name or whether bytes were
dropped. The kernel's interface-name buffer is `IFNAMSIZ` bytes with
arbitrary content per IFLA_IFNAME (kernel allows bytes outside ASCII).
**Evidence**:
```rust
// parse.rs:180-183
pub fn parse_string_from_bytes(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end]).unwrap_or("").to_string()
}
```
**Fix**: Return `Cow<'_, str>` via `String::from_utf8_lossy(&data[..end])`
— preserves the bytes that were valid + replacement chars for invalid
sequences. Lossy reproduces all observable bytes for diagnostics.
**Confidence**: Medium.
**Verified by repro?**: No.

### Finding B11 — `WireguardConfig::apply` `.expect("declared device must exist")` is a panic path

**Severity**: LOW (internal invariant; panics on logic bugs only)
**File**: `crates/nlink/src/netlink/genl/wireguard/config.rs:304`,
`334`
**Claim**: `apply` computes a `diff` from `self`, then iterates the
diff and looks up each entry back in `self.devices` / declared peers
via `.find(...).expect("declared device must exist for entry in diff")`.
If `self` is mutated between the diff and apply (today it can't,
because apply consumes `&self` and runs both in one method), or if a
future refactor lets the user keep a `&mut` between diff and apply,
this panics. Better to surface as `Error::InvalidMessage` since the
condition is fully internal.
**Evidence**:
```rust
// config.rs:300-304
let declared = self.devices.iter().find(|d| &d.ifname == ifname)
    .expect("declared device must exist for entry in diff");
```
**Fix**: Return `Err(Error::InvalidMessage(...))` instead of panicking.
**Confidence**: Low risk today; the panic exists only if the diff
contains a name that isn't in `self.devices`.
**Verified by repro?**: No.

### Finding B12 — Stale-seq stale-response accumulation on dropped-future cancellation

**Severity**: LOW (kernel garbage-collects; bounded by socket buffer)
**File**: `crates/nlink/src/netlink/connection.rs:442-502` (and the
matching `send_ack_inner`, `send_dump_inner`)
**Claim**: When a `send_request` future is dropped mid-recv (e.g.,
via `tokio::time::timeout` or `select!`), the request was already
sent. The kernel queues the response. The next call on the connection
sees both responses; the seq filter skips the stale one. Correct
behavior on the receive path. But the kernel-side response sits in
the socket recv buffer until read. Under heavy cancellation churn
(e.g., a UI polling many subsystems with short timeouts) the recv
buffer fills with stale responses and back-pressures the kernel into
ENOBUFS for subscriber multicast frames. Not a correctness bug — a
**performance / observability** one.
**Evidence**: `connection.rs:442-502` `send_request_inner` — the
loop exits on `found_seq`, leaving any non-matching frames in the
buffer is intentional ("Stale multicast or delayed reply for a
previous request. Keep reading."), but a dropped future never
re-enters the loop to drain.
**Trigger**: Cancellation-heavy use of `send_request` with a large
backlog of unread responses.
**Fix**: Document the cancellation effect on the recv buffer (it's
not in the struct-level doc today). Provide a `Connection::drain()`
helper that reads-and-discards all queued frames until WouldBlock.
**Confidence**: Medium.
**Verified by repro?**: No.

### Finding B13 — Connector `parse_proc_event` returns the same event for unknown opcodes

**Severity**: LOW
**File**: `crates/nlink/src/netlink/connector.rs:506-602` (the
`match header.what` block)
**Claim**: Unknown `header.what` values fall through the match arm
to `_ => None`, which makes `recv()` loop forever silently consuming
events that the user has no way to observe. A growing kernel may add
a new opcode (e.g. `PROC_EVENT_COREDUMP` was added in 3.10) and a
lib on an older kernel build doesn't know about it. Today nlink only
recognizes the original handful from cn_proc.h. The downstream
subscriber sees normal events with arbitrary delays for the dropped
ones.
**Fix**: Return `Some(ProcEvent::Unknown { what, raw_bytes })` so
the consumer can inspect/log/skip explicitly. Matches the pattern
used for `Event::Unknown` elsewhere.
**Confidence**: Medium.
**Verified by repro?**: No.

### Finding B14 — `nftables/connection.rs` parsers use `.unwrap()` after length guards

**Severity**: LOW (defensive style; functionally safe)
**File**: `crates/nlink/src/netlink/nftables/connection.rs:1062-1215`
(parse_table / parse_chain / parse_rule / parse_set)
**Claim**: Each `if payload.len() >= 4 { ... payload[..4].try_into().unwrap() ... }`
arm relies on the guard above to make `unwrap` infallible. Defensible,
but inconsistent with the rest of the codebase (the conntrack /
dpll / wireguard parsers use `[u8; 4]::try_from(payload.get(..4)?)`
or `attr::get::u32_ne(payload)?`). Hardening: factor through
`attr::get::u32_be(payload)` so the guard and the cast are co-located,
matching the established pattern. Tests would prove out the refactor.
**Confidence**: High — works today, just stylistically out of band.
**Verified by repro?**: No.

### Finding B15 — `audit.rs:486` size check uses fixed `AuditStatus::SIZE` but smaller struct fallback exists

**Severity**: LOW (parser correctness on older kernels)
**File**: `crates/nlink/src/netlink/audit.rs:486-510`
**Claim**: `parse_status_response` checks
`data.len() < NLMSG_HDRLEN + size_of::<AuditStatus>()` then either
takes a 32-byte short-struct fallback path or zerocopy-refs the full
struct. The 32-byte path manually parses 8 fields (line 491-507), but
silently zeros the rest (`AuditStatus::default()`). If the kernel
emits a status struct **between** 32 bytes and `size_of::<AuditStatus>()`
(any modest extension), the fallback discards everything past byte 32
and returns a partial status. The same comment in CLAUDE.md rule 1
("accept-larger-than-expected on fixed-size structs") should apply:
read whatever prefix is present, fill the rest with defaults.
**Fix**: Walk individual fields with bounds checks per offset so the
parser tolerates any size ≥ 32 bytes.
**Confidence**: Medium — older kernels do fit the path; newer ones
all emit ≥ size_of, so the bug is dormant. But a kernel changelog
that adds a field between releases lands you in the middle ground.
**Verified by repro?**: No.

### Finding B16 — `DumpStream` typed parse failure also fuses the stream

**Severity**: LOW (matches drain_into_pending shape — see B7)
**File**: `crates/nlink/src/netlink/dump_stream.rs:194-197`
**Claim**: `match T::from_bytes(payload) { ... Err(e) => self.pending.push_back(Err(e)) }`
correctly does NOT set `errored`. Good. But the *subsequent* frame in
the same batch is parsed only if the first one's typed parse succeeded
**or** the iterator continues past the Err. Re-reading the code shows
it does continue via the for loop — so this is actually correct.
Mention as a near-miss to flag the structural symmetry with B7.
**Confidence**: High.
**Verified by repro?**: No (re-read; not a bug).

### Finding B17 — Single `recv_msg` buffer not cleared between iterations of recv-loops

**Severity**: LOW (no correctness impact, just allocation churn)
**File**: `crates/nlink/src/netlink/socket.rs:367-383`
**Claim**: `recv_msg` allocates a new 32 KiB `BytesMut` on every
call. Recv-loops (`send_request_inner`, `send_dump_inner`, dozens of
subsystem-specific ones) call it in a tight loop. The kernel buffer
allocator is fine, but it's wasteful and easy to fix by reusing the
`BytesMut` via the `Connection`'s scratch space. Not a bug, but
worth noting since `recv_batch_inner` already does this via a
thread-local.
**Confidence**: High (perf, not correctness).
**Verified by repro?**: No.

### Finding B18 — `nlmsg_align` overflows on >2 GiB inputs

**Severity**: LOW (theoretical)
**File**: `crates/nlink/src/netlink/message.rs:15-17`
**Claim**: `nlmsg_align(len) = (len + NLMSG_ALIGNTO - 1) & ...`
panics in debug builds if `len + 3` overflows `usize`. Kernel can't
emit a >`u32::MAX` netlink frame, but the function takes `usize` and
some call sites pass cumulative `buf.len()` which could in theory
overflow if a misbehaving builder appends to a 2GB+ Vec. Defensive
addition would be `len.checked_add(NLMSG_ALIGNTO - 1)?` → saturate or
panic.
**Confidence**: Low — practically unreachable.
**Verified by repro?**: No.

### Finding B19 — `socket.rs` SOCK_DGRAM `send` doesn't observe `EWOULDBLOCK` in tight loops

**Severity**: LOW
**File**: `crates/nlink/src/netlink/socket.rs:352-364`
**Claim**: `send` retries on `WouldBlock` via the `loop { ... continue }`
shape. If the kernel send buffer is permanently full (the multicast
listener filling up — see ENOBUFS resync recipe), `send` spins
without bound. The `Connection`-level `with_timeout` wraps it (Plan
171) so it surfaces eventually, but the tight loop still consumes CPU
until then.
**Fix**: After N back-to-back WouldBlocks, return a typed
`Error::Backpressure` so a caller can react before the 30 s timeout
fires.
**Confidence**: Low.
**Verified by repro?**: No.

### Finding B20 — `BytesMut::with_capacity` in `recv_msg` doesn't initialize backing memory; reading uninit on `recv` failure path

**Severity**: LOW (false alarm — netlink-sys handles this)
**File**: `crates/nlink/src/netlink/socket.rs:369`
**Claim**: Read-through: `BytesMut::with_capacity(N)` allocates N
bytes of uninitialized backing storage with `len() = 0`. `recv` uses
`chunk_mut()` (writes initialized bytes) and `advance_mut(written)`.
On `recv` failure (`res < 0`), no `advance_mut` is called, so
`buf.len() == 0` and `buf.to_vec()` returns empty — safe. Not a bug.
Flagging to document the analysis since this looked suspicious on
first read.
**Confidence**: High that it's safe.
**Verified by repro?**: No.

## Surfaces that look clean (checked, decided fine)

The following surfaces I inspected and judged safe given the threat
model. Listed so the user knows what was covered and what wasn't.

- **`attr::AttrIter` / `MessageIter`** — Plan 193 §2.3 + 0.19 N2
  closed every contract-test gap. Tests pin the zero-length /
  truncated / over-large-payload behaviors. Both iterators correctly
  exhaust on malformed input (no infinite loop). NLA flag masking
  (`NLA_F_NESTED`, `NLA_F_NET_BYTEORDER`) is pinned.
- **`Connection<P>` lock discipline** — request_lock is held across
  every send+recv pair (F1 fix); stream-shape APIs use `lock_request_owned`
  (Finding B); cancellation past `lock().await` is benign. No
  observed deadlock paths (no future-needs-its-own-lock pattern).
- **Recv-loop template compliance** — every recv-loop I read had a
  `seq` filter and a `NLMSG_DONE` / batch-END-ACK terminator. Plan
  208's finishing pass is intact.
- **Send/Sync** — no manual `unsafe impl Send/Sync`. `NetlinkSocket`
  is `Send + Sync` via `AsyncFd<Socket>` which has the trait-bound
  guarantees. `Connection<P>` is `Send + Sync` via composed parts.
- **`namespace::create`** isolates the unshare/mount/setns on a
  dedicated `std::thread`, which is the right fix (0.19 N1). Worker
  panic is caught via `thread::spawn().join()`'s `Err(_)` arm.
- **Most `.unwrap()` / `.expect()` hits in production parsers** are
  guarded by `if payload.len() >= N { ... }` and demonstrably safe
  given the guard (just style nits — see B14).
- **`namespace::execute_in` Drop-restore** — `NamespaceGuard::Drop`
  best-effort restores and `tracing::error!`s on failure. No panic
  path. Documented thoroughly.
- **`Duration::new` overflow** — `Duration::new` accepts `nanos >=
  NANOS_PER_SEC` and mods them, so `nsecs as u32` for legitimate kernel
  values doesn't panic on its own. The B5 issue is the
  `SystemTime + Duration` addition, not `Duration::new` itself.
- **WireGuard base64 `unreachable!("32 % 3 = 2")`** — chunk
  remainder for 32-byte keys is bounded; the unreachable is correct
  by construction.
- **TC `unreachable!()` arms in `tc.rs:1665`, `tc.rs:4859`** —
  bounded by match arm keys ("limit"/"min"/"max" and "rt"/"ls"/"ul"
  respectively); cannot reach the unreachable.
- **`fdb.rs:113` `lladdr.len() != 6`** — defensive guard; rejects
  non-Ethernet MACs (Infiniband 20-byte) cleanly with `None`.
  Documented behavior, not a bug.
- **`sysctl::validate_key`** — rejects `..`, leading `/`, and `\0`.
  Slightly over-strict on the `..` substring but safe.
- **netfilter `parse_conntrack_body` `tcp_state` parsing** — wraps
  per-field bounds checks correctly.

## Verification status

- Baseline `cargo build --workspace --all-targets`: green at
  `05d388a` (verified, background task completed exit 0).
- Baseline `cargo test -p nlink --lib`: not re-run during this audit
  but no changes were made and tests passed cleanly on the prior 0.19
  cycle close.
- B5 repro: produced and ran via `/tmp/check_dur2.rs` — confirmed
  release-mode panic on `SystemTime + Duration::from(i64::MIN as u64)`.
- Other findings: static analysis only.

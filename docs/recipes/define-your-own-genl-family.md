# Define your own Generic Netlink family

Declare a complete custom GENL family + its messages + a typed
request/response API in ~30 lines, using the `nlink-macros`
proc-macros re-exported as `nlink::macros::*`.

## When to use this

- The kernel ships a Generic Netlink family that nlink doesn't
  natively cover (taskstats, NetLabel, ACPI events, vendor
  out-of-tree families, your own kernel module).
- You want typed request + reply structs instead of hand-rolled
  `MessageBuilder` + `AttrIter` parsing.
- You want the same `Connection<Family>::new_async().await` +
  `conn.send_typed(req).await?` API the in-tree families
  (Wireguard, MACsec, Devlink, …) expose.

If you only need to talk to one of the in-tree families, use the
typed wrapper for it directly — these macros are for the *families
nlink doesn't ship*.

## High-level approach

The macros split family declaration into four orthogonal pieces:

| Macro | Replaces | Lines saved |
|---|---|---|
| `#[genl_family(name, version)]` | Family marker struct + `ProtocolState` + `AsyncProtocolInit` + sealed-trait impls + `family_id` field/getter + `Default`/`Debug` | ~80 |
| `#[derive(GenlCommand)]` | `impl From<MyCmd> for u8` + `impl TryFrom<u8> for MyCmd` | ~25/enum |
| `#[derive(GenlAttribute)]` | `impl From<MyAttr> for u16` + `impl TryFrom<u16> for MyAttr` | ~25/enum |
| `#[derive(GenlMessage)]` | Hand-rolled `to_bytes` + `from_bytes` walking `MessageBuilder` / `AttrIter` | ~30/message |

Once these are in place, the generic
`Connection::<F: GenlFamily>::send_typed<M, R>` +
`dump_typed_stream<M, R>` (Plan 154 Phase 5) do the rest.

The end shape:

```rust,ignore
let conn = Connection::<MyFamily>::new_async().await?;
let reply: MyReply = conn.send_typed(MyRequest { id: 7 }).await?;
```

No `MessageBuilder`, no `GenlMsgHdr::new(...)`, no `AttrIter`,
no `family_id()` lookup — the macros emit all of it.

## Complete walkthrough — taskstats

Working file:
[`crates/nlink/examples/macros/define_taskstats.rs`](../../crates/nlink/examples/macros/define_taskstats.rs).
The kernel's taskstats family (per-task accounting via
`linux/taskstats.h`) is small, frozen, and real — the canonical
example for the macro stack.

### 1. Family marker

```rust,ignore
use nlink::macros::*;
use nlink::netlink::Connection;

#[genl_family(name = "TASKSTATS", version = 1)]
pub struct Taskstats;
```

That one attribute expands to:

- A rewritten `struct Taskstats { family_id: u16 }` (the macro
  injects the `family_id` field — the input must be a unit
  struct).
- `impl ProtocolState for Taskstats` → `PROTOCOL = Protocol::Generic`.
- `impl AsyncProtocolInit for Taskstats` whose `resolve_async`
  body calls `nlink::macros::__rt::resolve_genl_family(socket,
  "TASKSTATS")` — the standard `CTRL_CMD_GETFAMILY` round-trip.
- `impl GenlFamily for Taskstats` — the send-time contract that
  exposes `family_id() -> u16`, `NAME = "TASKSTATS"`, `VERSION = 1`.
- Sealed impls `ProtocolStateSeal` + `AsyncConstructibleSeal` so
  `Connection::<Taskstats>::new_async()` typechecks.
- `Default` (with `family_id = 0`) + `Debug` for diagnostic
  output.
- Compile-time-constant accessors `Taskstats::NAME` and
  `Taskstats::VERSION` for introspection.

### 2. Typed command + attribute enums

```rust,ignore
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
pub enum TaskstatsCmd {
    Unspec = 0,
    Get = 1,
    New = 2,
}

#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
pub enum TaskstatsCmdAttr {
    Unspec = 0,
    Pid = 1,
    Tgid = 2,
    RegisterCpumask = 3,
    DeregisterCpumask = 4,
}

#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
pub enum TaskstatsType {
    Unspec = 0,
    Pid = 1,
    Tgid = 2,
    Stats = 3,
    AggrPid = 4,
    AggrTgid = 5,
    Null = 6,
}
```

The two derives emit `From<MyCmd> for u8` + `TryFrom<u8> for MyCmd`
(and analogously for `u16`-repr attribute enums). Use either repr
for either purpose — `GenlCommand` happens to default to `u8`
because that's the GENL header's `cmd` field width.

### 3. Request body

```rust,ignore
#[derive(GenlMessage, Debug, Default)]
#[genl_message(cmd = TaskstatsCmd::Get)]
pub struct TaskstatsGet {
    #[genl_attr(TaskstatsCmdAttr::Pid)]
    pub pid: u32,
}
```

`#[genl_message(cmd = ...)]` sets the `CMD` const that the
dispatcher writes into the outbound GENL header. `cmd =` accepts
either a literal (`cmd = 1u8`) or a typed-enum variant
(`cmd = TaskstatsCmd::Get`) — the latter routes through the
`GenlCommand` codec, so renaming the variant is a single-edit
change that flows through.

`#[genl_attr(...)]` on each field sets the kernel attribute type
the macro emits/parses. Accepts a literal (`#[genl_attr(1u16)]`)
or a typed-enum variant (`#[genl_attr(TaskstatsCmdAttr::Pid)]`).

Supported field types as of 0.16:

- `u8` / `u16` / `u32` / `u64`
- `String`
- `Vec<u8>`
- `Option<T>` for any of the above — omitted on `None`,
  present-when-`Some` on emit; `Some(parsed)` if the kernel
  returns it on parse.

Unsupported types (`i32`, nested attribute groups via
`#[derive(NetlinkAttrs)]`, `IpAddr`, `bool`) produce a
compile-time error pointing at the offending field. Nested
groups via `#[derive(NetlinkAttrs)]` are tracked as a Plan 154
follow-up.

### 4. Reply body

```rust,ignore
#[derive(GenlMessage, Debug, Default)]
#[genl_message(cmd = TaskstatsCmd::New)]
pub struct TaskstatsReply {
    #[genl_attr(TaskstatsType::Pid)]
    pub pid: u32,
    #[genl_attr(TaskstatsType::Tgid)]
    pub tgid: u32,
    /// Raw `struct taskstats` payload.
    #[genl_attr(TaskstatsType::Stats)]
    pub stats: Vec<u8>,
}
```

Reply structs need `Default`. The macro-emitted `from_bytes`
starts with `Self::default()` and overwrites fields for
attributes it recognizes — missing attributes leave the field
at its `Default` value. This means schema drift in the kernel
doesn't fail-closed: missing fields read as defaults, never as
parse errors. That matches every other nlink parser's behavior.

### 5. Drive it

```rust,ignore
#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Taskstats>::new_async().await?;

    let my_pid = std::process::id();
    let reply: TaskstatsReply = conn
        .send_typed(TaskstatsGet { pid: my_pid })
        .await?;

    println!("PID  : {}", reply.pid);
    println!("TGID : {}", reply.tgid);
    println!("stats payload: {} bytes", reply.stats.len());
    Ok(())
}
```

That's the entire write-the-wire-and-parse-the-reply cycle.
`send_typed` builds a `NLM_F_REQUEST | NLM_F_ACK` frame with the
correct family ID + GENL header + your attributes, sends it,
parses the first non-ACK reply.

For dump-shape kernels (`*_CMD_GET` + `NLM_F_DUMP` returning many
frames), use `dump_typed_stream`:

```rust,ignore
use tokio_stream::StreamExt;

let mut stream = conn.dump_typed_stream::<MyDumpReq, MyReply>(req).await?;
while let Some(item) = stream.next().await {
    let row = item?;
    process(row);
}
```

## Errors

The macros plug into the same `nlink::Error` machinery as the
in-tree families:

- Resolution failure (kernel doesn't have the family registered
  — typically missing kernel module or feature disabled) →
  `Err(Error::FamilyNotFound { name })`. Use `e.is_not_found()`.
- `EPERM` on send (your family requires CAP_NET_ADMIN or
  similar) → `e.is_permission_denied()`.
- Malformed wire frames → `Error::InvalidMessage` /
  `Error::Truncated`. Treat as bugs; surface to logs.
- Kernel error TLVs (ext-ack-enabled, default) carry
  human-readable diagnostic text → `Error::Kernel::ext_ack`.

See [`error-handling-patterns.md`](error-handling-patterns.md)
for the canonical predicate-dispatch idiom.

## Hand-written reference families

When you want to see what the macro generates, read the in-tree
hand-written families in
[`crates/nlink/src/netlink/genl/`](../../crates/nlink/src/netlink/genl/):

- [`wireguard/`](../../crates/nlink/src/netlink/genl/wireguard/) —
  full CRUD over WireGuard devices + peers.
- [`macsec/`](../../crates/nlink/src/netlink/genl/macsec/) — full
  CRUD over MACsec devices + SAs + SCs.
- [`devlink/`](../../crates/nlink/src/netlink/genl/devlink/) —
  device + port + rate-limit + per-port-function-state.

These have the same wire format as a macro-defined family — ~600
lines hand-rolled vs ~30 lines macro-derived. The macros do not
replace them (they all pre-date the macros); they exist as
reference implementations.

## See also

- [`crates/nlink/examples/macros/define_taskstats.rs`](../../crates/nlink/examples/macros/define_taskstats.rs)
  — the runnable end-to-end version of this recipe.
- `nlink::macros` module rustdoc — per-macro reference + the
  `__rt` runtime substrate documentation.
- `nlink-macros` crate README — versioning / publish-order
  guarantees vs nlink proper.
- Plan 154 ([`plans/154-0.16-nlink-macros-plan.md`](../../plans/154-0.16-nlink-macros-plan.md))
  — design rationale + comparison vs neli's macro story.

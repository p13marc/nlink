# nlink-macros

[![crates.io](https://img.shields.io/crates/v/nlink-macros.svg)](https://crates.io/crates/nlink-macros)
[![docs.rs](https://docs.rs/nlink-macros/badge.svg)](https://docs.rs/nlink-macros)

Procedural-macro derives + attribute macros for the
[`nlink`](https://crates.io/crates/nlink) Linux netlink library.
Lets downstream code declare a complete **Generic Netlink family**
— marker struct, typed command enum, typed attribute-kind enums,
typed message bodies, and the full request/response round-trip —
in ~30 lines of declarative code.

## Don't depend on this directly

Add `nlink` to your `Cargo.toml`; it re-exports everything from
this crate under `nlink::macros::*`:

```toml
[dependencies]
nlink = "0.16"
```

```rust
use nlink::macros::*;          // pulls in every macro + the traits
use nlink::netlink::Connection;
```

You only need to depend on `nlink-macros` directly if you're
building a library that exposes the macros to *its* downstream
without dragging in the full `nlink` runtime.

## What it ships

| Macro | Replaces |
|---|---|
| `#[genl_family(name = "...", version = N)]` | Family marker struct + `ProtocolState` + `AsyncProtocolInit` + sealed-trait impls + `family_id` field/getter + `GenlFamily` impl |
| `#[derive(GenlCommand)]` + `#[genl_command(repr = "u8"\|"u16")]` | Typed GENL command enum — `From<MyCmd> for u8` + `TryFrom<u8> for MyCmd` |
| `#[derive(GenlAttribute)]` + `#[genl_attribute(repr = "u8"\|"u16")]` | Typed attribute-kind enum |
| `#[derive(GenlEnum)]` + `#[genl_enum(repr = "u8"\|"u16"\|"u32")]` | Typed value enum encoded *inside* an attribute payload |
| `#[derive(GenlMessage)]` + `#[genl_message(cmd = ...)]` | Typed request/response body with per-field `#[genl_attr(...)]` |

`#[derive(NetlinkAttrs)]` for nested attribute groups is a tracked
follow-up (the marker trait is defined in `nlink::macros::NetlinkAttrs`
already so hand-implementations work today).

## Quick taste

```rust
use nlink::macros::*;
use nlink::netlink::Connection;

#[genl_family(name = "TASKSTATS", version = 1)]
pub struct Taskstats;

#[derive(GenlCommand, Debug, Clone, Copy)]
#[genl_command(repr = "u8")]
pub enum TaskstatsCmd { Unspec = 0, Get = 1, New = 2 }

#[derive(GenlAttribute, Debug, Clone, Copy)]
#[genl_attribute(repr = "u16")]
pub enum TaskstatsCmdAttr { Pid = 1, Tgid = 2 }

#[derive(GenlMessage, Debug, Default)]
#[genl_message(cmd = TaskstatsCmd::Get)]
pub struct TaskstatsGet {
    #[genl_attr(TaskstatsCmdAttr::Pid)] pub pid: u32,
}

#[derive(GenlMessage, Debug, Default)]
#[genl_message(cmd = TaskstatsCmd::New)]
pub struct TaskstatsReply {
    #[genl_attr(TaskstatsCmdAttr::Pid)]  pub pid: u32,
    #[genl_attr(TaskstatsCmdAttr::Tgid)] pub tgid: u32,
}

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Taskstats>::new_async().await?;
    let reply: TaskstatsReply =
        conn.send_typed(TaskstatsGet { pid: std::process::id() }).await?;
    println!("pid={} tgid={}", reply.pid, reply.tgid);
    Ok(())
}
```

See [`docs/recipes/define-your-own-genl-family.md`](https://github.com/p13marc/nlink/blob/master/docs/recipes/define-your-own-genl-family.md)
for the narrative walkthrough and
[`crates/nlink/examples/macros/define_taskstats.rs`](https://github.com/p13marc/nlink/blob/master/crates/nlink/examples/macros/define_taskstats.rs)
for the runnable end-to-end version.

## Versioning & publish order

`nlink-macros` is published to crates.io independently of `nlink`
but they version in lockstep — version `X.Y.Z` of `nlink` depends
on the matching `X.Y.Z` of `nlink-macros`. When cutting a release:

1. Bump both crates' versions.
2. `cargo publish -p nlink-macros` first.
3. Wait ~30s for crates.io to index.
4. `cargo publish -p nlink`.

`nlink`'s `Cargo.toml` pins `nlink-macros` with a `version = "..."`
in addition to the path dep — this is required for `cargo publish
nlink` to resolve the dep on crates.io. Publishing nlink before
nlink-macros will fail with "no matching version found."

## MSRV

Matches `nlink` proper: **Rust 1.95** as of 0.16.

## License

Dual-licensed under MIT OR Apache-2.0, matching `nlink`. See the
root `LICENSE-*` files.

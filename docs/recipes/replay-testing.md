# Testing code that drives nlink, without a kernel

Code that configures networking is awkward to test: it wants root, a
namespace, and often a kernel feature the CI machine does not have. The
`replay` feature (#168) records what a connection sends and receives once,
against a real kernel, and replays it anywhere after that. A test then runs
your code against the recording, as an ordinary user, in a plain `cargo test`.

## When to use this

- Unit tests for code that calls nlink: a reconciler, a CLI, an exporter.
- Reproducing a bug report: record against the reporter's kernel, replay in
  CI.
- Pinning a kernel's answer, such as a newer kernel's attribute layout, that
  the CI kernel cannot give.

It does not replace the integration tests nlink runs against real kernels.
A replay answers only the requests that were recorded, in the order they
were recorded.

## Record

Enable the feature in your dev-dependencies:

```toml
[dev-dependencies]
nlink = { version = "0.32", features = ["replay", "lab"] }
```

Record once, as root, against the kernel whose answers you want:

```rust,no_run
use nlink::lab::LabNamespace;
use nlink::netlink::Route;
use nlink::netlink::link::DummyLink;
use nlink::replay::Recorder;

# async fn record() -> nlink::Result<()> {
let ns = LabNamespace::new("record")?;
let recorder = Recorder::new();
let conn = recorder.connection_in::<Route>(ns.netns())?;

// Whatever your code does with the connection:
conn.add_link(DummyLink::new("d0")).await?;
let links = conn.get_links().await?;
# let _ = links;

recorder.fixture().save("tests/fixtures/add-dummy.nlreplay")?;
# Ok(())
# }
```

A Generic Netlink family records its family-id resolution too:
`recorder.connection_async_in::<Wireguard>(ns.netns()).await?`.

## Replay

```rust,no_run
use nlink::netlink::Route;
use nlink::netlink::link::DummyLink;
use nlink::replay::Fixture;

# async fn replay() -> nlink::Result<()> {
let fixture = Fixture::load("tests/fixtures/add-dummy.nlreplay")?;
let conn = fixture.connection::<Route>()?;

conn.add_link(DummyLink::new("d0")).await?;
let links = conn.get_links().await?;
assert!(links.iter().any(|l| l.name() == Some("d0")));
# Ok(())
# }
```

No root and no namespace are needed: the connection's socket is real but
idle, and every answer comes from the file.

## How a replay matches

- Each datagram your code sends must be the next one recorded, apart from
  its sequence numbers and port id. The replayed answers carry the live
  sequence numbers, including the copy of the request inside an
  acknowledgement. A different request is an error that says so.
- Multicast datagrams come back as they were recorded, so event streams
  replay too.
- Once the recording has ended, a receive is an error rather than a wait.
- A receive while the recording's next frame is a send waits for that send.
  This is what lets a dispatcher's receive task run ahead of its requests.

## The file

```text
nlink-replay v1
tx 2000000012000103…
rx 98050000100002000…
mc …
```

The format is one datagram per line: `tx` for a datagram sent, `rx` for one
received, `mc` for multicast, then the datagram in hex. `#` starts a comment.
The files diff well, and a recording can be trimmed by hand.

## Gotchas

- One recorder or fixture is one connection. Record each connection your
  code opens separately.
- Concurrent requests replay only in the order they were recorded.
- Socket options set on a replayed connection go to its idle socket. File
  descriptors passed with a message are not recorded.

## See also

- `nlink::replay` in the API documentation.
- `scripts/regen-replay-fixtures.sh`: how nlink keeps its own recording, which
  its unit tests replay.

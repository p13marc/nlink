//! The smallest program that calls netem's convenience wrappers — #310.
//!
//! Run with: cargo run -p nlink --example route_tc_minimal_caller -- --apply
//!
//! This example is deliberately tiny, and that is the point.
//!
//! Each `async fn` that awaits another embeds the callee's future in its
//! own, so rustc computes the caller's layout by recursing once per
//! level. nlink's request chain already sits close to the default limit
//! of 128, and `del_netem` / `apply_netem` / `plug_buffer` are one frame
//! deeper than the methods they call:
//!
//! ```text
//! del_netem -> del_qdisc -> del_qdisc_full -> send_ack -> ...
//! ```
//!
//! Layout queries are cached, so a program that touches nlink anywhere
//! else usually computes these futures' layouts on a *shallow* stack
//! first and hits the cache later. That is why nlink's own tests and its
//! larger examples never saw this, and why a small downstream tool that
//! does nothing but call `del_netem` failed to compile with
//! `error: queries overflow the depth limit!` — pointing at its own
//! async block, with no mention of nlink and nothing nlink could set to
//! fix it.
//!
//! So the guard has to be a program with nothing else in it. Adding
//! calls here weakens it.

use nlink::{
    Connection, Route, TcHandle,
    netlink::tc::{NetemConfig, PlugConfig},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    if !std::env::args().any(|a| a == "--apply") {
        println!("compile-only guard for #310; pass --apply to run it against dummy0");
        return Ok(());
    }

    let conn = Connection::<Route>::new()?;
    conn.apply_netem("dummy0", NetemConfig::new().build()).await?;
    conn.del_netem("dummy0").await?;
    conn.add_qdisc("dummy0", PlugConfig::new().build()).await?;
    conn.plug_buffer("dummy0", TcHandle::ROOT).await?;
    Ok(())
}

// #879: a retry helper that takes an `AsyncFnMut`, called with an async
// closure that borrows `self`. No lifetime of `&self` makes the future
// `Send`, and nothing said so until a caller spawned it.
// trybuild sets `--cfg trybuild`, which the checkers build under, without
// declaring it.
#![allow(unexpected_cfgs)]
pub struct Options;

impl Options {
    pub async fn retry<T>(&self, mut f: impl AsyncFnMut() -> T) -> T {
        f().await
    }
}

pub struct Config {
    value: u32,
}

#[nlink_macros::send_futures]
impl Config {
    pub async fn apply_reconcile(&self, opts: &Options) -> u32 {
        opts.retry(async || self.step().await).await
    }

    async fn step(&self) -> u32 {
        self.value
    }
}

fn main() {}

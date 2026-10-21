// A skip records why; one without a reason, or on an impl block, is refused.
// trybuild sets `--cfg trybuild`, which the checkers build under, without
// declaring it.
#![allow(unexpected_cfgs)]
pub struct Counter;

#[nlink_macros::send_futures]
impl Counter {
    #[send_futures(skip = "")]
    pub async fn count(&self) {}
}

#[nlink_macros::send_futures(skip = "the whole block")]
impl Counter {
    pub async fn other(&self) {}
}

fn main() {}

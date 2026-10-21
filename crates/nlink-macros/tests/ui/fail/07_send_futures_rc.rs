// A future that holds an `Rc` across an await is not `Send`.
// trybuild sets `--cfg trybuild`, which the checkers build under, without
// declaring it.
#![allow(unexpected_cfgs)]
pub struct Counter;

#[nlink_macros::send_futures]
impl Counter {
    pub async fn count(&self) -> usize {
        let rc = std::rc::Rc::new(1);
        std::future::ready(()).await;
        *rc
    }
}

#[nlink_macros::send_futures]
pub async fn free() -> usize {
    let rc = std::rc::Rc::new(2);
    std::future::ready(()).await;
    *rc
}

fn main() {}

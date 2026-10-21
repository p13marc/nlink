// #884: every shape of public async fn the checker has to take, each Send.
// trybuild sets `--cfg trybuild`, which the checkers build under, without
// declaring it.
#![allow(unexpected_cfgs)]
use std::sync::Arc;

pub struct Conn<P> {
    name: String,
    _p: std::marker::PhantomData<P>,
}

pub struct Route;

#[nlink_macros::send_futures]
impl<P: Send + Sync> Conn<P> {
    pub async fn by_ref(&self) -> usize {
        self.name.len()
    }

    pub async fn by_mut(&mut self, more: &str) {
        self.name.push_str(more);
    }

    pub async fn by_value(mut self) -> String {
        self.name.push('!');
        self.name
    }

    pub async fn arced(self: Arc<Self>) -> usize {
        self.name.len()
    }

    pub async fn impl_trait(&self, dev: impl Into<String>, (a, _b): (u8, u8)) -> String {
        format!("{}{a}", dev.into())
    }

    pub async fn generic<T: Clone, const N: usize>(&self, items: &[T; N]) -> Vec<T>
    where
        T: std::fmt::Debug,
    {
        items.to_vec()
    }

    /// Not checked: not public.
    async fn private(&self) {}

    /// Not checked: recorded as not `Send`.
    #[send_futures(skip = "holds an Rc across an await, on purpose")]
    pub async fn skipped(&self) {
        let rc = std::rc::Rc::new(1);
        std::future::ready(()).await;
        drop(rc);
    }

    pub fn not_async(&self) {}
}

#[nlink_macros::send_futures]
pub async fn free<'a>(conn: &'a Conn<Route>, label: &'a str) -> String {
    format!("{label}{}", conn.by_ref().await)
}

fn main() {}

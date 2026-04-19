//! Netlink batching for bulk operations.
//!
//! Send multiple netlink messages in a single `sendmsg()` to reduce syscall
//! overhead. For 1000 routes, this reduces 1000 round-trips to ~5.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::route::Ipv4Route;
//!
//! let conn = Connection::<Route>::new()?;
//! let results = conn.batch()
//!     .add_route(Ipv4Route::new("10.0.0.0", 8).dev_index(5))
//!     .add_route(Ipv4Route::new("10.1.0.0", 16).dev_index(5))
//!     .execute()
//!     .await?;
//!
//! println!("{} succeeded, {} failed", results.success_count(), results.error_count());
//! ```

use super::{
    addr::AddressConfig,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    fdb::FdbEntryBuilder,
    link::LinkConfig,
    message::{
        MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NlMsgError, NlMsgType,
    },
    neigh::NeighborConfig,
    protocol::Route,
    route::RouteConfig,
    tc::QdiscConfig,
    types::{
        link::IfInfoMsg,
        tc::{TcMsg, TcaAttr, tc_handle},
    },
};

/// Maximum batch size before auto-splitting (200KB).
const MAX_BATCH_SIZE: usize = 200 * 1024;

/// A batch of netlink operations to execute in minimal syscalls.
///
/// Operations are buffered and sent as concatenated messages in a single
/// `sendmsg()`. The kernel processes them sequentially and returns one
/// ACK per message. Auto-splits at 200KB to stay within socket buffer limits.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::route::Ipv4Route;
///
/// let conn = Connection::<Route>::new()?;
/// let results = conn.batch()
///     .add_route(Ipv4Route::new("10.0.0.0", 8).dev_index(5))
///     .add_route(Ipv4Route::new("10.1.0.0", 16).dev_index(5))
///     .execute()
///     .await?;
///
/// if !results.all_ok() {
///     for (i, err) in results.errors() {
///         eprintln!("op {i}: {err}");
///     }
/// }
/// ```
pub struct Batch<'a> {
    conn: &'a Connection<Route>,
    ops: Vec<BatchOp>,
}

struct BatchOp {
    seq: u32,
    msg: Vec<u8>,
}

impl<'a> Batch<'a> {
    pub(crate) fn new(conn: &'a Connection<Route>) -> Self {
        Self {
            conn,
            ops: Vec::new(),
        }
    }

    /// Add a route to the batch.
    ///
    /// Note: interface references must be pre-resolved to indices (use `dev_index()`
    /// instead of `dev()`) since batching cannot perform async name resolution.
    pub fn add_route<R: RouteConfig>(mut self, config: R) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        config.write_add(&mut builder, &Default::default());
        self.push(builder);
        self
    }

    /// Delete a route in the batch.
    pub fn del_route<R: RouteConfig>(mut self, config: R) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);
        config.write_delete(&mut builder);
        self.push(builder);
        self
    }

    /// Add a link to the batch.
    ///
    /// Note: Only link types without parent references (DummyLink, IfbLink, etc.)
    /// work in batch mode. Types with parent references need async resolution.
    pub fn add_link<L: LinkConfig>(mut self, config: L) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);
        config.write_to(&mut builder, None);
        self.push(builder);
        self
    }

    /// Delete a link by index in the batch.
    pub fn del_link_by_index(mut self, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        let mut ifinfo = IfInfoMsg::new();
        ifinfo.ifi_index = ifindex as i32;
        builder.append(&ifinfo);
        self.push(builder);
        self
    }

    /// Add an address in the batch.
    ///
    /// Note: Use address types with pre-resolved indices (e.g., `Ipv4Address::with_index()`).
    pub fn add_address<A: AddressConfig>(mut self, config: A, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        if config.write_add(&mut builder, ifindex).is_ok() {
            self.push(builder);
        }
        self
    }

    /// Delete an address in the batch.
    pub fn del_address<A: AddressConfig>(mut self, config: A, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
        if config.write_delete(&mut builder, ifindex).is_ok() {
            self.push(builder);
        }
        self
    }

    /// Add a neighbor in the batch.
    ///
    /// Note: Use neighbor types with pre-resolved indices.
    pub fn add_neighbor<N: NeighborConfig>(mut self, config: N, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        if config.write_add(&mut builder, ifindex).is_ok() {
            self.push(builder);
        }
        self
    }

    /// Delete a neighbor in the batch.
    pub fn del_neighbor<N: NeighborConfig>(mut self, config: N, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        if config.write_delete(&mut builder, ifindex).is_ok() {
            self.push(builder);
        }
        self
    }

    /// Add an FDB entry in the batch.
    ///
    /// Pass the resolved interface index and optional master (bridge) index.
    pub fn add_fdb(
        mut self,
        entry: FdbEntryBuilder,
        ifindex: u32,
        master_idx: Option<u32>,
    ) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.push(builder);
        self
    }

    /// Delete an FDB entry in the batch.
    pub fn del_fdb(mut self, entry: FdbEntryBuilder, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        entry.write_delete(&mut builder, ifindex);
        self.push(builder);
        self
    }

    /// Add a qdisc in the batch.
    ///
    /// `ifindex` is the interface index. The qdisc is added as root.
    pub fn add_qdisc(mut self, ifindex: u32, config: impl QdiscConfig) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWQDISC,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(tc_handle::ROOT)
            .with_handle(config.default_handle().unwrap_or(0));
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        if config.write_options(&mut builder).is_ok() {
            builder.nest_end(options_token);
            self.push(builder);
        }
        self
    }

    /// Delete a qdisc in the batch (root qdisc).
    pub fn del_qdisc(mut self, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELQDISC, NLM_F_REQUEST | NLM_F_ACK);
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(tc_handle::ROOT);
        builder.append(&tcmsg);
        self.push(builder);
        self
    }

    fn push(&mut self, mut builder: MessageBuilder) {
        let seq = self.conn.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.conn.socket().pid());
        let msg = builder.finish();
        self.ops.push(BatchOp { seq, msg });
    }

    /// Number of buffered operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Execute all operations, returning per-operation results.
    ///
    /// Auto-splits into chunks if the total size exceeds 200KB.
    /// Only returns `Err` for transport-level errors (socket failure).
    /// Individual operation failures are captured in `BatchResults`.
    #[tracing::instrument(level = "debug", skip_all, fields(ops = self.ops.len()))]
    pub async fn execute(self) -> Result<BatchResults> {
        if self.ops.is_empty() {
            return Ok(BatchResults {
                results: Vec::new(),
            });
        }

        let mut all_results = Vec::with_capacity(self.ops.len());
        let mut chunk_start = 0;
        let mut chunk_size = 0;

        for (i, op) in self.ops.iter().enumerate() {
            if chunk_size + op.msg.len() > MAX_BATCH_SIZE && chunk_size > 0 {
                let chunk_results = self.send_chunk(&self.ops[chunk_start..i]).await?;
                all_results.extend(chunk_results);
                chunk_start = i;
                chunk_size = 0;
            }
            chunk_size += op.msg.len();
        }

        // Send remaining chunk
        if chunk_start < self.ops.len() {
            let chunk_results = self.send_chunk(&self.ops[chunk_start..]).await?;
            all_results.extend(chunk_results);
        }

        Ok(BatchResults {
            results: all_results,
        })
    }

    /// Execute all operations, returning the first error encountered.
    pub async fn execute_all(self) -> Result<()> {
        let results = self.execute().await?;
        for result in &results.results {
            if let Err(e) = result {
                return Err(Error::InvalidMessage(format!(
                    "batch operation failed: {e}"
                )));
            }
        }
        Ok(())
    }

    async fn send_chunk(&self, ops: &[BatchOp]) -> Result<Vec<std::result::Result<(), Error>>> {
        // Concatenate messages into a single buffer
        let total_size: usize = ops.iter().map(|o| o.msg.len()).sum();
        let mut buf = Vec::with_capacity(total_size);
        for op in ops {
            buf.extend_from_slice(&op.msg);
        }

        // Single sendmsg()
        self.conn.socket().send(&buf).await?;

        // Collect ACKs matched by sequence number
        let mut results: Vec<Option<std::result::Result<(), Error>>> =
            (0..ops.len()).map(|_| None).collect();
        let mut remaining = ops.len();

        while remaining > 0 {
            let response = self.conn.socket().recv_msg().await?;

            for result in MessageIter::new(&response) {
                let (header, payload) = result?;

                // Find which op this ACK belongs to
                if let Some(idx) = ops.iter().position(|op| op.seq == header.nlmsg_seq) {
                    if results[idx].is_some() {
                        continue; // Already got this one
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        if err.is_ack() {
                            results[idx] = Some(Ok(()));
                        } else {
                            results[idx] = Some(Err(Error::from_errno(err.error)));
                        }
                        remaining -= 1;
                    }
                }
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap_or(Ok(()))).collect())
    }
}

/// Results from a batch execution.
///
/// Contains one `Result<()>` per operation in submission order.
pub struct BatchResults {
    results: Vec<std::result::Result<(), Error>>,
}

impl BatchResults {
    /// Iterate over all results.
    pub fn iter(&self) -> impl Iterator<Item = &std::result::Result<(), Error>> {
        self.results.iter()
    }

    /// Iterate over only the errors with their indices.
    pub fn errors(&self) -> impl Iterator<Item = (usize, &Error)> {
        self.results
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().err().map(|e| (i, e)))
    }

    /// Number of successful operations.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_ok()).count()
    }

    /// Number of failed operations.
    pub fn error_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_err()).count()
    }

    /// True if all operations succeeded.
    pub fn all_ok(&self) -> bool {
        self.results.iter().all(|r| r.is_ok())
    }

    /// Total number of operations.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether there are no results.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_results(results: Vec<std::result::Result<(), Error>>) -> BatchResults {
        BatchResults { results }
    }

    #[test]
    fn test_empty_results() {
        let r = make_results(vec![]);
        assert!(r.is_empty());
        assert!(r.all_ok());
        assert_eq!(r.len(), 0);
        assert_eq!(r.success_count(), 0);
        assert_eq!(r.error_count(), 0);
        assert_eq!(r.errors().count(), 0);
    }

    #[test]
    fn test_all_success() {
        let r = make_results(vec![Ok(()), Ok(()), Ok(())]);
        assert!(r.all_ok());
        assert_eq!(r.len(), 3);
        assert_eq!(r.success_count(), 3);
        assert_eq!(r.error_count(), 0);
        assert_eq!(r.errors().count(), 0);
    }

    #[test]
    fn test_mixed_results() {
        let r = make_results(vec![
            Ok(()),
            Err(Error::from_errno(-2)), // ENOENT
            Ok(()),
            Err(Error::from_errno(-1)), // EPERM
        ]);
        assert!(!r.all_ok());
        assert_eq!(r.len(), 4);
        assert_eq!(r.success_count(), 2);
        assert_eq!(r.error_count(), 2);

        let errors: Vec<_> = r.errors().collect();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].0, 1); // index of first error
        assert!(errors[0].1.is_not_found());
        assert_eq!(errors[1].0, 3); // index of second error
        assert!(errors[1].1.is_permission_denied());
    }

    #[test]
    fn test_all_errors() {
        let r = make_results(vec![
            Err(Error::from_errno(-17)), // EEXIST
            Err(Error::from_errno(-16)), // EBUSY
        ]);
        assert!(!r.all_ok());
        assert_eq!(r.success_count(), 0);
        assert_eq!(r.error_count(), 2);
    }

    #[test]
    fn test_iter() {
        let r = make_results(vec![Ok(()), Err(Error::from_errno(-1))]);
        let items: Vec<_> = r.iter().collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }
}

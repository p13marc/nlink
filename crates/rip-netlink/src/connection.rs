//! High-level netlink connection with request/response handling.

use crate::builder::MessageBuilder;
use crate::error::{Error, Result};
use crate::message::{
    MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_MULTI, NLM_F_REQUEST, NlMsgError, NlMsgHdr, NlMsgType,
};
use crate::socket::{NetlinkSocket, Protocol};

/// High-level netlink connection.
pub struct Connection {
    socket: NetlinkSocket,
}

impl Connection {
    /// Create a new connection for the given protocol.
    pub fn new(protocol: Protocol) -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::new(protocol)?,
        })
    }

    /// Get the underlying socket.
    pub fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// Send a request and wait for a single response or ACK.
    pub async fn request(&self, mut builder: MessageBuilder) -> Result<Vec<u8>> {
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Receive response
        let response = self.socket.recv_msg().await?;
        self.process_response(&response, seq)?;

        Ok(response)
    }

    /// Send a request that expects an ACK only (no data response).
    pub async fn request_ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Receive ACK
        let response = self.socket.recv_msg().await?;
        self.process_ack(&response, seq)?;

        Ok(())
    }

    /// Send a dump request and collect all responses.
    pub async fn dump(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        let mut responses = Vec::new();

        loop {
            let data = self.socket.recv_msg().await?;
            let mut done = false;

            for result in MessageIter::new(&data) {
                let (header, payload) = result?;

                // Check sequence number
                if header.nlmsg_seq != seq {
                    continue;
                }

                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if !err.is_ack() {
                        return Err(Error::from_errno(err.error));
                    }
                }

                if header.is_done() {
                    done = true;
                    break;
                }

                // Collect the full message (header + payload)
                let msg_len = header.nlmsg_len as usize;
                let msg_start = payload.as_ptr() as usize
                    - data.as_ptr() as usize
                    - std::mem::size_of::<NlMsgHdr>();
                if msg_start + msg_len <= data.len() {
                    responses.push(data[msg_start..msg_start + msg_len].to_vec());
                }
            }

            if done {
                break;
            }
        }

        Ok(responses)
    }

    /// Process a response and check for errors.
    fn process_response(&self, data: &[u8], expected_seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != expected_seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    return Err(Error::from_errno(err.error));
                }
            }
        }

        Ok(())
    }

    /// Process an ACK response.
    fn process_ack(&self, data: &[u8], expected_seq: u32) -> Result<()> {
        for result in MessageIter::new(data) {
            let (header, payload) = result?;

            if header.nlmsg_seq != expected_seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                if !err.is_ack() {
                    return Err(Error::from_errno(err.error));
                }
                return Ok(());
            }
        }

        Err(Error::InvalidMessage("expected ACK message".into()))
    }

    /// Subscribe to multicast groups for monitoring.
    pub fn subscribe(&mut self, group: u32) -> Result<()> {
        self.socket.add_membership(group)
    }

    /// Receive the next event message (for monitoring).
    pub async fn recv_event(&self) -> Result<Vec<u8>> {
        self.socket.recv_msg().await
    }
}

/// Helper to build a dump request.
pub fn dump_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_DUMP)
}

/// Helper to build a request expecting ACK.
pub fn ack_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK)
}

/// Helper to build a create request.
pub fn create_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400) // NLM_F_CREATE
}

/// Helper to build a create-or-replace request.
pub fn replace_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400 | 0x100) // NLM_F_CREATE | NLM_F_REPLACE
}

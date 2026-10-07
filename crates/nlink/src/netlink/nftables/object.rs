//! Named stateful objects — counters, quotas and limits a table holds by
//! name and rules share (`counter name "web"`, `quota name "q"`), and that
//! object maps pick per packet. ipset's per-element `counters` become a map
//! of counter objects.

use super::expr::{LimitExpr, QuotaExpr};
use super::types::{Family, LimitUnit};
use super::*;
use crate::netlink::attr::{AttrIter, get};
use crate::netlink::builder::MessageBuilder;

/// The kind of a stateful object: `NFT_OBJECT_*`. Only the kinds nlink can
/// build are named; [`ObjectState::Other`] carries the rest as read back.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum ObjectType {
    /// `NFT_OBJECT_COUNTER`.
    Counter = 1,
    /// `NFT_OBJECT_QUOTA`.
    Quota = 2,
    /// `NFT_OBJECT_LIMIT`.
    Limit = 4,
}

impl ObjectType {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Counter),
            2 => Some(Self::Quota),
            4 => Some(Self::Limit),
            _ => None,
        }
    }
}

/// What an object is configured to do.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectConfig {
    /// A counter: packets and bytes.
    Counter,
    /// A byte quota — see [`QuotaExpr`].
    Quota(QuotaExpr),
    /// A packet-rate limit — see [`LimitExpr`].
    Limit(LimitExpr),
}

impl ObjectConfig {
    /// The object type this configures.
    pub fn object_type(&self) -> ObjectType {
        match self {
            Self::Counter => ObjectType::Counter,
            Self::Quota(_) => ObjectType::Quota,
            Self::Limit(_) => ObjectType::Limit,
        }
    }
}

/// A named stateful object, to create with
/// [`Connection::add_object`](crate::netlink::Connection::add_object).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Object {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) config: ObjectConfig,
}

impl Object {
    /// An object named `name` in `table`, configured by `config`.
    pub fn new(table: &str, name: &str, config: ObjectConfig) -> Self {
        Self {
            table: table.to_string(),
            name: name.to_string(),
            family: Family::Inet,
            config,
        }
    }

    /// A named counter (`counter name`).
    pub fn counter(table: &str, name: &str) -> Self {
        Self::new(table, name, ObjectConfig::Counter)
    }

    /// A named quota (`quota name`).
    pub fn quota(table: &str, name: &str, quota: QuotaExpr) -> Self {
        Self::new(table, name, ObjectConfig::Quota(quota))
    }

    /// A named limit (`limit name`).
    pub fn limit(table: &str, name: &str, limit: LimitExpr) -> Self {
        Self::new(table, name, ObjectConfig::Limit(limit))
    }

    /// Set the address family (default `inet`).
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Owning table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Object name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its configuration.
    pub fn config(&self) -> &ObjectConfig {
        &self.config
    }
}

/// A stateful object as read back from the kernel.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ObjectInfo {
    /// Owning table.
    pub table: String,
    /// Object name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Kernel handle.
    pub handle: u64,
    /// How many rules and set elements reference it.
    pub use_count: u32,
    /// Its configuration and live state.
    pub state: ObjectState,
}

impl ObjectInfo {
    /// The object type, if nlink models it.
    pub fn object_type(&self) -> Option<ObjectType> {
        match &self.state {
            ObjectState::Counter { .. } => Some(ObjectType::Counter),
            ObjectState::Quota { .. } => Some(ObjectType::Quota),
            ObjectState::Limit(_) => Some(ObjectType::Limit),
            ObjectState::Other { .. } => None,
        }
    }
}

/// An object's configuration and live state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectState {
    /// A counter's totals.
    #[non_exhaustive]
    Counter {
        /// Packets counted.
        packets: u64,
        /// Bytes counted.
        bytes: u64,
    },
    /// A quota.
    #[non_exhaustive]
    Quota {
        /// The quota, in bytes.
        bytes: u64,
        /// Bytes used, capped at the quota.
        consumed: u64,
        /// `quota over`: matches once used up.
        over: bool,
        /// Used up (`NFT_QUOTA_F_DEPLETED`).
        depleted: bool,
    },
    /// A packet-rate limit.
    Limit(LimitExpr),
    /// A kind nlink does not model (or a byte-rate limit): its
    /// `NFT_OBJECT_*` type and raw `NFTA_OBJ_DATA`.
    #[non_exhaustive]
    Other {
        /// `NFT_OBJECT_*`.
        object_type: u32,
        /// The raw `NFTA_OBJ_DATA` payload.
        data: Vec<u8>,
    },
}

impl ObjectState {
    /// The configuration part of this state, for the declarative diff; live
    /// counts and consumption are not configuration.
    pub(crate) fn config(&self) -> Option<ObjectConfig> {
        match self {
            Self::Counter { .. } => Some(ObjectConfig::Counter),
            Self::Quota { bytes, over, .. } => {
                let mut quota = QuotaExpr::new(*bytes);
                quota.over = *over;
                Some(ObjectConfig::Quota(quota))
            }
            Self::Limit(limit) => Some(ObjectConfig::Limit(limit.clone())),
            Self::Other { .. } => None,
        }
    }
}

/// Append `NFTA_OBJ_DATA` for `config`: what `nft_obj_init` reads, in the
/// shape the matching expression has.
pub(crate) fn append_object_data(builder: &mut MessageBuilder, config: &ObjectConfig) {
    let data = builder.nest_start(NFTA_OBJ_DATA | 0x8000);
    match config {
        ObjectConfig::Counter => {}
        ObjectConfig::Quota(quota) => super::expr::write_quota_attrs(builder, quota, false),
        ObjectConfig::Limit(limit) => super::expr::write_limit_attrs(builder, limit),
    }
    builder.nest_end(data);
}

/// Parse one `NFT_MSG_NEWOBJ` dump payload (after the nfgenmsg).
pub(crate) fn parse_object(data: &[u8], family: Family) -> Option<ObjectInfo> {
    let mut table = None;
    let mut name = None;
    let mut object_type = None;
    let mut payload: &[u8] = &[];
    let mut handle = 0;
    let mut use_count = 0;
    for (attr, value) in AttrIter::new(data) {
        match attr & 0x7FFF {
            NFTA_OBJ_TABLE => table = get::string(value).ok().map(str::to_string),
            NFTA_OBJ_NAME => name = get::string(value).ok().map(str::to_string),
            NFTA_OBJ_TYPE => object_type = get::u32_be(value).ok(),
            NFTA_OBJ_DATA => payload = value,
            NFTA_OBJ_HANDLE => handle = get::u64_be(value).unwrap_or(0),
            NFTA_OBJ_USE => use_count = get::u32_be(value).unwrap_or(0),
            _ => {}
        }
    }
    let object_type = object_type?;
    let state = parse_state(object_type, payload).unwrap_or_else(|| ObjectState::Other {
        object_type,
        data: payload.to_vec(),
    });
    Some(ObjectInfo {
        table: table?,
        name: name?,
        family,
        handle,
        use_count,
        state,
    })
}

fn parse_state(object_type: u32, data: &[u8]) -> Option<ObjectState> {
    let attrs: Vec<(u16, &[u8])> = AttrIter::new(data).map(|(a, v)| (a & 0x7FFF, v)).collect();
    let u64_of = |id| {
        attrs
            .iter()
            .find(|(a, _)| *a == id)
            .and_then(|(_, v)| get::u64_be(v).ok())
    };
    let u32_of = |id| {
        attrs
            .iter()
            .find(|(a, _)| *a == id)
            .and_then(|(_, v)| get::u32_be(v).ok())
    };
    match ObjectType::from_u32(object_type)? {
        ObjectType::Counter => Some(ObjectState::Counter {
            packets: u64_of(NFTA_COUNTER_PACKETS)?,
            bytes: u64_of(NFTA_COUNTER_BYTES)?,
        }),
        ObjectType::Quota => {
            let flags = u32_of(NFTA_QUOTA_FLAGS).unwrap_or(0);
            Some(ObjectState::Quota {
                bytes: u64_of(NFTA_QUOTA_BYTES)?,
                consumed: u64_of(NFTA_QUOTA_CONSUMED).unwrap_or(0),
                over: flags & NFT_QUOTA_F_INV != 0,
                depleted: flags & NFT_QUOTA_F_DEPLETED != 0,
            })
        }
        ObjectType::Limit => {
            // A byte-rate limit (NFT_LIMIT_PKT_BYTES) is not a LimitExpr.
            if u32_of(NFTA_LIMIT_TYPE).unwrap_or(0) != 0 {
                return None;
            }
            let unit = match u64_of(NFTA_LIMIT_UNIT)? {
                1 => LimitUnit::Second,
                60 => LimitUnit::Minute,
                3600 => LimitUnit::Hour,
                86400 => LimitUnit::Day,
                _ => return None,
            };
            let mut limit = LimitExpr::packets(u64_of(NFTA_LIMIT_RATE)?, unit)
                .burst(u32_of(NFTA_LIMIT_BURST).unwrap_or(0));
            if u32_of(NFTA_LIMIT_FLAGS).unwrap_or(0) & NFT_LIMIT_F_INV != 0 {
                limit = limit.over();
            }
            Some(ObjectState::Limit(limit))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_of(config: &ObjectConfig) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        append_object_data(&mut b, config);
        // Header (16) + the NFTA_OBJ_DATA nest header (4).
        b.as_bytes()[20..].to_vec()
    }

    #[test]
    fn object_data_reads_back_as_its_configuration() {
        let quota = ObjectConfig::Quota(QuotaExpr::new(1_000_000).over());
        let state = parse_state(ObjectType::Quota as u32, &data_of(&quota)).unwrap();
        assert_eq!(state.config(), Some(quota));

        let limit = ObjectConfig::Limit(LimitExpr::packets(10, LimitUnit::Minute).burst(3));
        let state = parse_state(ObjectType::Limit as u32, &data_of(&limit)).unwrap();
        assert_eq!(state.config(), Some(limit));

        // A counter's request carries no data; the dump has its totals.
        assert!(data_of(&ObjectConfig::Counter).is_empty());
    }

    #[test]
    fn a_request_never_carries_a_quota_consumption_or_depletion() {
        // nft_quota_do_init starts the quota at CONSUMED if it is sent, and
        // refuses NFT_QUOTA_F_DEPLETED (EOPNOTSUPP).
        let data = data_of(&ObjectConfig::Quota(QuotaExpr::new(500)));
        let attrs: Vec<u16> = AttrIter::new(&data).map(|(a, _)| a & 0x7FFF).collect();
        assert_eq!(attrs, [NFTA_QUOTA_BYTES, NFTA_QUOTA_FLAGS]);
    }

    #[test]
    fn a_byte_limit_or_an_unknown_kind_is_other_not_a_guess() {
        let mut b = MessageBuilder::new(0, 0);
        b.append_attr_u64_be(NFTA_LIMIT_RATE, 1000);
        b.append_attr_u64_be(NFTA_LIMIT_UNIT, 1);
        b.append_attr_u32_be(NFTA_LIMIT_TYPE, 1); // NFT_LIMIT_PKT_BYTES
        assert_eq!(parse_state(ObjectType::Limit as u32, &b.as_bytes()[16..]), None);
        assert_eq!(parse_state(3, &[]), None); // ct helper
    }
}

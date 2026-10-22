//! What the kernel holds, one object at a time, as the typed diff says it
//! (#708).
//!
//! Each type is the same on both sides of a change: read back from the
//! kernel with `from_kernel`, or from what a declaration makes the kernel
//! hold (the echo [`RulesetSnapshot::from_config`] simulates). A read-back
//! never fails and never invents a value: what nlink cannot name is kept as
//! the kernel said it ([`SetKeyType::Other`], a rule's raw
//! [`Expr`](crate::netlink::nftables::Expr)s) or named in `unread`.
//!
//! [`RulesetSnapshot::from_config`]: super::RulesetSnapshot::from_config

use std::time::Duration;

use super::super::expr::ElementStatement;
use super::super::object::{ObjectConfig, ObjectInfo};
use super::super::types::{
    ChainInfo, ChainKind, Family, Flowtable, RuleInfo, SetDataType, SetElement, SetFlags, SetInfo,
    SetKeyType, SetPolicy, Table,
};
use super::super::RuleSpec;
use super::diff::{RuleHandle, RulePlacement};

/// A table: its flags and comment. Its contents are changes of their own.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftTable {
    /// Its family.
    pub family: Family,
    /// Its name.
    pub name: String,
    /// `NFT_TABLE_F_*`.
    pub flags: u32,
    /// Its comment.
    pub comment: Option<String>,
}

impl NftTable {
    /// The table as the kernel reports it.
    pub fn from_kernel(table: &Table) -> Self {
        Self {
            family: table.family,
            name: table.name.clone(),
            flags: table.flags,
            comment: table.comment.clone(),
        }
    }
}

/// A chain: regular or base, and its comment.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftChain {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// What it is, with a base chain's devices sorted. `None` for a base
    /// chain of a hook or type nlink has no name for.
    pub kind: Option<ChainKind>,
    /// Its comment.
    pub comment: Option<String>,
}

impl NftChain {
    /// The chain as the kernel reports it.
    pub fn from_kernel(chain: &ChainInfo) -> Self {
        Self {
            family: chain.family,
            table: chain.table.clone(),
            name: chain.name.clone(),
            kind: chain.kind().map(ChainKind::with_sorted_devices),
            comment: chain.comment.clone(),
        }
    }
}

/// A rule: where it is, or where it goes, and its body.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftRule {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its chain.
    pub chain: String,
    /// nlink's key for it, if nlink wrote it.
    pub key: Option<String>,
    /// Its kernel handle: where it is. `None` for a rule not yet added.
    pub handle: Option<RuleHandle>,
    /// Where it goes. `None` for a rule that stays where it is.
    pub placement: Option<RulePlacement>,
    /// Its body. In JSON it is [`nft`](Self::nft).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub spec: RuleSpec,
    /// The body as `nft -s list` prints it, or `None` where nlink cannot
    /// print it.
    pub nft: Option<String>,
}

impl NftRule {
    /// The rule as the kernel reports it, lifted to a spec.
    pub fn from_kernel(rule: &RuleInfo) -> Self {
        Self {
            family: rule.family,
            table: rule.table.clone(),
            chain: rule.chain.clone(),
            key: rule.key.clone(),
            handle: Some(RuleHandle(rule.handle)),
            placement: None,
            spec: rule.spec(),
            nft: rule.nft_syntax_stateless(),
        }
    }
}

/// A set or map: its key, data, flags and settings. Its elements are a
/// change of their own, [`NftElements`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftSet {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Its key.
    pub key_type: SetKeyType,
    /// Its flags, as the kernel keeps them.
    pub flags: SetFlags,
    /// What a map maps to; `None` for a set.
    pub data: Option<SetDataType>,
    /// Its size, if it has one.
    pub size: Option<u32>,
    /// Its elements' default timeout.
    pub timeout: Option<Duration>,
    /// Its garbage collection interval.
    pub gc_interval: Option<Duration>,
    /// What the kernel picks its backend for.
    pub policy: SetPolicy,
    /// The statements each element carries.
    pub statements: Vec<ElementStatement>,
    /// Its comment.
    pub comment: Option<String>,
    /// What nlink could not read: an object type or a statement it has no
    /// name for.
    pub unread: Vec<String>,
}

impl NftSet {
    /// The set as the kernel reports it.
    pub fn from_kernel(set: &SetInfo) -> Self {
        let mut unread = Vec::new();
        let data =
            match SetDataType::from_kernel(set.flags, set.data_type, set.data_len, set.object_type)
            {
                Ok(data) => data,
                Err(why) => {
                    unread.push(why);
                    None
                }
            };
        let mut statements = Vec::new();
        for statement in &set.statements {
            match ElementStatement::from_rule_expr(statement) {
                Some(s) => statements.push(s),
                None => unread.push(format!("statement {statement:?}")),
            }
        }
        Self {
            family: set.family,
            table: set.table.clone(),
            name: set.name.clone(),
            key_type: SetKeyType::from_kernel(set.key_type, set.key_len),
            flags: set.flags,
            data,
            size: set.size,
            timeout: set.timeout,
            gc_interval: set.gc_interval,
            policy: set.policy,
            statements,
            comment: set.comment.clone(),
            unread,
        }
    }
}

/// Elements of a set or map.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftElements {
    /// The set's table's family.
    pub family: Family,
    /// The set's table.
    pub table: String,
    /// The set.
    pub set: String,
    /// The elements.
    pub elements: Vec<SetElement>,
}

/// A named counter, quota, limit, conntrack helper or secmark.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftObject {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Its configuration, without what the packet path has done to it.
    pub config: ObjectConfig,
}

impl NftObject {
    /// The object as the kernel reports it; `None` for one of a type nlink
    /// does not model.
    pub fn from_kernel(object: &ObjectInfo) -> Option<Self> {
        Some(Self {
            family: object.family,
            table: object.table.clone(),
            name: object.name.clone(),
            config: object.state.config()?,
        })
    }
}

/// A flowtable.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftFlowtable {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Its devices, sorted.
    pub devices: Vec<String>,
    /// Its priority.
    pub priority: i32,
    /// `NFT_FLOWTABLE_*`.
    pub flags: u32,
}

impl NftFlowtable {
    /// The flowtable as the kernel reports it.
    pub fn from_kernel(flowtable: &Flowtable) -> Self {
        let mut devices = flowtable.devs.clone();
        devices.sort();
        Self {
            family: flowtable.family,
            table: flowtable.table.clone(),
            name: flowtable.name.clone(),
            devices,
            priority: flowtable.priority,
            flags: flowtable.flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: [SetKeyType; 8] = [
        SetKeyType::Ipv4Addr,
        SetKeyType::Ipv6Addr,
        SetKeyType::EtherAddr,
        SetKeyType::InetService,
        SetKeyType::IfIndex,
        SetKeyType::ClassId,
        SetKeyType::Mark,
        SetKeyType::InetProto,
    ];

    /// Every key type nlink names reads back as itself, and so does every
    /// concatenation of two to five of them.
    #[test]
    fn a_key_type_reads_back_as_itself() {
        let back = |k: &SetKeyType| SetKeyType::from_kernel(k.type_id(), k.len());
        for key in &KEYS {
            assert_eq!(back(key), *key);
        }
        let mut concats: Vec<Vec<SetKeyType>> = KEYS.iter().map(|k| vec![k.clone()]).collect();
        let mut checked = 0;
        for _ in 2..=5 {
            concats = concats
                .iter()
                .flat_map(|c| {
                    KEYS.iter().map(move |k| {
                        let mut c = c.clone();
                        c.push(k.clone());
                        c
                    })
                })
                .collect();
            for parts in &concats {
                let key = SetKeyType::Concat(parts.clone());
                assert_eq!(back(&key), key);
                checked += 1;
            }
        }
        assert_eq!(checked, 64 + 512 + 4096 + 32768);
    }

    /// What nlink has no name for is kept as the kernel said it, never
    /// guessed.
    #[test]
    fn an_unknown_key_type_is_kept_as_it_is() {
        // nft's TYPE_IFNAME, 16 bytes.
        let ifname = SetKeyType::from_kernel(41, 16);
        assert_eq!(
            ifname,
            SetKeyType::Other {
                type_id: 41,
                len: 16
            }
        );
        assert_eq!((ifname.type_id(), ifname.len()), (41, 16));
        // A name nlink knows, at a length it is not.
        assert_eq!(
            SetKeyType::from_kernel(7, 16),
            SetKeyType::Other {
                type_id: 7,
                len: 16
            }
        );
        // ifname . ipv4_addr: the unknown part takes what the other leaves.
        assert_eq!(
            SetKeyType::from_kernel((41 << 6) | 7, 20),
            SetKeyType::Concat(vec![
                SetKeyType::Other {
                    type_id: 41,
                    len: 16
                },
                SetKeyType::Ipv4Addr
            ])
        );
        // Two unknown parts, or lengths that do not add up: the whole key.
        assert_eq!(
            SetKeyType::from_kernel((41 << 6) | 42, 20),
            SetKeyType::Other {
                type_id: (41 << 6) | 42,
                len: 20
            }
        );
        assert_eq!(
            SetKeyType::from_kernel((7 << 6) | 13, 12),
            SetKeyType::Other {
                type_id: (7 << 6) | 13,
                len: 12
            }
        );
        // A field of id 0, inside, says nothing of where the fields are.
        let zero = (7 << 12) | 13;
        assert_eq!(
            SetKeyType::from_kernel(zero, 12),
            SetKeyType::Other {
                type_id: zero,
                len: 12
            }
        );
        // The unknown part's room must be whole 4-byte words.
        let odd = (41 << 6) | 7;
        assert_eq!(
            SetKeyType::from_kernel(odd, 22),
            SetKeyType::Other {
                type_id: odd,
                len: 22
            }
        );
    }

    /// A map's data type reads back; an object map of a type nlink does not
    /// model says which.
    #[test]
    fn a_maps_data_type_reads_back() {
        use crate::netlink::nftables::NFT_DATA_VERDICT;
        use crate::netlink::nftables::object::ObjectType;
        let set = SetFlags::empty();
        assert_eq!(SetDataType::from_kernel(set, None, None, None), Ok(None));
        assert_eq!(
            SetDataType::from_kernel(SetFlags::MAP, Some(NFT_DATA_VERDICT), None, None),
            Ok(Some(SetDataType::Verdict))
        );
        assert_eq!(
            SetDataType::from_kernel(SetFlags::MAP, Some(19), Some(4), None),
            Ok(Some(SetDataType::Value(SetKeyType::Mark)))
        );
        assert_eq!(
            SetDataType::from_kernel(
                SetFlags::OBJECT,
                None,
                None,
                Some(ObjectType::Counter as u32)
            ),
            Ok(Some(SetDataType::Object(ObjectType::Counter)))
        );
        assert_eq!(
            SetDataType::from_kernel(SetFlags::OBJECT, None, None, Some(99)),
            Err("object type 99".to_string())
        );
        assert_eq!(
            SetDataType::from_kernel(SetFlags::OBJECT, None, None, None),
            Err("an object map without an object type".to_string())
        );
    }
}

//! Libnftnl-compatible TLV encoding for `NFTA_RULE_USERDATA`.
//!
//! `NFTA_RULE_USERDATA` is the kernel's opaque-bytes attribute on
//! rules — preserved verbatim across reads / writes, max 256
//! bytes. By convention (set by libnftnl + adopted by Google's
//! `nftables` Go library + the `nft` CLI) the payload is a TLV
//! sequence where each entry is `[type: u8][length: u8][data: N
//! bytes]`. Type `NFTNL_UDATA_RULE_COMMENT = 0` is the standard
//! human-readable comment that `nft list ruleset` renders as
//! inline `comment "..."`.
//!
//! nlink uses this for **per-rule reconciliation identity** —
//! the [`DeclaredRule::handle_key`] is encoded as
//! `"nlink:<key>"`, so the kernel round-trips it across dumps
//! and the diff layer can match declared rules to kernel rules
//! by key (Plan 157b v2 — analogous to `LinkConfig::name` /
//! `RouteConfig::destination` in the existing `NetworkConfig`).
//!
//! Foreign comments — anything that doesn't start with
//! `"nlink:"` — are preserved as opaque bytes
//! ([`RuleInfo::userdata_raw`]) so re-applying a config doesn't
//! strip comments set by other tools.
//!
//! [`DeclaredRule::handle_key`]:
//!     crate::netlink::nftables::config::DeclaredRule
//! [`RuleInfo::userdata_raw`]: super::types::RuleInfo

/// `NFTNL_UDATA_RULE_COMMENT = 0` — the libnftnl-defined TLV
/// type for user-visible rule comments.
pub(crate) const NFTNL_UDATA_RULE_COMMENT: u8 = 0;

/// `NFTNL_UDATA_COMMENT_MAXLEN = 128` — libnftnl-enforced max
/// length for the comment string (including trailing NUL).
pub(crate) const NFTNL_UDATA_COMMENT_MAXLEN: usize = 128;

/// Prefix attached to the user-supplied `handle_key` so the diff
/// layer can distinguish rules nlink created from rules added
/// externally (`iptables-nft`, hand-edited via `nft -f`, etc.).
const NLINK_PREFIX: &str = "nlink:";

/// The comment text a rule carries: `nlink:<key>`, `nlink:<key> <comment>`,
/// or — for a rule nlink does not manage — the comment verbatim.
pub(crate) fn rule_comment_text(key: Option<&str>, comment: Option<&str>) -> Option<String> {
    match (key, comment) {
        (Some(key), Some(comment)) => Some(format!("{NLINK_PREFIX}{key} {comment}")),
        (Some(key), None) => Some(format!("{NLINK_PREFIX}{key}")),
        (None, Some(comment)) => Some(comment.to_string()),
        (None, None) => None,
    }
}

/// Encode a rule's key and comment as a libnftnl-compatible TLV `userdata`
/// payload, suitable for `NFTA_RULE_USERDATA`. `Ok(None)` when the rule has
/// neither.
///
/// A comment longer than `NFTNL_UDATA_COMMENT_MAXLEN` (127 bytes and the
/// NUL) is an error. It used to be dropped silently, installing a keyed
/// rule with no identity — which the declarative diff then re-added on
/// every apply.
pub(crate) fn encode_rule_userdata(
    key: Option<&str>,
    comment: Option<&str>,
) -> crate::netlink::error::Result<Option<Vec<u8>>> {
    let Some(text) = rule_comment_text(key, comment) else {
        return Ok(None);
    };
    if text.contains('\0') {
        return Err(crate::netlink::error::Error::InvalidMessage(
            "rule comment contains a NUL byte".into(),
        ));
    }
    let body = format!("{text}\0");
    let body_bytes = body.as_bytes();
    if body_bytes.len() > NFTNL_UDATA_COMMENT_MAXLEN {
        return Err(crate::netlink::error::Error::InvalidMessage(format!(
            "rule comment `{text}` is {} bytes; the kernel keeps at most {} \
             (`nlink:<key>` and a following comment share that space)",
            text.len(),
            NFTNL_UDATA_COMMENT_MAXLEN - 1,
        )));
    }
    let mut tlv = Vec::with_capacity(2 + body_bytes.len());
    tlv.push(NFTNL_UDATA_RULE_COMMENT);
    tlv.push(body_bytes.len() as u8);
    tlv.extend_from_slice(body_bytes);
    Ok(Some(tlv))
}

/// Encode a bare key, as `nlink:<key>`. Test convenience.
#[cfg(test)]
pub(crate) fn encode_nlink_comment(key: &str) -> Option<Vec<u8>> {
    encode_rule_userdata(Some(key), None).ok().flatten()
}

/// Walk a libnftnl-formatted TLV `userdata` payload and extract
/// an `nlink:`-prefixed comment, if any.
///
/// Returns `None` when:
/// - The payload is empty or malformed (truncated TLV).
/// - No `NFTNL_UDATA_RULE_COMMENT` entry is present.
/// - The comment exists but doesn't carry the `nlink:` prefix
///   (i.e., it's a foreign comment — preserved in
///   [`RuleInfo::userdata_raw`] but not managed by our diff).
///
/// The TLV walk is lenient: unknown TLV types are skipped (forward-
/// compat with future libnftnl additions like
/// `NFTNL_UDATA_RULE_EBPF`).
///
/// [`RuleInfo::userdata_raw`]: super::types::RuleInfo
pub(crate) fn parse_nlink_comment(userdata: &[u8]) -> Option<String> {
    let text = parse_comment(userdata)?;
    let rest = text.strip_prefix(NLINK_PREFIX)?;
    // The key runs to the first space; what follows is a human comment.
    Some(rest.split_once(' ').map_or(rest, |(key, _)| key).to_string())
}

/// The human part of an nlink comment — what follows `nlink:<key> ` — or
/// the whole text for a comment nlink did not write.
pub(crate) fn human_comment(comment_text: &str) -> Option<&str> {
    match comment_text.strip_prefix(NLINK_PREFIX) {
        Some(rest) => rest.split_once(' ').map(|(_, human)| human),
        None => Some(comment_text),
    }
}

/// The rule comment exactly as `nft list ruleset` shows it — the
/// `NFTNL_UDATA_RULE_COMMENT` string with its NUL removed — whoever set
/// it. `None` when there is no comment or the TLVs are malformed.
pub(crate) fn parse_comment(userdata: &[u8]) -> Option<String> {
    let mut cursor = userdata;
    while cursor.len() >= 2 {
        let ty = cursor[0];
        let len = cursor[1] as usize;
        if cursor.len() < 2 + len {
            // Truncated TLV; bail. Foreign tools shouldn't ship
            // these but defensive code costs nothing.
            return None;
        }
        let payload = &cursor[2..2 + len];
        if ty == NFTNL_UDATA_RULE_COMMENT {
            let s = std::str::from_utf8(payload)
                .ok()?
                .trim_end_matches('\0');
            return Some(s.to_string());
        }
        cursor = &cursor[2 + len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_parse_round_trips() {
        let key = "input/ssh-accept";
        let encoded = encode_nlink_comment(key).expect("encode");
        // TLV: type=0, length=22 (6 prefix + 16 key + 1 nul),
        //      payload=b"nlink:input/ssh-accept\0"
        assert_eq!(encoded[0], NFTNL_UDATA_RULE_COMMENT);
        assert_eq!(encoded[1] as usize, NLINK_PREFIX.len() + key.len() + 1);
        let decoded = parse_nlink_comment(&encoded).expect("decode");
        assert_eq!(decoded, key);
    }

    #[test]
    fn encode_rejects_overlong_key() {
        // Total payload (prefix + key + nul) must fit in 128 bytes.
        let too_long = "x".repeat(NFTNL_UDATA_COMMENT_MAXLEN);
        assert!(encode_nlink_comment(&too_long).is_none());
    }

    #[test]
    fn encode_accepts_max_size_key() {
        let max_key_len = NFTNL_UDATA_COMMENT_MAXLEN - NLINK_PREFIX.len() - 1;
        let max_key = "x".repeat(max_key_len);
        assert!(encode_nlink_comment(&max_key).is_some());
    }

    #[test]
    fn parse_ignores_foreign_comment_prefix() {
        // Comment without our prefix — foreign tool's tag.
        let body = b"cilium:abc123\0";
        let mut tlv = vec![NFTNL_UDATA_RULE_COMMENT, body.len() as u8];
        tlv.extend_from_slice(body);
        assert_eq!(parse_nlink_comment(&tlv), None);
    }

    #[test]
    fn parse_skips_unknown_tlv_types() {
        // Unknown TLV first, then our comment — should still find
        // the comment by walking past the unknown entry.
        let mut tlv = Vec::new();
        // Unknown type 99, 4 bytes of junk.
        tlv.extend_from_slice(&[99, 4, 0xde, 0xad, 0xbe, 0xef]);
        // Our comment.
        let body = b"nlink:my-key\0";
        tlv.extend_from_slice(&[NFTNL_UDATA_RULE_COMMENT, body.len() as u8]);
        tlv.extend_from_slice(body);

        assert_eq!(parse_nlink_comment(&tlv), Some("my-key".to_string()));
    }

    #[test]
    fn parse_handles_empty_userdata() {
        assert_eq!(parse_nlink_comment(&[]), None);
    }

    #[test]
    fn parse_handles_truncated_tlv() {
        // type=0, length=10 but only 2 bytes follow → truncated.
        let tlv = [NFTNL_UDATA_RULE_COMMENT, 10, 0x6e, 0x6c];
        assert_eq!(parse_nlink_comment(&tlv), None);
    }

    #[test]
    fn parse_handles_invalid_utf8() {
        // Type-0 TLV with non-UTF-8 bytes.
        let tlv = [NFTNL_UDATA_RULE_COMMENT, 2, 0xff, 0xfe];
        assert_eq!(parse_nlink_comment(&tlv), None);
    }
}

#[cfg(test)]
mod comment_tests {
    use super::*;

    fn tlv(comment: &str) -> Vec<u8> {
        let body = format!("{comment}\0");
        let mut tlv = vec![NFTNL_UDATA_RULE_COMMENT, body.len() as u8];
        tlv.extend_from_slice(body.as_bytes());
        tlv
    }

    #[test]
    fn a_foreign_comment_has_text_but_no_key() {
        let foreign = tlv("allow ssh from the office");
        assert_eq!(parse_nlink_comment(&foreign), None);
        assert_eq!(
            parse_comment(&foreign).as_deref(),
            Some("allow ssh from the office")
        );
    }

    #[test]
    fn an_nlink_comment_has_both() {
        let ours = encode_nlink_comment("k").unwrap();
        assert_eq!(parse_nlink_comment(&ours).as_deref(), Some("k"));
        assert_eq!(parse_comment(&ours).as_deref(), Some("nlink:k"));
    }
}

//! MACsec (IEEE 802.1AE) kernel constants.
//!
//! This module provides constants for MACsec Generic Netlink operations.

/// MACsec GENL commands (MACSEC_CMD_*).
pub mod macsec_cmd {
    /// Get TX SC information.
    pub const GET_TXSC: u8 = 0;
    /// Add an RX SC.
    pub const ADD_RXSC: u8 = 1;
    /// Delete an RX SC.
    pub const DEL_RXSC: u8 = 2;
    /// Update an RX SC.
    pub const UPD_RXSC: u8 = 3;
    /// Add a TX SA.
    pub const ADD_TXSA: u8 = 4;
    /// Delete a TX SA.
    pub const DEL_TXSA: u8 = 5;
    /// Add an RX SA.
    pub const ADD_RXSA: u8 = 6;
    /// Delete an RX SA.
    pub const DEL_RXSA: u8 = 7;
    /// Get RX SC information.
    pub const GET_RXSC: u8 = 8;
    /// Get TX SA information.
    pub const GET_TXSA: u8 = 9;
    /// Get RX SA information.
    pub const GET_RXSA: u8 = 10;
    /// Update a TX SA.
    pub const UPD_TXSA: u8 = 11;
    /// Update an RX SA.
    pub const UPD_RXSA: u8 = 12;
    /// Update offload configuration.
    pub const UPD_OFFLOAD: u8 = 13;
}

/// MACsec GENL top-level attributes (MACSEC_ATTR_*).
pub mod macsec_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Interface index.
    pub const IFINDEX: u16 = 1;
    /// RX SC configuration (nested).
    pub const RXSC_CONFIG: u16 = 2;
    /// RX SC statistics (nested).
    pub const RXSC_STATS: u16 = 3;
    /// SA configuration (nested).
    pub const SA_CONFIG: u16 = 4;
    /// SA statistics (nested).
    pub const SA_STATS: u16 = 5;
    /// SecY configuration (nested).
    pub const SECY_CONFIG: u16 = 6;
    /// SecY statistics (nested).
    pub const SECY_STATS: u16 = 7;
    /// TX SC statistics (nested).
    pub const TXSC_STATS: u16 = 8;
    /// RX SC list (nested).
    pub const RXSC_LIST: u16 = 9;
    /// TX SA list (nested).
    pub const TXSA_LIST: u16 = 10;
    /// Offload configuration (nested).
    pub const OFFLOAD: u16 = 11;
}

/// RX SC configuration attributes (MACSEC_RXSC_ATTR_*).
pub mod macsec_rxsc_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Secure Channel Identifier (u64).
    pub const SCI: u16 = 1;
    /// Active flag (u8).
    pub const ACTIVE: u16 = 2;
    /// RX SA list (nested).
    pub const SA_LIST: u16 = 3;
}

/// SA configuration attributes (MACSEC_SA_ATTR_*).
pub mod macsec_sa_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Association Number (u8, 0-3).
    pub const AN: u16 = 1;
    /// Active flag (u8).
    pub const ACTIVE: u16 = 2;
    /// Packet Number (u32 or u64 for XPN).
    pub const PN: u16 = 3;
    /// Key (16 or 32 bytes).
    pub const KEY: u16 = 4;
    /// Key ID (128 bits).
    pub const KEYID: u16 = 5;
}

/// SecY configuration attributes (MACSEC_SECY_ATTR_*).
pub mod macsec_secy_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Secure Channel Identifier (u64).
    pub const SCI: u16 = 1;
    /// Encoding SA (u8).
    pub const ENCODING_SA: u16 = 2;
    /// Window size for replay protection (u32).
    pub const WINDOW: u16 = 3;
    /// Cipher suite (u64).
    pub const CIPHER_SUITE: u16 = 4;
    /// ICV length (u8).
    pub const ICV_LEN: u16 = 5;
    /// Encryption enabled (u8).
    pub const ENCRYPT: u16 = 6;
    /// Protect frames (u8).
    pub const PROTECT: u16 = 7;
    /// Replay protection enabled (u8).
    pub const REPLAY: u16 = 8;
    /// Validation mode (u8).
    pub const VALIDATE: u16 = 9;
    /// Padding (unused).
    pub const PAD: u16 = 10;
    /// Include SCI in frames (u8).
    pub const INC_SCI: u16 = 11;
    /// End station (u8).
    pub const ES: u16 = 12;
    /// Single Copy Broadcast (u8).
    pub const SCB: u16 = 13;
}

/// SecY statistics attributes (MACSEC_SECY_STATS_ATTR_*).
pub mod macsec_secy_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Outgoing untagged packets (u64).
    pub const OUT_PKTS_UNTAGGED: u16 = 1;
    /// Outgoing too long packets (u64).
    pub const OUT_PKTS_TOO_LONG: u16 = 2;
    /// Incoming untagged packets (u64).
    pub const IN_PKTS_UNTAGGED: u16 = 3;
    /// Incoming no tag packets (u64).
    pub const IN_PKTS_NO_TAG: u16 = 4;
    /// Incoming bad tag packets (u64).
    pub const IN_PKTS_BAD_TAG: u16 = 5;
    /// Incoming unknown SCI packets (u64).
    pub const IN_PKTS_UNKNOWN_SCI: u16 = 6;
    /// Incoming no SCI packets (u64).
    pub const IN_PKTS_NO_SCI: u16 = 7;
    /// Incoming overrun packets (u64).
    pub const IN_PKTS_OVERRUN: u16 = 8;
}

/// TX SC statistics attributes (MACSEC_TXSC_STATS_ATTR_*).
pub mod macsec_txsc_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Protected packets (u64).
    pub const OUT_PKTS_PROTECTED: u16 = 1;
    /// Encrypted packets (u64).
    pub const OUT_PKTS_ENCRYPTED: u16 = 2;
    /// Protected octets (u64).
    pub const OUT_OCTETS_PROTECTED: u16 = 3;
    /// Encrypted octets (u64).
    pub const OUT_OCTETS_ENCRYPTED: u16 = 4;
}

/// RX SC statistics attributes (MACSEC_RXSC_STATS_ATTR_*).
pub mod macsec_rxsc_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// OK packets (u64).
    pub const IN_PKTS_OK: u16 = 1;
    /// Unchecked packets (u64).
    pub const IN_PKTS_UNCHECKED: u16 = 2;
    /// Delayed packets (u64).
    pub const IN_PKTS_DELAYED: u16 = 3;
    /// Late packets (u64).
    pub const IN_PKTS_LATE: u16 = 4;
    /// Invalid packets (u64).
    pub const IN_PKTS_INVALID: u16 = 5;
    /// Not valid packets (u64).
    pub const IN_PKTS_NOT_VALID: u16 = 6;
    /// Validated octets (u64).
    pub const IN_OCTETS_VALIDATED: u16 = 7;
    /// Decrypted octets (u64).
    pub const IN_OCTETS_DECRYPTED: u16 = 8;
}

/// TX SA statistics attributes (MACSEC_SA_STATS_ATTR_*).
pub mod macsec_sa_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Protected packets (u64).
    pub const OUT_PKTS_PROTECTED: u16 = 1;
    /// Encrypted packets (u64).
    pub const OUT_PKTS_ENCRYPTED: u16 = 2;
}

/// Offload attributes (MACSEC_OFFLOAD_ATTR_*).
pub mod macsec_offload_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Offload type (u8).
    pub const TYPE: u16 = 1;
}

/// Offload types (MACSEC_OFFLOAD_*).
pub mod macsec_offload {
    /// No offload.
    pub const OFF: u8 = 0;
    /// PHY offload.
    pub const PHY: u8 = 1;
    /// MAC offload.
    pub const MAC: u8 = 2;
}

/// Validation modes (MACSEC_VALIDATE_*).
pub mod macsec_validate {
    /// Disabled.
    pub const DISABLED: u8 = 0;
    /// Check (accept invalid frames).
    pub const CHECK: u8 = 1;
    /// Strict (drop invalid frames).
    pub const STRICT: u8 = 2;
}

/// MACsec cipher suite IDs.
pub mod macsec_cipher {
    /// GCM-AES-128 (default).
    pub const GCM_AES_128: u64 = 0x0080_0200_0100_0001;
    /// GCM-AES-256.
    pub const GCM_AES_256: u64 = 0x0080_C200_0100_0001;
    /// GCM-AES-XPN-128 (extended packet numbering).
    pub const GCM_AES_XPN_128: u64 = 0x0080_C200_0100_0002;
    /// GCM-AES-XPN-256 (extended packet numbering).
    pub const GCM_AES_XPN_256: u64 = 0x0080_C200_0100_0003;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_values() {
        // Verify cipher suite IDs match kernel values
        assert_eq!(macsec_cipher::GCM_AES_128, 0x0080_0200_0100_0001);
        assert_eq!(macsec_cipher::GCM_AES_256, 0x0080_C200_0100_0001);
    }

    #[test]
    fn test_validate_values() {
        assert_eq!(macsec_validate::DISABLED, 0);
        assert_eq!(macsec_validate::CHECK, 1);
        assert_eq!(macsec_validate::STRICT, 2);
    }
}

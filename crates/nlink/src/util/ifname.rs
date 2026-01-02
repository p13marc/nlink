//! Interface name and index utilities.

/// Maximum interface name length (including null terminator).
pub const IFNAMSIZ: usize = 16;

/// Error type for interface operations.
#[derive(Debug, thiserror::Error)]
pub enum IfError {
    #[error("interface not found: {0}")]
    NotFound(String),

    #[error("invalid interface name: {0}")]
    InvalidName(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IfError>;

/// Validate an interface name.
pub fn validate(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(IfError::InvalidName("empty name".to_string()));
    }

    if name.len() >= IFNAMSIZ {
        return Err(IfError::InvalidName(format!(
            "name too long (max {} chars)",
            IFNAMSIZ - 1
        )));
    }

    if name.contains('/') || name.contains('\0') {
        return Err(IfError::InvalidName(
            "name contains invalid characters".to_string(),
        ));
    }

    // Check for whitespace
    if name.chars().any(|c| c.is_whitespace()) {
        return Err(IfError::InvalidName("name contains whitespace".to_string()));
    }

    Ok(())
}

/// Convert an interface index to name.
pub fn index_to_name(index: u32) -> Result<String> {
    if index == 0 {
        return Err(IfError::NotFound("index 0".to_string()));
    }

    // Read from /sys/class/net
    let entries = std::fs::read_dir("/sys/class/net")?;

    for entry in entries.flatten() {
        let path = entry.path().join("ifindex");
        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(idx) = content.trim().parse::<u32>()
            && idx == index
        {
            return Ok(entry.file_name().to_string_lossy().to_string());
        }
    }

    Err(IfError::NotFound(format!("index {}", index)))
}

/// Convert an interface name to index.
pub fn name_to_index(name: &str) -> Result<u32> {
    validate(name)?;

    let path = format!("/sys/class/net/{}/ifindex", name);
    let content =
        std::fs::read_to_string(&path).map_err(|_| IfError::NotFound(name.to_string()))?;

    content
        .trim()
        .parse()
        .map_err(|_| IfError::NotFound(name.to_string()))
}

/// Get all interface names.
pub fn list_interfaces() -> Result<Vec<String>> {
    let entries = std::fs::read_dir("/sys/class/net")?;

    let mut names = Vec::new();
    for entry in entries.flatten() {
        names.push(entry.file_name().to_string_lossy().to_string());
    }

    names.sort();
    Ok(names)
}

/// Parse an interface name or index.
/// If the string is numeric, treat it as an index and resolve to name.
/// Otherwise, treat it as a name.
pub fn resolve(s: &str) -> Result<(String, u32)> {
    if let Ok(index) = s.parse::<u32>() {
        let name = index_to_name(index)?;
        Ok((name, index))
    } else {
        let index = name_to_index(s)?;
        Ok((s.to_string(), index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate() {
        assert!(validate("eth0").is_ok());
        assert!(validate("lo").is_ok());
        assert!(validate("veth123").is_ok());

        assert!(validate("").is_err());
        assert!(validate("this_name_is_way_too_long_for_an_interface").is_err());
        assert!(validate("eth/0").is_err());
        assert!(validate("eth 0").is_err());
    }

    #[test]
    fn test_list_interfaces() {
        // This should at least find "lo"
        let interfaces = list_interfaces().unwrap();
        assert!(interfaces.contains(&"lo".to_string()));
    }
}

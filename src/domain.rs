use std::fs;
use std::path::Path;
use std::time::Duration;

use log::warn;

use crate::config::parse_interval;
use crate::types::AppError;

/// A domain entry with optional per-domain recipient and interval overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainEntry {
    pub domain: String,
    pub recipient: Option<String>,
    pub interval: Option<Duration>,
}

/// Returns true if the domain name is syntactically valid.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Parse a single line from the domains file.
/// Format: `domain[,recipient][,interval]`
/// Fields are comma-separated. Empty fields use global defaults.
fn parse_domain_line(line: &str) -> Option<DomainEntry> {
    let parts: Vec<&str> = line.splitn(3, ',').map(|s| s.trim()).collect();

    let domain = parts[0];
    if !is_valid_domain(domain) {
        return None;
    }

    let recipient = parts.get(1)
        .and_then(|r| if r.is_empty() { None } else { Some(r.to_string()) });

    let interval = parts.get(2)
        .and_then(|i| if i.is_empty() { None } else { parse_interval(i).ok() });

    Some(DomainEntry {
        domain: domain.to_string(),
        recipient,
        interval,
    })
}

/// Reads domain file, skips empty lines and comments (lines starting with #).
/// Format: `domain[,recipient][,interval]`
/// Returns valid domain entries, logs warnings for invalid ones.
pub fn load_domains(path: &Path) -> Result<Vec<DomainEntry>, AppError> {
    let content = fs::read_to_string(path).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read domain file '{}': {}", path.display(), e),
        ))
    })?;

    let mut entries = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match parse_domain_line(trimmed) {
            Some(entry) => entries.push(entry),
            None => {
                warn!(
                    "Invalid domain at line {} in '{}', skipping: {}",
                    line_num + 1,
                    path.display(),
                    trimmed
                );
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_valid_domains() {
        let f = write_temp_file("example.com\nshop.example.com\n");
        let entries = load_domains(f.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[0].recipient, None);
        assert_eq!(entries[0].interval, None);
    }

    #[test]
    fn test_load_with_recipient_and_interval() {
        let f = write_temp_file("example.com,ops@example.com,30m\n");
        let entries = load_domains(f.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[0].recipient, Some("ops@example.com".to_string()));
        assert_eq!(entries[0].interval, Some(Duration::from_secs(30 * 60)));
    }

    #[test]
    fn test_load_with_recipient_only() {
        let f = write_temp_file("example.com,ops@example.com\n");
        let entries = load_domains(f.path()).unwrap();
        assert_eq!(entries[0].recipient, Some("ops@example.com".to_string()));
        assert_eq!(entries[0].interval, None);
    }

    #[test]
    fn test_load_with_empty_fields() {
        let f = write_temp_file("example.com,,3h\n");
        let entries = load_domains(f.path()).unwrap();
        assert_eq!(entries[0].recipient, None);
        assert_eq!(entries[0].interval, Some(Duration::from_secs(3 * 60 * 60)));
    }

    #[test]
    fn test_skips_comments_and_empty_lines() {
        let f = write_temp_file("# comment\n\nexample.com\n  \n# another comment\ntest.org\n");
        let entries = load_domains(f.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[1].domain, "test.org");
    }

    #[test]
    fn test_only_comments_and_empty_lines_returns_empty() {
        let f = write_temp_file("# comment\n\n  \n# another\n");
        let entries = load_domains(f.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_skips_invalid_domains() {
        let f = write_temp_file("example.com\nnot_valid!\nsingle\nok.org\n");
        let entries = load_domains(f.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[1].domain, "ok.org");
    }

    #[test]
    fn test_file_not_found_returns_error() {
        let result = load_domains(Path::new("/nonexistent/domains.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_domain_basic() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("a-b.example.com"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("single"));
        assert!(!is_valid_domain("-bad.com"));
        assert!(!is_valid_domain("bad-.com"));
        assert!(!is_valid_domain("bad..com"));
        assert!(!is_valid_domain("sp ace.com"));
    }
}

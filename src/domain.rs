use std::fs;
use std::path::Path;

use log::warn;

use crate::types::AppError;

/// Returns true if the domain name is syntactically valid.
/// A valid domain has at least two labels separated by dots,
/// each label is 1-63 chars of alphanumeric or hyphens (not starting/ending with hyphen),
/// and the total length is at most 253 characters.
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

/// Reads domain file, skips empty lines and comments (lines starting with #).
/// Returns valid domain names, logs warnings for invalid ones.
pub fn load_domains(path: &Path) -> Result<Vec<String>, AppError> {
    let content = fs::read_to_string(path).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read domain file '{}': {}", path.display(), e),
        ))
    })?;

    let mut domains = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if is_valid_domain(trimmed) {
            domains.push(trimmed.to_string());
        } else {
            warn!(
                "Invalid domain '{}' at line {} in '{}', skipping",
                trimmed,
                line_num + 1,
                path.display()
            );
        }
    }

    Ok(domains)
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
        let domains = load_domains(f.path()).unwrap();
        assert_eq!(domains, vec!["example.com", "shop.example.com"]);
    }

    #[test]
    fn test_skips_comments_and_empty_lines() {
        let f = write_temp_file("# comment\n\nexample.com\n  \n# another comment\ntest.org\n");
        let domains = load_domains(f.path()).unwrap();
        assert_eq!(domains, vec!["example.com", "test.org"]);
    }

    #[test]
    fn test_only_comments_and_empty_lines_returns_empty() {
        let f = write_temp_file("# comment\n\n  \n# another\n");
        let domains = load_domains(f.path()).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_skips_invalid_domains() {
        let f = write_temp_file("example.com\nnot_valid!\nsingle\nok.org\n");
        let domains = load_domains(f.path()).unwrap();
        assert_eq!(domains, vec!["example.com", "ok.org"]);
    }

    #[test]
    fn test_file_not_found_returns_error() {
        let result = load_domains(Path::new("/nonexistent/domains.txt"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("domain file"), "Error should mention domain file: {msg}");
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

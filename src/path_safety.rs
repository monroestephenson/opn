use anyhow::{bail, Result};
use std::path::{Component, Path};

const MAX_USER_PATH_LEN: usize = 4096;

pub fn validate_user_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        bail!("path must not be empty");
    }
    if path.len() > MAX_USER_PATH_LEN {
        bail!("path is too long");
    }
    if path
        .chars()
        .any(|c| c == '\0' || c == '\n' || c == '\r' || c == '\u{1b}')
    {
        bail!("path contains unsupported control characters");
    }

    // If canonicalization fails (nonexistent path, perms, etc.), forbid unresolved ".."
    // to avoid rendering or matching on traversal-style input directly.
    if std::fs::canonicalize(path).is_err()
        && Path::new(path)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        bail!("path traversal components ('..') are not allowed for unresolved paths");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_user_path;

    #[test]
    fn test_validate_user_path_accepts_normal_paths() {
        assert!(validate_user_path("/tmp/file.txt").is_ok());
        assert!(validate_user_path("./relative/file.txt").is_ok());
    }

    #[test]
    fn test_validate_user_path_rejects_empty_and_control_chars() {
        assert!(validate_user_path("").is_err());
        assert!(validate_user_path(" \t ").is_err());
        assert!(validate_user_path("bad\npath").is_err());
        assert!(validate_user_path("bad\rpath").is_err());
        assert!(validate_user_path("bad\u{1b}path").is_err());
    }

    #[test]
    fn test_validate_user_path_rejects_unresolved_parent_dir_components() {
        assert!(validate_user_path("../definitely-not-here/secret").is_err());
    }
}

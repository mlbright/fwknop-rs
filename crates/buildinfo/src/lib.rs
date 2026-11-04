//! Version and git metadata for the fwknop-rs binaries.
//!
//! Each binary passes its own package version; the git commit, commit time
//! and dirty flag are embedded by this crate's build script.

use std::fmt;

/// Version and source metadata for one binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Package version, e.g. `0.1.0`.
    pub version: String,
    /// Short (12 character) commit hash, if built from a git checkout.
    pub commit: Option<String>,
    /// Commit timestamp in RFC 3339 UTC, if known.
    pub time: Option<String>,
    /// Whether the work tree had uncommitted changes.
    pub dirty: bool,
}

impl Info {
    /// Build info for a binary whose package version is `version`
    /// (pass `env!("CARGO_PKG_VERSION")`).
    pub fn new(version: &str) -> Info {
        Info::from_parts(
            version,
            option_env!("FWKNOP_GIT_COMMIT"),
            option_env!("FWKNOP_GIT_TIME"),
            option_env!("FWKNOP_GIT_DIRTY") == Some("true"),
        )
    }

    fn from_parts(version: &str, commit: Option<&str>, time: Option<&str>, dirty: bool) -> Info {
        let commit = commit
            .filter(|c| !c.is_empty())
            .map(|c| c.chars().take(12).collect::<String>());
        Info {
            version: version.to_string(),
            time: commit.as_ref().and(time).map(str::to_string),
            dirty: commit.is_some() && dirty,
            commit,
        }
    }
}

/// Formats as `0.1.0`, `0.1.0 (commit: a1b2c3d4e5f6, built: 2026-04-10T18:30:00Z)`
/// or the same with `, dirty` before the closing parenthesis.
impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.version)?;
        let Some(commit) = &self.commit else {
            return Ok(());
        };
        write!(f, " (commit: {commit}")?;
        if let Some(time) = &self.time {
            write!(f, ", built: {time}")?;
        }
        if self.dirty {
            f.write_str(", dirty")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_only_without_commit() {
        let info = Info::from_parts("0.1.0", None, Some("2026-04-10T18:30:00Z"), true);
        assert_eq!(info.to_string(), "0.1.0");
    }

    #[test]
    fn full_string() {
        let info = Info::from_parts(
            "0.1.0",
            Some("a1b2c3d4e5f6"),
            Some("2026-04-10T18:30:00Z"),
            false,
        );
        assert_eq!(
            info.to_string(),
            "0.1.0 (commit: a1b2c3d4e5f6, built: 2026-04-10T18:30:00Z)"
        );
    }

    #[test]
    fn dirty_and_no_time() {
        let info = Info::from_parts("1.2.3", Some("a1b2c3d4e5f6"), None, true);
        assert_eq!(info.to_string(), "1.2.3 (commit: a1b2c3d4e5f6, dirty)");
    }

    #[test]
    fn commit_is_truncated_to_12_chars() {
        let info = Info::from_parts(
            "0.1.0",
            Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
            None,
            false,
        );
        assert_eq!(info.commit.as_deref(), Some("a1b2c3d4e5f6"));
    }

    #[test]
    fn short_commit_kept_as_is() {
        let info = Info::from_parts("0.1.0", Some("abc"), None, false);
        assert_eq!(info.commit.as_deref(), Some("abc"));
    }
}

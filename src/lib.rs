//! Root crate for the ACCI project
//!
//! This crate serves as the main entry point and re-exports the public interfaces
//! of all workspace crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(unreachable_pub)]

// Re-export core functionality
// pub use acci_core;

/// Version of the ACCI project
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the version of the ACCI project
#[must_use]
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}

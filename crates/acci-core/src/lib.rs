//! Core functionality for the ACCI system.
//!
//! This crate provides the core types and traits that are used throughout the ACCI system.
//! It defines the fundamental abstractions and interfaces that other crates build upon.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

/// Authentication and authorization related types and traits.
///
/// This module provides the core abstractions for authentication and authorization
/// in the ACCI system, including traits for authentication providers and user sessions.
pub mod auth;
pub mod error;
// pub mod models;
// pub mod traits;
// pub mod types;

/// Re-export of common types and traits
pub mod prelude {
    pub use crate::error::{Error, Result};
    // pub use crate::traits::*;
    // pub use crate::types::*;
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}

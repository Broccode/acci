//! Core functionality for the ACCI system
//!
//! This crate provides the core types, traits, and utilities used across the ACCI system.
//! It includes authentication, error handling, and other fundamental components.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

/// Authentication and authorization related types and traits.
///
/// This module provides the core abstractions for authentication and authorization
/// in the ACCI system, including traits for authentication providers and user sessions.
pub mod auth;
pub mod error;
/// Core models used throughout the application.
pub mod models;
// pub mod traits;
// pub mod types;

/// Re-export of common types and traits
pub mod prelude {
    pub use crate::error::{Error, Result};
    pub use crate::models::User;
    // pub use crate::traits::*;
    // pub use crate::types::*;
    pub use crate::clock::Clock;
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Clock functionality for time-based operations and testing.
pub mod clock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}

//! Authentication functionality for the ACCI system.
//!
//! This crate provides authentication and authorization functionality,
//! including user authentication, session management, and token validation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub use acci_core::auth::{AuthConfig, AuthProvider, AuthResponse, AuthSession, Credentials};

pub mod providers;
pub use providers::BasicAuthProvider;

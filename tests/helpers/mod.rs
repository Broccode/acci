//! Test helper functions and utilities.

use std::net::SocketAddr;

/// Creates a random local address for testing
pub fn random_local_address() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

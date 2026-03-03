//! ATI library — exposes core modules for integration tests and embedding.

pub mod core;
pub mod proxy;
pub mod security;

// These are used by the binary (main.rs) only, not exposed as library API.
// cli, output, providers remain private to the binary.

pub mod client;
pub use client::{ClientError, SettledClient};

// Re-export the verifier from settled-core so callers only need this crate.
pub use settled_core::hash::{leaf_hash, node_hash};
pub use settled_core::proof::{verify_consistency, verify_inclusion};
pub use settled_core::sth::{sign_tree_head, verify_tree_head};

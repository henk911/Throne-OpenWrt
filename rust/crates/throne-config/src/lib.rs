//! Offline config generation and transactional file staging.
//! No downloads, firewall edits, or service restarts happen in this crate.
pub mod config;
pub mod rule_sets;
pub mod transaction;

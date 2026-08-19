//! The TSP-0013 adapter between native TITH IPC and legacy tosser storage.
//!
//! This crate owns the placement, transaction, and ownership boundary around
//! the TSP-0003 byte mapping. It is the one component permitted to see both
//! sides: `tith-wire` for native items and `tith-message-legacy` for legacy
//! objects, neither of which may depend on the other.

#![forbid(unsafe_code)]

pub mod address;
pub mod config;
pub mod convert;
pub mod inbound;
pub mod policy;
pub mod publish;
pub mod srif;
pub mod tic;

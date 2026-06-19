#![forbid(unsafe_code)]
//! MIMIC — an escape-proof SSH honeypot emulating a Debian 12 server.
//!
//! The library crate hosts the layered architecture (network, SSH engine,
//! shell, VFS, commands). Phase 1 ships only the skeleton; modules are added
//! incrementally in later phases.

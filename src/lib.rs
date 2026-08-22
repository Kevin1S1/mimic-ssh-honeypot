#![forbid(unsafe_code)]
//! MIMIC — an escape-proof SSH honeypot emulating a Debian 12 server.
//!
//! Security invariant: emulation layers never touch the real OS. No
//! `std::process`, no `std::fs` against attacker-controlled paths. Every
//! "command" is a pure Rust function operating on in-memory state. The only
//! real I/O permitted is in the network layer (TCP, SSH, host-key persistence).

pub mod clock;
pub mod commands;
pub mod config;
pub mod logging;
pub mod network;
pub mod shell;
pub mod vfs;

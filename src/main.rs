#![forbid(unsafe_code)]
//! MIMIC honeypot binary entry point.
//!
//! Phase 1 is an intentionally empty skeleton: it exists so CI (clippy, tests,
//! dependency audit) is green from the very first commit. Subsequent phases wire
//! in configuration loading, the async runtime, and the network listener.

fn main() {}

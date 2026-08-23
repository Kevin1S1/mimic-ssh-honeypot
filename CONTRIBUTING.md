# Contributing to MIMIC

Thanks for looking. This file exists because two of the project's conventions
are load-bearing and were previously written down nowhere a reader could see
them: the module boundary, and the `// ponytail:` marker.

## The module boundary, and why it fails the build

MIMIC is a honeypot. Its safety claim *is* the product — the whole value
proposition is that an attacker gets a convincing Debian shell while no shell
process exists, no real path is opened, and no socket is dialled. That claim is
worth exactly as much as its weakest enforcement.

So it is not enforced by code review. `src/shell/`, `src/vfs/` and
`src/commands/` may never import `std::process`, real `std::fs`, or anything
that opens a socket. [`tests/escape_vectors.rs`](tests/escape_vectors.rs) scans
those directories for the forbidden APIs and **fails the build** if one appears.

That choice is the most interesting decision in the codebase, and the reasoning
is worth stating explicitly:

- **A review-time rule is a rule someone eventually merges past.** Reviewers get
  tired; a `std::fs::read` inside an otherwise reasonable 400-line diff is easy
  to miss. A failing test is not.
- **The invariant is architectural, not local.** No single call site looks
  dangerous. The property that matters — *nothing in the emulation layers can
  reach the host* — is only visible at the layer boundary, which is precisely
  where a compiler or a test can see it and a reviewer cannot.
- **It converts a promise into a fact.** `README.md` and `SECURITY.md` both use
  the phrase "physically impossible". A documented rule does not earn that
  phrase. A test that refuses to build the crate does.

The test matches literal substrings, which is why it also bans brace-grouped
`std::{…}` imports outright: `use std::{fs, process};` contains neither
`std::fs` nor `std::process` and would otherwise slip past every other entry.

**If a change genuinely needs real-OS access outside `src/network/`, stop and
open an issue rather than adding it.** That is an architecture decision, not a
code change. `src/network/` is the only layer permitted to do real I/O — binding
the listener, persisting host keys, and writing the quarantine store — and it is
deliberately small so it can be read in full.

## The `// ponytail:` marker

MIMIC emulates about a hundred commands. Emulating all of any of them is not the
goal; emulating enough of them that an attacker keeps going is. So the codebase
is full of deliberate shortcuts, and an undocumented shortcut is
indistinguishable from a bug.

A `// ponytail:` comment marks a shortcut that is **known, bounded, and
deliberate**. It states two things:

```rust
// ponytail: <what the ceiling actually is>, upgrade when <the trigger>
```

For example:

```rust
// ponytail: `tar -z/-j/-J` are accepted and ignored, which is unobservable
// here because the box has no `file` or `gzip` to check the result with.
// Upgrade if a compression-aware command is ever added.
```

Two rules keep the convention honest:

1. **The stated ceiling must match what the code actually does.** A marker that
   understates its own limitation is worse than no marker, because it stops the
   next reader from looking.
2. **It is for realism ceilings, not safety ones.** Security bounds are not
   shortcuts — they are listed in
   [SECURITY.md](SECURITY.md#every-attacker-driven-bound-in-one-place) and get
   built in full regardless of how much code that takes. If you find yourself
   writing `// ponytail:` above something that bounds attacker-controlled
   memory, you are marking a bug.

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

All three are gates in CI. `cargo test` includes `escape_vectors`, so run it on
any change under `src/shell/`, `src/vfs/` or `src/commands/`.

Also:

- **Update the docs in the same PR as the code**, not after — `README.md` for
  behaviour, config, commands or setup; `SECURITY.md` for an invariant,
  mitigation or bound; `deploy/mimic.toml` for any config key, since it is the
  reference example.
- **Add a `CHANGELOG.md` entry under `## [Unreleased]`** in the same PR. Use
  only the Keep a Changelog categories (`Added`, `Changed`, `Fixed`, `Security`,
  `Removed`, `Deprecated`). Security-relevant fixes go under `Security` even
  when they would also fit `Fixed` — that is what makes the changelog useful to
  someone auditing which version fixed what.
- **Write commit messages that say *why*.** What changed is in the diff.

## Reporting a security issue

Please do not open a public issue. See
[SECURITY.md](SECURITY.md#reporting-a-vulnerability) for the disclosure process.

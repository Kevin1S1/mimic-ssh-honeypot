# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────
# Uses the official Rust image on Debian Bookworm to match the target OS.
# Dependency caching: Cargo.toml + Cargo.lock are copied first so that
# changing source code does not invalidate the (slow) dependency download.
FROM rust:1.88-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo fetch --locked

COPY src ./src
RUN cargo build --release --locked --bin mimic \
    && strip target/release/mimic

# ── Runtime stage ────────────────────────────────────────────────────
# distroless/cc-debian12:nonroot — ~20 MB, no shell, no package manager.
# The image ships with a nonroot user (uid 65534) so the binary never
# runs as root inside the container.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/mimic /usr/local/bin/mimic

WORKDIR /data
VOLUME ["/data"]
EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/mimic"]

# ULPF container image.
#
# Two stages: a build stage with the Rust toolchain, and a distroless runtime
# carrying nothing but the binary and the Source Packs. Requirement (k).
#
# The build uses --locked so the image is reproducible from Cargo.lock and
# cannot silently pick up a different dependency tree than the one CI tested.
# That matters more here than usual: the whole air-gap argument rests on
# knowing exactly what is in the binary.

FROM rust:1.85-bookworm AS builder
WORKDIR /app

# Copy the manifests first so a source-only change does not re-resolve and
# re-download every crate.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY packs ./packs

RUN cargo build --release --locked --bin ulpf

FROM gcr.io/distroless/cc-debian12
WORKDIR /app

COPY --from=builder /app/target/release/ulpf /app/ulpf
COPY --from=builder /app/packs /app/packs

# 8787 operator console, 5514/udp syslog receiver. Both have to be published
# for the container to be useful; the syslog port was previously undeclared,
# so the receiver was unreachable from outside the container.
EXPOSE 8787/tcp
EXPOSE 5514/udp

# Distroless runs as a non-root user by default. The vault, integrity and any
# sink directories must therefore be writable volumes owned by that user —
# see deploy/ulpf-compose.yaml.
ENTRYPOINT ["/app/ulpf"]
CMD ["serve", "--packs", "/app/packs", "--vault", "/app/data/vault", "--integrity-dir", "/app/data/integrity", "--host", "0.0.0.0", "--port", "8787", "--syslog-bind", "0.0.0.0:5514"]

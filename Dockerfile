# Build stage
FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Distroless runtime stage
FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /app/target/release/ulpf /app/ulpf
COPY --from=builder /app/packs /app/packs

ENTRYPOINT ["/app/ulpf"]
CMD ["serve"]

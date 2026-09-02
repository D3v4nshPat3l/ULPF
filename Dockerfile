FROM rust:1.85-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY packs ./packs
RUN cargo build --locked --release --bin ulpf

FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 ulpf
WORKDIR /app
COPY --from=builder /src/target/release/ulpf /usr/local/bin/ulpf
COPY packs /app/packs
RUN mkdir -p /app/data && chown -R ulpf:ulpf /app
USER ulpf
EXPOSE 8787 5514/udp
VOLUME ["/app/data"]
ENTRYPOINT ["ulpf"]
CMD ["serve", "--packs", "/app/packs", "--vault", "/app/data/vault", "--integrity-dir", "/app/data/integrity", "--host", "0.0.0.0", "--port", "8787"]

# Etap 1: Budowanie (Builder)
FROM rust:latest as builder
WORKDIR /app
COPY . .
# Budujemy wersję release (zoptymalizowaną)
RUN cargo build --release

# Etap 2: Uruchamianie (Runner) - lekki obraz Debian
FROM debian:bookworm-slim
WORKDIR /app

# Tworzymy folder data, żeby mieć pewność, że istnieje
RUN mkdir -p /app/data

# Kopiujemy skompilowany plik z etapu Buildera
COPY --from=builder /app/target/release/smb_server /app/server

# Uruchamiamy serwer
CMD ["/app/server"]
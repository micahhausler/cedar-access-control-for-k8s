# Use the official Rust image as a builder
FROM rust:1.83-slim as builder

# Create a new empty shell project
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./

# Create a dummy source file (required for cargo fetch)
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo fetch && \
    cargo build --release && \
    rm -rf src/

# Copy the real source code
COPY src/ src/

# Build the application
RUN cargo build --release

# Create a new stage with a minimal image
FROM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-glibc:latest-al23

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/cedar-k8s-webhook /usr/local/bin/cedar-k8s-webhook

ENV RUST_BACKTRACE=1
ENV RUST_LOG=info

ENV TLS_CERT_PATH=/var/run/cedar-authorizer/certs/cedar-authorizer-server.crt
ENV TLS_KEY_PATH=/var/run/cedar-authorizer/certs/cedar-authorizer-server.key

# Set the startup command
CMD ["/usr/local/bin/cedar-k8s-webhook"]

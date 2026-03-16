FROM lukemathwalker/cargo-chef:latest-rust-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev gcc

FROM chef AS planner
COPY . .
# Create a recipe file that stays the same unless dependencies change
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# Now copy source and build the real app
COPY . .
RUN cargo build --release --bin ssandbox

# Final runtime stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/ssandbox .
CMD ["./ssandbox"]
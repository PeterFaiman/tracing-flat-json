check: fmt
    cargo clippy --all-targets --no-default-features -- --no-deps
    cargo clippy --all-targets --no-default-features -F tracing-log -- --no-deps
    cargo clippy --all-targets --no-default-features -F tracing-opentelemetry -- --no-deps
    cargo clippy --all-targets --no-default-features -F tracing-log -F tracing-opentelemetry -- --no-deps
    cargo clippy --all-targets --all-features -- --no-deps

fmt:
    cargo +nightly fmt -- --config-path rustfmt-nightly.toml

test:
    cargo test --no-default-features
    cargo test --no-default-features -F tracing-log
    cargo test --no-default-features -F tracing-opentelemetry
    cargo test --no-default-features -F tracing-log -F tracing-opentelemetry
    cargo test --all-features

bench:
    cargo bench --bench other-crates tracing-flat-json -- --measurement-time 300

demo *ARGS:
    RUSTFLAGS="--remap-path-prefix ${CARGO_HOME:-$HOME/.cargo}/registry/src/index.crates.io-1949cf8c6b5b557f/=" cargo run --example demo {{ARGS}}

demo-otel: (demo "-F tracing-opentelemetry")

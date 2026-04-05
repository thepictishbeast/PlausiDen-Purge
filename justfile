default: check-all
check-all: fmt clippy test
build:
    cargo build
test:
    cargo test
fmt:
    cargo fmt --all -- --check
clippy:
    cargo clippy -- -D warnings

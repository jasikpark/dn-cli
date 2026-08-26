# Run the CLI from source. Auth comes from `dn auth login` or DEFINED_API_KEY.
# Usage:  just run hosts list [--json]
run *args:
    cargo run -- {{args}}

# Build the release binary.
build:
    cargo build --release

# Run the release binary.
run-release *args: build
    ./target/release/dn {{args}}

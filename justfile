# Run the CLI with secrets injected from 1Password.
# `.env` maps DEFINED_API_KEY to an op:// secret reference (see .env.example).
# Usage:  just run hosts list [--json]
run *args:
    op run --env-file=.env -- cargo run -- {{args}}

# Build the release binary.
build:
    cargo build --release

# Run a release binary build with secrets injected.
run-release *args: build
    op run --env-file=.env -- ./target/release/dn {{args}}

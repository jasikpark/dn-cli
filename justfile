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

# Mutation-test the whole crate. A MISSED mutant is a behaviour change no test notices.
mutants *args:
    cargo mutants -j 4 {{args}}

# Mutation-test only the lines this change (main..@) touches.
mutants-diff *args:
    mkdir -p target
    jj diff --git -r 'main..@' > target/mutants.diff
    cargo mutants -j 4 --in-diff target/mutants.diff {{args}}

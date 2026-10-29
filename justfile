# Run the CLI from source. Auth comes from `dn auth login` or DEFINED_API_KEY.
# Usage:  just run host list [--json]
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

# Print n fresh, API-shaped mock ids for hand-written fixtures: just mock-id host 3
mock-id kind n='1':
    python3 -c 'import os, base64, sys; kind, n = sys.argv[1], int(sys.argv[2]); [print(kind + "-" + base64.b32encode(os.urandom(16)).decode().rstrip(chr(61))) for _ in range(n)]' {{kind}} {{n}}

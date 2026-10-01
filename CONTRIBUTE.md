# Contributing

`dn-cli` is an unofficial CLI for the Defined Networking API. Thanks for helping
improve it. See the [README](./README.md) for installation, authentication, and
user-facing commands.

## Develop

Use a Rust toolchain compatible with `Cargo.toml` (`rust-version = "1.89"`).
The CLI uses [clap](https://docs.rs/clap) and [ureq](https://docs.rs/ureq), with
rustls for TLS.

With [`just`](https://github.com/casey/just):

```bash
just run host list --json
```

Or directly:

```bash
cargo run -- host list --json
cargo build --release
```

To run the same checks as CI before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

`just mutants` runs [cargo-mutants](https://mutants.rs/) over the crate: it edits
one expression at a time and reruns `cargo test`. A MISSED mutant is an edit the
suite did not notice, so it names a behaviour nothing asserts on.
`just mutants-diff` narrows that to the lines the current change touches.
The `cargo-mutants` skill in `.claude/skills/` loads when Claude Code runs in this
checkout and walks through a run and the survivor triage.

## Testing against another API server

Every profile talks to `https://api.defined.net` unless it was saved with
`--api-url`. That, and `DEFINED_API_URL` (which overrides any profile's URL for
one call), exist for testing — against a local mock API, or a non-production
server:

```bash
DEFINED_API_URL=http://127.0.0.1:8080 DEFINED_API_KEY=test dn host list   # a local mock
dn auth login --profile test --api-url https://api.test.example --keep-default
```

Plain `http://` is only allowed to this machine (`localhost`, `127.0.0.1`,
`[::1]`), so the key never crosses a network unencrypted. When a call isn't
going to `https://api.defined.net`, `dn` says so on stderr (never under
`--json`).

## Changelog and releases

`CHANGELOG.md` is generated from commit subjects, so every user-visible change
needs a [conventional commit](https://www.conventionalcommits.org/): `feat:`
and `fix:` become entries under the next version, `feat!:` (or a
`BREAKING CHANGE:` footer) marks a breaking change, and other types (`docs:`,
`chore:`, `test:`) stay out of the changelog. Write the subject as the line a
user should read in the release notes. The `Require changes to be documented`
check on each PR is [Knope](https://knope.tech) looking for exactly that.

On every push to `main`, Knope opens or updates a `chore: prepare release X`
PR that bumps `Cargo.toml` and writes `CHANGELOG.md`. Merging it pushes the
`vX` tag, and cargo-dist builds the binaries and publishes the release.


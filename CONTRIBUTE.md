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

[Knope](https://knope.tech) builds `CHANGELOG.md` from two sources:
change files in `.changeset/` and
[conventional commit](https://www.conventionalcommits.org/) subjects. Squash
merges keep only the PR title, so the title is the commit Knope reads. The
`Require changes to be documented` check on each PR passes when it finds either
source.

Pick one source per PR, by what the change needs:

- Nothing users should read about (`chore:`, `ci:`, `docs:`, `test:`, ...): a
  conventional title and no change file. These types stay out of the changelog.
- A one-line feature or fix: a `feat:` or `fix:` title and no change file.
- Anything with more to say, or a breaking change: a change file and a plain
  title with no conventional type, such as "Show the organization and key in
  auth status". A `feat:` or `fix:` title alongside a change file writes the
  same change into the changelog twice.

A change file can give a release note a body, which a squash merge's title
can't, and its `default` sets the version bump: a breaking change uses
`default: major`, not a `feat!:` title. Add `.changeset/<short-name>.md`:

```markdown
---
default: minor
---

# The heading users read in the release notes

Optional body: what changed, and anything a user has to do about it.
```

`default` is the package; its value is `major` (Breaking Changes), `minor`
(Features), or `patch` (Fixes).

On every push to `main`, Knope opens or updates a `chore: prepare release X`
PR that bumps `Cargo.toml` and writes `CHANGELOG.md`. Merging it pushes the
`vX` tag, and cargo-dist builds the binaries and publishes the release.


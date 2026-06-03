# dn-cli

A CLI (`dn`) for the [Defined Networking](https://defined.net) API.

Rust + [clap](https://docs.rs/clap) + [ureq](https://docs.rs/ureq) (pure-Rust
TLS via rustls, so the binary statically links cleanly for per-platform npm
distribution later, à la `sentry-cli`).

Designed to be driven two ways:

- **Interactively** by a human (tables; confirmations on destructive actions)
- **Non-interactively** by an agent or script (`--json`, explicit flags, no prompts)

## Auth

`dn` reads `DEFINED_API_KEY` from the environment and never persists it. Inject
it per-invocation with 1Password so the secret lives only for the lifetime of a
single command. `op run` resolves a 1Password *secret reference* mapped to that
variable name — bare `op run -- dn ...` won't inject anything on its own. Map it
once with an env file:

```bash
cp .env.example .env          # set DEFINED_API_KEY to your op:// reference
op run --env-file=.env -- dn hosts list
```

`.env` is gitignored and holds only the reference (`op://vault/item/field`),
never the secret value. Override the base URL with `DEFINED_API_URL` (defaults
to `https://api.defined.net`).

## Develop

With [`just`](https://github.com/casey/just) (wraps `op run` + `cargo`):

```bash
just run hosts list --json
```

Or directly:

```bash
op run --env-file=.env -- cargo run -- hosts list --json
cargo build --release
```

## Status

Reads-only tracer: `hosts list`. Writes and deletes are a deliberate later
phase, gated behind confirmation prompts and host-level permission rules.

## License

[FSL-1.1-Apache-2.0](./LICENSE.md) — source-available; converts to Apache-2.0
two years after each release.

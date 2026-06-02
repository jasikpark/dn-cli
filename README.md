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
single command:

```bash
op run -- dn hosts list
```

Override the base URL with `DEFINED_API_URL` (defaults to `https://api.defined.net`).

## Develop

```bash
cargo run -- hosts list --json
cargo build --release
op run -- ./target/release/dn hosts list
```

## Status

Reads-only tracer: `hosts list`. Writes and deletes are a deliberate later
phase, gated behind confirmation prompts and host-level permission rules.

## License

[FSL-1.1-Apache-2.0](./LICENSE.md) — source-available; converts to Apache-2.0
two years after each release.

# dn-cli

A CLI (`dn`) for the [Defined Networking](https://defined.net) API.

Rust + [clap](https://docs.rs/clap) + [ureq](https://docs.rs/ureq) (pure-Rust
TLS via rustls, so the binary statically links cleanly for per-platform npm
distribution later, à la `sentry-cli`).

Designed to be driven two ways:

- **Interactively** by a human (tables; confirmations on destructive actions)
- **Non-interactively** by an agent or script (`--json`, explicit flags, no prompts)

## Auth

Store a 1Password *secret reference* to your API key once:

```bash
dn auth login
```

It walks you through creating a key at
<https://admin.defined.net/settings/api-keys/add> (pick only the permissions you
need), asks for the key's `op://vault/item/field` reference, verifies it against
the API, and saves the reference to `~/.config/dn/config.json`
(`%APPDATA%\dn\config.json` on Windows; override the directory with
`DN_CONFIG_DIR`). The key itself never touches disk: every `dn` call resolves
the reference with [`op read`](https://developer.1password.com/docs/cli/get-started/),
so 1Password's unlock prompt gates each invocation.

`dn auth status` shows which source is active; `dn auth logout` forgets the
reference. Pass `--ref op://...` to `auth login` when scripting it.

For CI or agents, `DEFINED_API_KEY` in the environment takes precedence over the
config file. It may hold the raw key or an `op://` reference — `dn` resolves the
latter the same way. Override the base URL with `DEFINED_API_URL` (defaults to
`https://api.defined.net`).

## Develop

With [`just`](https://github.com/casey/just):

```bash
just run hosts list --json
```

Or directly:

```bash
cargo run -- hosts list --json
cargo build --release
```

`just mutants` runs [cargo-mutants](https://mutants.rs/) over the crate: it edits
one expression at a time and reruns `cargo test`. A MISSED mutant is an edit the
suite did not notice, so it names a behaviour nothing asserts on.
`just mutants-diff` narrows that to the lines the current change touches.
The `cargo-mutants` skill in `.claude/skills/` loads when Claude Code runs in this
checkout and walks through a run and the survivor triage.

### Changelog and releases

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

## Claude Code plugin

This repo doubles as a [Claude Code](https://claude.com/claude-code) plugin
(`.claude-plugin/plugin.json`). The `defined-networking` skill
(`skills/defined-networking/SKILL.md`) teaches Claude to drive `dn` — checking
`dn auth status --json` first and parsing `--json` output. Load it by installing the
plugin, or symlink the skill into `~/.claude/skills/` for local use. The longer-
term goal: *"I have this device, set it up on my network"* — conversational
device enrollment.

## Status

- Reads: `hosts list`
- Auth: `auth login` / `auth status` / `auth logout` — stores a 1Password
  secret reference (never the key) in `~/.config/dn/config.json` and resolves
  it per call with `op read`.
- Writes: `hosts create` (host / lighthouse / relay) — wraps the
  `POST /v2/host-and-enrollment-code` one-shot endpoint, so the OTP comes
  back in the same response and the human view prints the `dnclient enroll`
  command to copy. Network is auto-picked when the account has exactly one.
  Hosts get an IPv4 whenever the network has an IPv4 prefix — the API alone
  leaves dual-stack hosts v6-only — and `--no-ipv4` skips that for a v6-only
  host. Key permissions: `hosts:create`, `hosts:enroll`, and `networks:list`
  (auto-pick) or `networks:read` (`--network <id>`).
- Deletes: `hosts delete <HOST_ID>` — wraps `DELETE /v1/hosts/{id}`. An
  interactive run looks the host up first (`hosts:read`) and asks
  `Delete host "<name>" (<id>; <ips>)? [y/N]`; `--yes` skips the lookup and the
  prompt, and is required with `--json` or when stdin isn't a terminal. Key
  permission: `hosts:delete`.
- Edits: `hosts edit <HOST_ID>` — `--name`, `--role <ROLE_ID>`, `--add-tag`,
  `--remove-tag` (repeatable). Reads the host, applies the changes, and PUTs
  the whole object back via `/v3/hosts/{id}`; a no-op edit skips the write.
  Key permissions: `hosts:read` and `hosts:update`.
- Roles: `roles list` — id, name, rule and host counts. Pair it with
  `hosts edit --role` to move a host off the default deny-all role.
- Coming next: `roles create` and `roles add-rule` — the default role denies
  all traffic, so newly enrolled hosts share a network but can't talk to
  each other until a permissive role exists and is assigned.

## License

[FSL-1.1-Apache-2.0](./LICENSE.md) — source-available; converts to Apache-2.0
two years after each release.

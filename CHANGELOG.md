# Changelog

All notable changes to this project are documented here.
## 0.1.2 (2026-08-26)

### Features

- dn auth login / status / logout backed by 1Password references

### Fixes

- harden login verify, config I/O, and status reporting
- accept the quoted reference 1Password copies for spaced item names
- reject unsupported name characters in a reference before calling op
- make config writes race-safe and surface op diagnostics under --json

## 0.1.1 (2026-06-04)

### Features

- dn-cli reads-only tracer
- surface Defined API error bodies on non-2xx
- emit structured JSON error envelope in --json mode
- follow cursor pagination on list, add unit tests
- switch list to v2 endpoint (dual-stack ipAddresses)
- make op run secret injection work + clearer setup
- aligned table output for human host list
- add Claude Code skill for the dn CLI
- scaffold cargo-dist for npm distribution
- add shell installer alongside npm
- add knope prepare-release PR flow

### Fixes

- read nextCursor as documented pagination field

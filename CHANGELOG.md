# Changelog

All notable changes to this project are documented here.
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

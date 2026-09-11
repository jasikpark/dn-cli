# AGENTS.md

Guidance for coding agents working in dn-cli.

## Code guidelines

- No trivial comments
- Minimal bloat (KISS, DRY, SRP)
- No unnecessary state (variables, fields, arguments)
- Each line of code should justify its existence
- Follow Rust idioms and best practices
- Latest Rust features can be used
- Descriptive variable and function names
- No wildcard imports
- Import types at top of file and use short names everywhere (e.g. `use std::sync::Arc;` then `Arc<T>`, never `std::sync::Arc<T>` inline)
- Keep consts at top of file, right after imports
- Explicit error handling with `Result<T, E>` over panics
- Use `anyhow` when the specific error is not as important
- Place unit tests in the same file using `#[cfg(test)]` modules
- Try solving with existing dependencies before adding new ones
- Prefer well-maintained crates from crates.io
- Provide helpful error messages
- Use snake_case for naming tests
- No need for bullshit tests (e.g. tautology)
- Make sure tests are not flaky (no weird sleeps)
- No inline magic numbers or strings
- In tests const error/status messages and assert against the shared constant
- Add #[derive(Copy)] only on structs with 1 primitive field

---

Adapted from [maki](https://github.com/tontinton/maki)'s `AGENTS.md`
(MIT, Copyright (c) 2026 Tony Solomonik).

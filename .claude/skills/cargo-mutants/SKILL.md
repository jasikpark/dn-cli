---
name: cargo-mutants
description: Mutation-test a Rust crate with cargo-mutants and triage the survivors into real test gaps vs equivalent or untestable mutants. Use after writing or changing tests for Rust code, when setting up cargo-mutants in a repo (config file, justfile recipe, PR-scoped CI job), and whenever the user asks "are these tests any good", "what am I not testing", "mutation testing", "test efficacy", or pastes cargo-mutants output (MISSED / caught / unviable / timeout lines, or a "N mutants tested" summary) to be interpreted. Reach for it when coverage is high but confidence is low; coverage says a line ran, mutation testing says a test would notice if the line were wrong.
---

# cargo-mutants — mutation testing for Rust

cargo-mutants copies the source tree, applies one change at a time (a *mutant*), rebuilds, and
runs the tests. A mutant nothing fails on is a behaviour change no test would notice. Its
signature move is replacing a whole function body with a constant of the return type, so the
headline question is "would any test notice if this function did nothing?" — a different and
blunter question than operator-swap tools ask. Verified against cargo-mutants 27.1.0.

## Install / check

```sh
command -v cargo-mutants || cargo binstall -y cargo-mutants || cargo install --locked cargo-mutants
```

No Homebrew formula. Book: https://mutants.rs · repo: https://github.com/sourcefrog/cargo-mutants

## Run

Run from the crate (or workspace) root. Scope with `-f` on a first run; a whole-crate run on a
large tree is slow and mostly reports code you did not touch.

```sh
cargo mutants -f src/parser.rs          # one file's mutants, run against the crate's tests
cargo mutants --list -f src/parser.rs   # inventory only; add --diff to see each change, --json for tooling
```

| flag | use it when |
|---|---|
| `-f GLOB` / `-e GLOB` | include / exclude source files (globs with a slash match the whole path) |
| `-F RE` / `-E RE` | include / exclude by mutant *name* — the full `--list` line, so `-E 'impl Debug'`, `-E 'src/cli.rs'`, `-F 'parse_'` all work |
| `-D git.diff` | only mutants on lines the diff touches — PR-scoped runs. A plain unified diff with `a/`/`b/` headers is enough; a diff that touches no `.rs` logs `Diff changes no Rust source files` and exits 0, so docs-only PRs pass a gated job |
| `--iterate` | you added tests and want to rerun only what was MISSED last time (reads `caught.txt`, `previously_caught.txt`, `unviable.txt`); finish with one plain run |
| `-j 2` | parallel jobs — start at 2 or 3; each job is a full copy with its own `target/` (2 GB+ is common) and rustc already parallelises builds, so 8 jobs is rarely faster than 3 |
| `-v` / `-V` | also print caught / unviable mutants (default prints only MISSED and timeouts) |
| `--timeout-multiplier 10` | timeouts are inflated — see triage step 1 (default is 5× the baseline test time, floor 20 s) |
| `-t SECS` / `--build-timeout SECS` | hard caps; `-t` bounds only the test phase, builds are separate, so `-t 1` does not force a TIMEOUT on a fast suite |
| `--cargo-arg=--locked` | pass a cargo flag; `--locked` is not a cargo-mutants flag and `cargo mutants --locked` is a usage error |
| `--minimum-test-timeout 60` | tiny suite, slow incremental link; or set `CARGO_MUTANTS_MINIMUM_TEST_TIMEOUT` |
| `--error '::anyhow::anyhow!("mutated")'` | functions returning `Result` should also be mutated to `Err(...)`; without it only the `Ok` mutant exists |
| `-- --all-targets` | skip doctests (slow, rarely catch anything) |
| `--test-tool nextest` | the crate already uses nextest |
| `--check` | only confirm mutants compile — a cheap first pass on a huge crate |
| `--shard 1/4` | split across CI machines |
| `-p CRATE` / `--workspace` | pick packages in a workspace; `--test-workspace true` runs every package's tests per mutant |
| `--in-place` | tests need the real tree path (disables timeout multipliers → 300 s fixed) |
| `--baseline skip` | tests are known green and you are in a hurry (same timeout caveat) |
| `--cap-lints true` | `RUSTFLAGS=-D warnings` or `#![deny(warnings)]` is turning unused-variable mutants unviable |
| `--emit-schema config` | you need the authoritative config-key list |

`--no-shuffle` is the default since 27.x; the book's `--no-shuffle -vV` CI line is just `-vV` now.

### Config file — `.cargo/mutants.toml`

Lists are *appended* to CLI values; scalars on the CLI win. `--config FILE` / `--no-config`
override the location. Editor schema: `https://json.schemastore.org/cargo-mutants-config.json`.

```toml
exclude_re = ["impl Debug", "impl Display for Error"]  # trait impls whose only test is a snapshot
error_values = ["::anyhow::anyhow!(\"mutated\")"]      # also mutate Result-returning fns to Err
skip_calls_defaults = true                             # skip `with_capacity` (capacity hints are never observable)
timeout_multiplier = 5.0
minimum_test_timeout = 20.0
additional_cargo_args = ["--locked"]                   # keep cargo from rewriting Cargo.lock in the copy; set it here OR on the CLI, never both
```

Lists append, so `additional_cargo_args = ["--locked"]` plus `--cargo-arg=--locked` hands cargo
`--locked --locked`, which clap rejects — the whole run fails, not just one mutant.

Other keys: `examine_globs`, `exclude_globs`, `examine_re`, `skip_calls`, `additional_cargo_test_args`,
`test_tool`, `test_package`, `test_workspace`, `features`, `all_features`, `no_default_features`,
`profile`, `cap_lints`, `build_timeout_multiplier`, `copy_target`, `copy_vcs`, `gitignore`, `output`,
`sharding`. The tree copy honours `.gitignore` even when there is no `.git` (a non-colocated jj
workspace), so `target/` and `mutants.out/` stay out of the copy.

### Skipping a function in source

Prefer this to a config regex when the reason lives with the code (a `main`, an intentional
infinite loop): add `mutants = "0.0.3"` as a *regular* dependency and mark the item
`#[mutants::skip]` or `#[cfg_attr(test, mutants::skip)]`. The `cfg_attr` condition is not
evaluated — the inner `mutants::skip` is always honoured.

## What gets mutated

| kind | change |
|---|---|
| function body → constant | `bool` → `true`,`false`; ints → `0`,`1`,`-1`; floats likewise; `String` → `String::new()`, `"xyzzy".into()`; `Vec` → `vec![]`, `vec![<one default>]`; `Option` → `None`, `Some(..)`; `Result` → `Ok(Default::default())` plus each `error_values` entry; `&T`/`&mut T` → `Box::leak(..)`; tuples → product of the above; anything else → `Default::default()`; `()` → empty body |
| binary operator | `==`↔`!=`; `<` → `==`,`>` (and the other comparisons likewise); `&&`↔`\|\|`; `+`↔`-`; `*`↔`/`; `%`; `&`,`\|`,`^` swapped; `<<`↔`>>` |
| unary operator | `-a` → `a`, `!a` → `a` |
| `match` | an arm is deleted when a wildcard arm exists; a guard becomes `true` / `false` |
| struct literal | a field is deleted when the literal has a `..base` |

Unviable (does not compile) is common and benign — `Default` not implemented, a leaked
reference of a non-`'static` type. It costs build time, nothing else.

## Read the output

Each mutant is named `path:line:col: replace <item> -> <type> with <value>` (or
`replace <op> with <op> in <fn>`); that name is what `-F`/`-E` match. The console prints one
line per mutant, outcome first, then build/test time:

```
ok       Unmutated baseline in 15s build + 0s test
MISSED   src/main.rs:157:5: replace main -> ExitCode with Default::default() in 1s build + 1s test
MISSED   src/api.rs:285:5: replace error_for_status -> Result<()> with Ok(()) in 1s build + 1s test
caught   src/main.rs:587:42: replace == with != in validate_create_preflight in 1s build + 1s test
unviable src/main.rs:239:5: replace label_verify_error -> anyhow::Error with Default::default() in 0s build
```

(`TIMEOUT` is the fourth token; not observed in a run here.) The run ends with
`N mutants tested in T: N missed, N caught, N unviable, N timeouts`.

Exit codes: **0** all caught · **1** usage · **2** something MISSED · **3** a timeout ·
**4** baseline tests already fail · **5**/**6** `--in-diff` does not match the tree / cannot be
parsed · **70** internal error. In practice a stale or wrong-direction diff exits **1** with
`Diff content doesn't match source file`, so do not key CI logic on 5/6.

`mutants.out/` (previous run is rotated to `mutants.out.old/`; gitignore both with
`/mutants.out*`):

| file | holds |
|---|---|
| `missed.txt`, `caught.txt`, `timeout.txt`, `unviable.txt` | one mutant name per line, by outcome |
| `outcomes.json` | every result with build/test phases, timings, and the summary counts |
| `mutants.json` | the full inventory, written before testing starts |
| `diff/*.diff` | the exact source change for each mutant — open this before judging a survivor |
| `log/*.log` | cargo output per mutant, plus `baseline.log` |
| `debug.log` | cargo-mutants' own trace of the run |
| `previously_caught.txt` | accumulates across `--iterate` runs |
| `lock.json` | start time, version, user, host; locked while a run is live |

**Efficacy = caught / (caught + missed).** cargo-mutants does not compute a score; timeouts and
unviable are excluded, so a run with many timeouts understates it.

## Triage

The count is a floor, not a grade. The work is deciding which survivors are real.

### 1. Resolve timeouts before reading anything else

The test timeout is `max(5 × baseline test time, 20 s)`; on a suite that finishes in 200 ms
that 20 s has to cover an incremental rebuild and relink under `-j N`. A mutant that would
obviously fail everything (a `parse` returning `Ok(Default::default())`) landing in timeout is
the tell. Rerun those with `--timeout-multiplier 10` or `-j 1`. What stays timed out is a
loop-bound or retry mutant that spins; treat it as caught-in-practice and say so.

### 2. For each MISSED, decide: equivalent, real, or untestable

Open `mutants.out/diff/<n>.diff`, write down the mutation, then trace the *boundary input* —
the one value where original and mutant disagree — through the rest of the function.

**Equivalent** (do not write a test): identical observable output because something downstream
absorbs the difference. Typical shapes:

- `with_capacity(n)` → `with_capacity(0)` — allocation hint (default `skip_calls` already covers it).
- `impl Debug` / `impl Display` bodies replaced — only observable via snapshot tests you do not want.
- `a < b` → `a <= b` where `a == b` already falls through to the same return.
- A guard duplicating a stricter check further down.

A test that kills an equivalent mutant only pins the implementation; skip it and say why.

**Real**: a different result, a panic, or a skipped write on some input. Name the *input class*
the suite is missing, not the mutant — one realistic case per class kills several mutants and
reads as a specification. The body-replacement mutants have characteristic meanings:

| survivor | what the suite never does |
|---|---|
| `-> bool with true` (or `false`) survives | exercises the other branch of this predicate |
| `-> Result<T> with Ok(Default::default())` survives | inspects the value inside the `Ok` |
| no `Err` mutant listed at all | `error_values` is unset — add it, the error path is untested by construction |
| `-> Option<T> with None` survives | asserts on the `Some` payload |
| `-> () with ()` on a fn that prints or writes | captures the output — see "untestable" below before writing a test |
| `-> String with String::new()` / `"xyzzy"` survives | compares the string, or compares only a prefix |
| `match` arm deleted survives | has a case for that variant |
| `==` → `!=` survives | tests both an equal and an unequal pair |

Recurring input classes: exactly-boundary sizes (`len == max`), empty collections, the
zero/negative/overflow numeric, the rare enum arm, malformed or truncated input (a panicking
mutant here is a robustness bug in disguise).

**Untestable as written**: the function's only observable effect is a live network call,
a write to real stdout, or process exit. These are a design finding, not N test gaps: report
them as one class and, where cheap, name the seam that would fix it (return a `String` /
take `impl Write`, take a `&dyn Client`). Exclude them by `exclude_re` on the function name
*with a comment saying why*, or accept the noise — do not paper over them with
`#[mutants::skip]` unless the skip reason belongs next to the code.

### 3. Unviable is not a gap

Count it and move on. A high unviable share only says the crate's return types lack `Default`.

### 4. Keep scope honest

Survivors in files outside the change under review are pre-existing debt. Report them in
their own section; do not fold them into the current diff's test work unless asked.

## Report

Use this shape; verdicts must say *why*, not just equivalent/real:

```
## <crate> — efficacy N% (C caught / M missed; T timeouts, U unviable)

### <file in the diff> — MISSED
| line | mutant | verdict |
| 107:20 | `parse_width -> Option<usize> with None` | REAL — width at exactly `MAX_WIDTH` never asserted; add a boundary case |
| 34:17  | `impl Debug for Row::fmt`               | equivalent — Debug is diagnostic-only; excluded via `exclude_re` |

### Untestable as written (N)
- api.rs `fetch_hosts`, `delete_host`, … — only reachable through a live HTTP call; no client seam

### Tests to add
1. width == MAX_WIDTH row            (kills 107:20, 112:9)
2. host list with zero entries       (kills 88:5)
```

## Close the loop

Add the tests, rerun with `--iterate`, confirm the targeted mutants moved to `caught.txt`, then
run once *without* `--iterate` — a code change can make a previously-caught mutant survive again.
Efficacy going *down* after adding tests means the new cases widened coverage onto lines with
their own survivors; that is progress.

## CI gate (PR-scoped)

Gate on the diff, not the crate: legacy survivors should not block unrelated PRs.

```yaml
mutants:
  if: github.event_name == 'pull_request'
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0                       # --in-diff needs the base ref
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    - uses: taiki-e/install-action@v2
      with:
        tool: cargo-mutants
    - run: git diff origin/${{ github.base_ref }}.. > git.diff
    - run: cargo mutants -vV --in-diff git.diff
    - uses: actions/upload-artifact@v4
      if: always()
      with:
        name: mutants.out
        path: mutants.out
```

Exit 2 fails the job on any MISSED mutant in the PR's own lines; `--annotations` auto-detects
GitHub Actions and annotates the PR inline. Pin actions to SHAs if the repo does.

Local equivalent in a jj repo, verified: `jj diff --git -r 'main..@' > target/git.diff && cargo mutants -D target/git.diff`.
`-r 'main..@'` diffs the branch's own commits whether there is one or several, and writing into
`target/` keeps the diff file out of the tree copy and out of `jj status`. As a justfile recipe:

```
mutants-diff *args:
    mkdir -p target
    jj diff --git -r 'main..@' > target/mutants.diff
    cargo mutants --in-diff target/mutants.diff {{args}}
```

## When cargo-mutants is the wrong tool

- **Go** → [gremlins](https://github.com/go-gremlins/gremlins) or [gomutants](https://github.com/szhekpisov/gomutants) (operator-swap mutants, `LIVED`/`KILLED` vocabulary); the `gremlins` skill covers the former where installed.
- **Solidity / TS / multi-language campaigns** → Trail of Bits' `mewt` (`trailofbits/skills@mutation-testing`).
- **Fuzzing** answers a different question (does *any* input crash it) — `cargo-fuzz`; both together is the strong position for parsers.

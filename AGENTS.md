# Agent notes

Read [CONTRIBUTE.md](./CONTRIBUTE.md) for the build, test, and release flow,
including how to title a PR and when it needs a change file.

## Code comments

Comments describe the world, not the diff. A comment carrying a constraint,
an API behaviour, or a domain fact the code can't show stays in the code. One
narrating the change (what it replaced, what used to go wrong, who flagged it)
goes in the commit body, and a callout meant for the reviewer goes in the PR.
Write as if the code always looked this way, and state mechanism in terms of
named constants and live code paths.

Prefer one tight sentence. A comment that runs long is usually arguing that
the change is correct, and that argument belongs in the PR body. Length is
earned only by the world: an invariant the code can't show, a worked example,
a fixture's layout, or a workaround's trigger plus the external system's
behaviour.

These are world, not diff, and stay:

- External facts: what the API accepts or rejects (`filter.search` shorter
  than two characters is a 400 `ERR_TOO_SHORT`), an upstream bug, a spec. Say
  it in prose; a bare link is fine only where the code beside it names what
  it cites.
- Test documentation: the behaviour a test pins, what a fixture or mock
  contains, and why a brittle or surprising technique is used (a directory
  placed at `auth.json.lock` because root ignores a read-only directory).
  Prefer an expressive test name over a doc comment restating it.
- Help text. A `///` on a clap argument or command is what `--help` prints,
  so it is written for the person running `dn`.
- Coupling notes: which other file or table to keep in sync. Name the
  counterpart.
- A bug fix's failure mode. Describe the failure the code prevents, without
  narrating the fix as a change. The issue or PR number goes in the commit
  message, never in a comment.

A `TODO` or `FIXME` states the condition that discharges it. A lint
suppression carries its reason in its own syntax
(`#[expect(lint, reason = "...")]`): why the rule is wrong here, not what the
rule is. When you rename a thing, rename it in its doc comment.

The test that wins over everything above: if the comment were removed, would
the code look like a mistake? Then it is world, and stays. If it only makes
sense while the PR is open, it is diff, and moves.

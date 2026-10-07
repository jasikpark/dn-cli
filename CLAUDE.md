# dn-cli

## Releases

Knope prepares each release from what landed on `main` since the last tag: conventional commits plus any `.changeset/*.md` files. PRs are squash-merged, and the squash message keeps only the PR title, so a commit body or footer (including `BREAKING CHANGE:`) never reaches Knope.

- A routine `feat:` / `fix:` needs nothing more: the PR title carries the type into the changelog.
- A breaking PR's title carries `!` (`feat!: …`), which survives the squash.
- Anything breaking, or anything a user needs more than one line to understand, also gets a changeset in the same PR:

  ```markdown
  ---
  default: major # major | minor | patch; major bumps 0.x to the next minor
  ---

  # Heading for the changelog entry

  What changed, and what a user or script must do about it.
  ```

- Check the result with `knope check-release --dry-run`. It prints the version and the changelog section without writing anything.

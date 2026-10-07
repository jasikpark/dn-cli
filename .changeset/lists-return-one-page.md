---
default: major
---

# Lists return one page at a time

`host list`, `host search`, `role list`, `tag list`, and `network list` used to walk every page and print the whole set. Each now fetches one page of up to 500 items, matching the admin panel. Pass `--limit` (alias `--page-size`) for a smaller page and `--cursor` for the next one. Without `--json`, stderr prints the command for the next and previous page. With `--json`, `metadata.hasNextPage` and `metadata.nextCursor` say whether more remain. A script that read the full list from one call should follow `nextCursor` until `hasNextPage` is false.

---
default: patch
---

# Show bidi and zero-width characters in names as spaces

Tables, detail views and delete confirmations already replaced control
characters in names from the API with spaces. They now do the same for
bidi overrides, isolates and marks, and zero-width spaces, which could make
a host named `web\u{202E}dorp` display as "webprod" in
`dn host delete`'s prompt. Zero-width joiners stay, so emoji sequences
display as before.

`Retry-After` waits are now capped at 60 seconds including jitter (up to
90 seconds before), and `dn host create --code-lifetime` accepts 60 to
604800 seconds, as `dn host enroll-code` does, instead of leaving an
out-of-range value for the API to reject.

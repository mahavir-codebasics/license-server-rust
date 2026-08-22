## What

<!-- Summarize the change. One logical change per PR keeps review fast. -->

## Why

<!-- Link the issue (e.g. "Fixes #123") or explain the motivation. -->

## Testing

<!-- How was this verified? Unit tests added? Which suites ran locally (incl. DB isolation lanes if crates/db touched)? -->

## Gates checked

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`

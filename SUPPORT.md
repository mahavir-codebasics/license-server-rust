# Support

Thanks for using **license-server-rust**! Here's how to get help — and help
us help you faster.

## Where to ask

| Need | Channel | Typical first response |
|---|---|---|
| "How do I…?" / usage questions | [GitHub Discussions → Q&A](https://github.com/mahavirvataliya/license-server-rust/discussions/categories/q-a) | best effort, community-driven |
| Feature ideas & design discussions | [GitHub Discussions → Ideas](https://github.com/mahavirvataliya/license-server-rust/discussions/categories/ideas) | maintainer triage |
| Bugs & regressions | [GitHub Issues](https://github.com/mahavirvataliya/license-server-rust/issues/new/choose) | maintainer triage |
| **Security vulnerabilities** | [Private disclosure](https://github.com/mahavirvataliya/license-server-rust/blob/main/SECURITY.md) — **do not open a public issue** | as soon as possible |

## Documentation

Start with the [documentation site](https://mahavirvataliya.github.io/license-server-rust/):

- [Getting started](https://mahavirvataliya.github.io/license-server-rust/getting-started/) — bootstrap an org, issue a signed license, validate it (5 min).
- [API reference](https://mahavirvataliya.github.io/license-server-rust/api-reference/) — every endpoint, error codes, rate limits, idempotency.
- [Deployment](https://mahavirvataliya.github.io/license-server-rust/deployment/) — roles, configuration, production checklist.
- [Security audit](https://mahavirvataliya.github.io/license-server-rust/security-audit/) — findings, remediations, measured baselines.

An LLM-friendly project summary is served at
[`/llms.txt`](https://mahavirvataliya.github.io/license-server-rust/llms.txt).

## Before filing a bug

Please include:

1. **What happened** vs. **what you expected** (exact error messages help).
2. **How you're running it**: `docker compose`, binary, `cargo run`; the
   `DATABASE_URL` *scheme* (SQLite/Postgres/MySQL) — never paste credentials.
3. **Version**: commit SHA, image tag, or `license-server --version`.
4. **Minimal reproduction**: a `curl` sequence or a failing test is ideal.
5. Request IDs (`x-request-id` response header) if you have them — they map
   directly to server trace spans.

> ⚠️ **Never share** admin tokens, license keys, master keys
> (`LICENSE_SERVER__CRYPTO__MASTER_KEY`), or database credentials in any
> issue or discussion. Tokens are stored hashed server-side and cannot be
> recovered — rotate if you accidentally expose one.

## Commercial / priority support

This is an open-source, best-effort project. If you need guaranteed SLAs or
priority fixes, [open a Discussion](https://github.com/mahavirvataliya/license-server-rust/discussions/categories/ideas)
so we can talk about your requirements.

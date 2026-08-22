# Contributing to license-server-rust

Thanks for your interest in contributing! This document covers local setup,
the quality gates every change must pass, and what to expect from the PR
process.

## Development setup

### Prerequisites

- **Rust** (stable) — install via [rustup](https://rustup.rs).
- **protoc** — required by `tonic-build` to compile the gRPC service:
  - macOS: `brew install protobuf`
  - Debian/Ubuntu: `sudo apt-get install -y protobuf-compiler`
- **Node.js + pnpm** — only if you work on the admin UI (`ui/`, Next.js 15).
- **Docker** — optional but recommended; used to run Postgres/MySQL/Redis
  locally.

### Repository setup

```bash
git clone https://github.com/<OWNER>/license-server-rust.git
cd license-server-rust

cp .env.example .env   # then fill in LICENSE_SERVER__CRYPTO__MASTER_KEY (openssl rand -hex 32)
```

### Running services locally

The root `docker-compose.yml` includes the full stack defined in
`docker/docker-compose.yml` (Postgres, MySQL, Redis, API, UI). To bring up
just the dependencies the server needs:

```bash
docker compose up postgres redis
```

Or run everything with one command (see the README's Quick start):

```bash
docker compose up
```

The DB backend is auto-selected from the scheme of `DATABASE_URL`
(`postgresql://`, `mysql://`, or `sqlite://`).

### Admin UI

```bash
cd ui
pnpm i
pnpm dev
```

## Quality gates

CI (`.github/workflows/ci.yml`) enforces these on every PR — run them before
you push:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Clippy is deny-by-default: any warning fails CI.

### Database matrix tests

In addition to unit tests, CI runs a live three-backend isolation suite
(Postgres, MySQL, SQLite) via service containers. To run a lane locally,
point `DATABASE_URL` at the corresponding database and enable ignored tests:

```bash
# SQLite (in-memory, no services needed)
cargo test -p license-db --test isolation -- --include-ignored

# Postgres / MySQL (requires a running server, e.g. via docker compose)
DATABASE_URL=postgresql://license:license@localhost:5432/license \
  cargo test -p license-db --test pg_isolation -- --include-ignored
DATABASE_URL=mysql://license:license@localhost:3306/license \
  cargo test -p license-db --test mysql_isolation -- --include-ignored
```

If your change touches `crates/db`, please run at least the SQLite suite
locally; the live PG/MySQL lanes are verified in CI.

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/):
`feat(scope): ...`, `fix(scope): ...`, `chore: ...`, `docs: ...`,
`perf: ...`, `refactor: ...`, `test: ...`.

## Pull requests

1. Fork/branch from `main`.
2. Make your change with tests where practical.
3. Run all gates above and tick them off in the PR template.
4. Open the PR using `.github/PULL_REQUEST_TEMPLATE.md` (What / Why /
   Testing / Gates checked).

Keep PRs focused — one logical change per PR makes review fast.

## License

By contributing you agree that your contributions will be licensed under the
Apache License 2.0.

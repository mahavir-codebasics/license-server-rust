import Link from "next/link";
import { Logo } from "@/components/logo";
import {
  ArrowRight,
  Boxes,
  CheckCircle2,
  Cpu,
  FileText,
  Github,
  KeyRound,
  ScrollText,
  Terminal,
  Webhook,
} from "lucide-react";

const GITHUB = "https://github.com/mahavirvataliya/license-server-rust";

const FEATURES = [
  {
    icon: KeyRound,
    title: "Signed license keys",
    body: "Ed25519, ECDSA, RSA, and JWT schemes. Keys verify offline — your software doesn't need to phone home to trust a license.",
  },
  {
    icon: Cpu,
    title: "Machine binding",
    body: "Fingerprint-based activation with heartbeats. Cap machines per policy, suspend bad actors, and see every device.",
  },
  {
    icon: FileText,
    title: "Policies, not one-offs",
    body: "Duration, seat limits, max uses, protection mode — define licensing once per product and issue thousands from it.",
  },
  {
    icon: Webhook,
    title: "Webhooks",
    body: "Signed events for every license lifecycle change. Pipe activations, expirations, and revocations into your own systems.",
  },
  {
    icon: ScrollText,
    title: "Full audit trail",
    body: "Every request that matters is recorded in a queryable event log — who activated what, where, and when.",
  },
  {
    icon: Boxes,
    title: "REST + gRPC, self-hosted",
    body: "The same API over HTTP/JSON and gRPC, official SDKs, and a single binary backed by SQLite, Postgres, or MySQL.",
  },
];

const STEPS = [
  {
    title: "Create a product & policy",
    code: `curl -X POST $HOST/v1/accounts/$ACC/policies \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "product_id": "…", "name": "Pro yearly",
        "scheme": "ed25519", "duration_secs": 31536000,
        "max_machines": 3 }'`,
  },
  {
    title: "Issue a license",
    code: `curl -X POST $HOST/v1/accounts/$ACC/licenses \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "product_id": "…", "policy_id": "…" }'

# → { "data": { "key": "KS-4F2A-9C1D-…", "state": "active" } }`,
  },
  {
    title: "Validate from any device",
    code: `curl -X POST $HOST/v1/accounts/$ACC/licenses/$LIC/actions/validate \\
  -H "Authorization: Bearer $LICENSE_TOKEN"

# → { "valid": true, "state": "active" }`,
  },
];

export default function HomePage() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* ── Nav ─────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-20 border-b border-white/5 bg-zinc-950/80 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo className="h-7 w-7" />
            <span className="font-semibold tracking-tight">
              license-server
              <span className="ml-2 rounded-full border border-white/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-zinc-400">
                rust
              </span>
            </span>
          </Link>
          <nav className="flex items-center gap-1 text-sm">
            <a
              href="#features"
              className="hidden rounded-md px-3 py-2 text-zinc-400 transition-colors hover:text-zinc-100 sm:block"
            >
              Features
            </a>
            <a
              href="#how"
              className="hidden rounded-md px-3 py-2 text-zinc-400 transition-colors hover:text-zinc-100 sm:block"
            >
              How it works
            </a>
            <a
              href={GITHUB}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 rounded-md px-3 py-2 text-zinc-400 transition-colors hover:text-zinc-100"
            >
              <Github className="h-4 w-4" />
              <span className="hidden sm:inline">GitHub</span>
            </a>
            <Link
              href="/login"
              className="ml-2 flex items-center gap-1.5 rounded-md bg-primary px-3.5 py-2 font-medium text-white shadow-lg shadow-orange-500/20 transition-colors hover:bg-primary/90"
            >
              Sign in
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </nav>
        </div>
      </header>

      {/* ── Hero ────────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div className="bg-grid-dark absolute inset-0" />
        <div className="bg-grid-fade absolute inset-0" />
        <div className="relative mx-auto max-w-6xl px-6 pb-24 pt-20 sm:pt-28">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3.5 py-1.5 text-xs text-zinc-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              Self-hostable · Apache-2.0 · REST + gRPC
            </div>
            <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-6xl">
              Software licensing,
              <br />
              <span className="bg-gradient-to-r from-orange-300 via-orange-400 to-orange-600 bg-clip-text text-transparent">
                without the scaffolding.
              </span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-zinc-400">
              Issue signed license keys, bind them to machines, and validate them
              from anywhere. One Rust binary, three databases, two APIs — drop it
              next to your app and stop building licensing from scratch.
            </p>
            <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
              <Link
                href="/login"
                className="flex h-11 items-center gap-2 rounded-lg bg-primary px-6 font-medium text-white shadow-xl shadow-orange-500/25 transition-all hover:bg-orange-500 hover:shadow-orange-500/40"
              >
                Open the console
                <ArrowRight className="h-4 w-4" />
              </Link>
              <a
                href={GITHUB}
                target="_blank"
                rel="noreferrer"
                className="flex h-11 items-center gap-2 rounded-lg border border-white/15 bg-white/5 px-6 font-medium text-zinc-200 transition-colors hover:bg-white/10"
              >
                <Github className="h-4 w-4" />
                Star on GitHub
              </a>
            </div>
            <div className="mt-7 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-zinc-500">
              {["Ed25519 · ECDSA · RSA · JWT", "SQLite · Postgres · MySQL", "Official SDKs", "Docker-ready"].map(
                (t) => (
                  <span key={t} className="flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 text-orange-500/80" />
                    {t}
                  </span>
                ),
              )}
            </div>
          </div>

          {/* Terminal card */}
          <div className="mx-auto mt-16 max-w-3xl">
            <div className="overflow-hidden rounded-xl border border-white/10 bg-zinc-900/80 shadow-2xl shadow-black/50 backdrop-blur">
              <div className="flex items-center gap-2 border-b border-white/5 px-4 py-3">
                <span className="h-3 w-3 rounded-full bg-rose-500/80" />
                <span className="h-3 w-3 rounded-full bg-amber-400/80" />
                <span className="h-3 w-3 rounded-full bg-emerald-400/80" />
                <span className="ml-3 flex items-center gap-1.5 text-xs text-zinc-500">
                  <Terminal className="h-3.5 w-3.5" />
                  issue a license
                </span>
              </div>
              <pre className="overflow-x-auto p-5 text-[13px] leading-relaxed">
                <code>
                  <span className="text-zinc-500">$ </span>
                  <span className="text-zinc-200">curl -X POST $HOST/v1/accounts/$ACC/licenses \</span>
                  {"\n"}
                  <span className="text-zinc-400">    -H </span>
                  <span className="text-emerald-300">&quot;Authorization: Bearer $TOKEN&quot;</span>
                  <span className="text-zinc-400"> \</span>
                  {"\n"}
                  <span className="text-zinc-400">    -d </span>
                  <span className="text-emerald-300">&apos;{"{ \"product_id\": \"…\", \"policy_id\": \"…\" }"}&apos;</span>
                  {"\n\n"}
                  <span className="text-zinc-500">{"{ \"data\": {"}</span>
                  {"\n"}
                  <span className="text-zinc-400">  &quot;key&quot;:   </span>
                  <span className="text-sky-300">&quot;KS-4F2A-9C1D-7E3B-88D0-2B6A&quot;</span>
                  <span className="text-zinc-500">,</span>
                  {"\n"}
                  <span className="text-zinc-400">  &quot;state&quot;: </span>
                  <span className="text-emerald-300">&quot;active&quot;</span>
                  <span className="text-zinc-400">, </span>
                  <span className="text-zinc-400">&quot;expiry&quot;: </span>
                  <span className="text-sky-300">&quot;2027-10-13T00:00:00Z&quot;</span>
                  {"\n"}
                  <span className="text-zinc-500">{"}"}</span>
                </code>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* ── Features ────────────────────────────────────────────────── */}
      <section id="features" className="border-t border-white/5 bg-zinc-950">
        <div className="mx-auto max-w-6xl px-6 py-24">
          <div className="mb-14 max-w-2xl">
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Everything licensing needs,
            </h2>
            <p className="mt-3 text-lg text-zinc-400">
              and nothing it doesn&apos;t. Each piece works standalone and gets out
              of your way.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(({ icon: Icon, title, body }) => (
              <div
                key={title}
                className="group rounded-xl border border-white/10 bg-zinc-900/50 p-6 transition-colors hover:border-orange-500/40 hover:bg-zinc-900"
              >
                <div className="mb-4 inline-flex rounded-lg border border-orange-500/20 bg-orange-500/10 p-2.5 text-orange-400 transition-colors group-hover:bg-orange-500/15">
                  <Icon className="h-5 w-5" />
                </div>
                <h3 className="font-semibold">{title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-zinc-400">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ────────────────────────────────────────────── */}
      <section id="how" className="border-t border-white/5">
        <div className="mx-auto max-w-6xl px-6 py-24">
          <div className="mb-14 max-w-2xl">
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Up and running in three calls.
            </h2>
            <p className="mt-3 text-lg text-zinc-400">
              Define what a license means once, then issue and validate forever.
            </p>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            {STEPS.map((s, i) => (
              <div key={s.title} className="flex flex-col rounded-xl border border-white/10 bg-zinc-900/50">
                <div className="flex items-center gap-3 border-b border-white/5 px-5 py-4">
                  <span className="flex h-7 w-7 items-center justify-center rounded-full bg-orange-500/15 text-sm font-semibold text-orange-400">
                    {i + 1}
                  </span>
                  <h3 className="font-medium">{s.title}</h3>
                </div>
                <pre className="flex-1 overflow-x-auto p-5 text-xs leading-relaxed text-zinc-400">
                  <code>{s.code}</code>
                </pre>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────────── */}
      <section className="border-t border-white/5">
        <div className="mx-auto max-w-6xl px-6 py-24">
          <div className="relative overflow-hidden rounded-2xl border border-orange-500/20 bg-gradient-to-br from-orange-500/15 via-zinc-900 to-zinc-950 px-8 py-16 text-center">
            <div className="bg-grid-dark absolute inset-0 opacity-60" />
            <div className="relative">
              <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
                Your licenses are waiting.
              </h2>
              <p className="mx-auto mt-3 max-w-xl text-zinc-400">
                Sign in to the console to create products, issue keys, and watch
                activations roll in.
              </p>
              <Link
                href="/login"
                className="mt-8 inline-flex h-11 items-center gap-2 rounded-lg bg-primary px-7 font-medium text-white shadow-xl shadow-orange-500/25 transition-colors hover:bg-orange-500"
              >
                Open the console
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────── */}
      <footer className="border-t border-white/5">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-6 px-6 py-10 sm:flex-row">
          <div className="flex items-center gap-2.5">
            <Logo className="h-6 w-6" />
            <span className="text-sm font-medium">license-server</span>
            <span className="text-sm text-zinc-500">· Apache-2.0</span>
          </div>
          <div className="flex items-center gap-5 text-sm text-zinc-400">
            <a href={GITHUB} target="_blank" rel="noreferrer" className="transition-colors hover:text-zinc-100">
              GitHub
            </a>
            <a href={`${GITHUB}#readme`} target="_blank" rel="noreferrer" className="transition-colors hover:text-zinc-100">
              Docs
            </a>
            <Link href="/login" className="transition-colors hover:text-zinc-100">
              Sign in
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

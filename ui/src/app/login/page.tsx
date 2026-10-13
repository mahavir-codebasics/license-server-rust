"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  api,
  ApiError,
  setAccountId,
  setToken,
  setUser,
} from "@/lib/api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui";
import { Logo } from "@/components/logo";
import { Cpu, KeyRound, Webhook } from "lucide-react";

type Tab = "signin" | "signup" | "token";

const PANEL_POINTS = [
  { icon: KeyRound, title: "Signed keys", body: "Ed25519, ECDSA, RSA, JWT — verified offline." },
  { icon: Cpu, title: "Machine binding", body: "Fingerprints, heartbeats, and per-policy limits." },
  { icon: Webhook, title: "Webhooks", body: "Signed events for every lifecycle change." },
];

export default function LoginPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [token, setTok] = useState("");
  const [accountId, setAid] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const enter = (tok: string, aid: string, user?: Parameters<typeof setUser>[0]) => {
    setToken(tok);
    setAccountId(aid);
    setUser(user ?? null);
    router.push(`/app/${aid}/dashboard`);
  };

  const signIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { data } = await api.login(email.trim(), password);
      enter(data.token, data.account.id, data.user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  const signUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { data } = await api.signup(
        email.trim(),
        password,
        fullName.trim() || undefined,
        orgName.trim() || undefined,
      );
      enter(data.token, data.account.id, data.user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "sign-up failed");
    } finally {
      setBusy(false);
    }
  };

  const signInWithToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { data } = await api.getAccount(accountId.trim());
      enter(token.trim(), data.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  const tabs: [Tab, string][] = [
    ["signin", "Sign in"],
    ["signup", "Create account"],
    ["token", "Token"],
  ];

  return (
    <div className="flex min-h-screen">
      {/* ── Brand panel (desktop) ─────────────────────────────────── */}
      <aside className="relative hidden w-[44%] shrink-0 flex-col overflow-hidden bg-zinc-950 p-10 text-zinc-100 lg:flex">
        <div className="bg-grid-dark absolute inset-0" />
        <div className="bg-grid-fade absolute inset-0" />
        <div className="relative flex flex-1 flex-col">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo className="h-8 w-8" />
            <span className="font-semibold tracking-tight">license-server</span>
          </Link>
          <div className="mt-auto mb-auto py-12">
            <h1 className="max-w-md text-4xl font-bold leading-tight tracking-tight">
              Licensing infrastructure,{" "}
              <span className="bg-gradient-to-r from-orange-300 to-orange-500 bg-clip-text text-transparent">
                ready when you are.
              </span>
            </h1>
            <ul className="mt-10 space-y-5">
              {PANEL_POINTS.map(({ icon: Icon, title, body }) => (
                <li key={title} className="flex items-start gap-3.5">
                  <span className="mt-0.5 rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-400">
                    <Icon className="h-4 w-4" />
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{title}</span>
                    <span className="block text-sm text-zinc-400">{body}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className="relative text-xs text-zinc-500">Apache-2.0 · self-hosted · REST + gRPC</p>
        </div>
      </aside>

      {/* ── Form ──────────────────────────────────────────────────── */}
      <main className="flex flex-1 items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="mb-6 flex items-center gap-2.5 lg:hidden">
            <Logo className="h-9 w-9" />
            <span className="text-lg font-semibold">license-server</span>
          </div>
          <Card>
            <CardHeader>
              <CardTitle className="text-xl">Welcome back</CardTitle>
              <p className="mt-1 text-sm text-muted-foreground">
                Sign in to manage products, policies, and licenses.
              </p>
              <div className="mt-4 flex gap-1 rounded-lg bg-muted p-1">
                {tabs.map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => {
                      setTab(id);
                      setError(null);
                    }}
                    className={`flex-1 rounded-md px-3 py-1.5 text-sm transition-colors ${
                      tab === id
                        ? "bg-background font-medium shadow-sm"
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent>
              {tab === "signin" && (
                <form onSubmit={signIn} className="space-y-3">
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Email</span>
                    <Input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@company.com"
                      className="mt-1"
                      required
                    />
                  </label>
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Password</span>
                    <Input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="mt-1"
                      required
                    />
                  </label>
                  {error && <p className="text-sm text-rose-600">{error}</p>}
                  <Button type="submit" disabled={busy} className="w-full">
                    {busy ? "Signing in…" : "Sign in"}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    New here?{" "}
                    <button type="button" className="font-medium underline" onClick={() => setTab("signup")}>
                      Create your own organization
                    </button>{" "}
                    — it takes a minute.
                  </p>
                </form>
              )}

              {tab === "signup" && (
                <form onSubmit={signUp} className="space-y-3">
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Email</span>
                    <Input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@company.com"
                      className="mt-1"
                      required
                    />
                  </label>
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Password</span>
                    <Input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="at least 8 characters"
                      className="mt-1"
                      required
                      minLength={8}
                    />
                  </label>
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Your name (optional)</span>
                    <Input value={fullName} onChange={(e) => setFullName(e.target.value)} className="mt-1" />
                  </label>
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Organization name (optional)</span>
                    <Input
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      placeholder="ACME Inc."
                      className="mt-1"
                    />
                  </label>
                  {error && <p className="text-sm text-rose-600">{error}</p>}
                  <Button type="submit" disabled={busy} className="w-full">
                    {busy ? "Creating…" : "Create account"}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    Creates your own organization — you can immediately add
                    products, policies, and issue licenses. You are signed in
                    automatically.
                  </p>
                </form>
              )}

              {tab === "token" && (
                <form onSubmit={signInWithToken} className="space-y-3">
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Account ID</span>
                    <Input
                      value={accountId}
                      onChange={(e) => setAid(e.target.value)}
                      placeholder="019f…"
                      className="mt-1"
                      required
                    />
                  </label>
                  <label className="block text-sm">
                    <span className="text-muted-foreground">Admin token</span>
                    <Input
                      value={token}
                      onChange={(e) => setTok(e.target.value)}
                      placeholder="adm_…"
                      className="mt-1 font-mono"
                      required
                    />
                  </label>
                  {error && <p className="text-sm text-rose-600">{error}</p>}
                  <Button type="submit" disabled={busy} className="w-full">
                    {busy ? "Signing in…" : "Sign in with token"}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    Advanced: sign in with a raw bearer token (e.g. an admin token
                    from the API bootstrap).
                  </p>
                </form>
              )}
            </CardContent>
          </Card>
          <p className="mt-6 text-center text-xs text-muted-foreground">
            <Link href="/" className="underline hover:text-foreground">
              ← Back to home
            </Link>
          </p>
        </div>
      </main>
    </div>
  );
}

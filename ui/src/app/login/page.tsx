"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  api,
  ApiError,
  setAccountId,
  setToken,
  setUser,
} from "@/lib/api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui";

type Tab = "signin" | "signup" | "token";

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
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center gap-2 mb-2">
            <img src="/logo.svg" alt="license-server logo" className="h-9 w-9" />
            <CardTitle>license-server</CardTitle>
          </div>
          <div className="flex gap-1 mt-2">
            {tabs.map(([id, label]) => (
              <button
                key={id}
                onClick={() => {
                  setTab(id);
                  setError(null);
                }}
                className={`px-3 py-1.5 text-sm rounded-md ${tab === id ? "bg-muted font-medium" : "text-muted-foreground"}`}
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
                <button type="button" className="underline" onClick={() => setTab("signup")}>
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
                {busy ? "Creating…" : "Sign up"}
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
    </div>
  );
}

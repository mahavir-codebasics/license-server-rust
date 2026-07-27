"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setAccountId, setToken } from "@/lib/api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [tab, setTab] = useState<"signin" | "bootstrap">("signin");
  const [token, setTok] = useState("");
  const [accountId, setAid] = useState("");
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const signIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      // Verify the token by hitting the account endpoint.
      const { data } = await api.getAccount(accountId.trim());
      setToken(token.trim());
      setAccountId(data.id);
      router.push(`/app/${data.id}/dashboard`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  const bootstrap = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { data } = await api.createAccount(slug.trim(), name.trim());
      setToken(data.admin_token);
      setAccountId(data.id);
      router.push(`/app/${data.id}/dashboard`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "bootstrap failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center gap-2 mb-2">
            <div className="h-8 w-8 rounded-md bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold">
              LS
            </div>
            <CardTitle>license-server</CardTitle>
          </div>
          <div className="flex gap-1 mt-2">
            <button
              onClick={() => setTab("signin")}
              className={`px-3 py-1.5 text-sm rounded-md ${tab === "signin" ? "bg-muted font-medium" : "text-muted-foreground"}`}
            >
              Sign in
            </button>
            <button
              onClick={() => setTab("bootstrap")}
              className={`px-3 py-1.5 text-sm rounded-md ${tab === "bootstrap" ? "bg-muted font-medium" : "text-muted-foreground"}`}
            >
              Create organization
            </button>
          </div>
        </CardHeader>
        <CardContent>
          {tab === "signin" ? (
            <form onSubmit={signIn} className="space-y-3">
              <label className="block text-sm">
                <span className="text-muted-foreground">Account ID</span>
                <Input value={accountId} onChange={(e) => setAid(e.target.value)} placeholder="019f…" className="mt-1" required />
              </label>
              <label className="block text-sm">
                <span className="text-muted-foreground">Admin token</span>
                <Input value={token} onChange={(e) => setTok(e.target.value)} placeholder="adm_…" className="mt-1 font-mono" required />
              </label>
              {error && <p className="text-sm text-rose-600">{error}</p>}
              <Button type="submit" disabled={busy} className="w-full">
                {busy ? "Signing in…" : "Sign in"}
              </Button>
            </form>
          ) : (
            <form onSubmit={bootstrap} className="space-y-3">
              <label className="block text-sm">
                <span className="text-muted-foreground">Slug</span>
                <Input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="acme" className="mt-1" required />
              </label>
              <label className="block text-sm">
                <span className="text-muted-foreground">Organization name</span>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="ACME Inc." className="mt-1" required />
              </label>
              {error && <p className="text-sm text-rose-600">{error}</p>}
              <Button type="submit" disabled={busy} className="w-full">
                {busy ? "Creating…" : "Create organization"}
              </Button>
              <p className="text-xs text-muted-foreground">
                Creates a new org and returns its first admin token. You&apos;ll
                be signed in automatically.
              </p>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

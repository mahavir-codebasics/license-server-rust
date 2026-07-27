"use client";

import { use, useState } from "react";
import { api, type CreateTokenResponse, type Token } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input, Select, Badge } from "@/components/ui";
import { fmtDate } from "@/lib/utils";

const KINDS = ["product", "license", "user", "personal"];
const tone = (k: string) => ({ admin: "amber", product: "blue", license: "green", user: "gray", personal: "blue" }[k] ?? "gray");

export default function TokensPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading, refresh } = useApi(
    () => api.listTokens(accountId),
    [accountId],
  );
  const [kind, setKind] = useState("product");
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [issued, setIssued] = useState<CreateTokenResponse | null>(null);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      const { data } = await api.createToken(accountId, kind, name.trim());
      setIssued(data);
      setName("");
      refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    } finally {
      setCreating(false);
    }
  };

  const rows: Token[] = data?.data ?? [];
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Tokens</h1>

      {issued && (
        <Card className="mb-6 border-amber-300 bg-amber-50">
          <CardContent className="pt-6">
            <p className="text-sm font-medium text-amber-800 mb-2">
              Token created — copy it now (shown once):
            </p>
            <code className="block bg-white border border-amber-200 rounded-md p-3 text-xs font-mono break-all">
              {issued.token}
            </code>
            <Button variant="ghost" size="sm" className="mt-2" onClick={() => setIssued(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <Card className="mb-6">
        <CardHeader><CardTitle className="text-base">New token</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={create} className="flex gap-2 items-end">
            <label className="text-sm">
              <span className="text-muted-foreground">Kind</span>
              <Select value={kind} onChange={(e) => setKind(e.target.value)} className="mt-1">
                {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
              </Select>
            </label>
            <label className="flex-1 text-sm">
              <span className="text-muted-foreground">Name (optional)</span>
              <Input value={name} onChange={(e) => setName(e.target.value)} className="mt-1" />
            </label>
            <Button type="submit" disabled={creating}>{creating ? "Creating…" : "Create"}</Button>
          </form>
          {err && <p className="text-sm text-rose-600 mt-2">{err}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="pt-6">
          <State loading={loading} error={error} empty={rows.length === 0}>
            <table className="w-full text-sm">
              <thead className="text-left text-muted-foreground">
                <tr><th className="py-2">Kind</th><th>Name</th><th>Last used</th><th>Created</th></tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((t) => (
                  <tr key={t.id}>
                    <td className="py-2"><Badge tone={tone(t.kind)}>{t.kind}</Badge></td>
                    <td>{t.name ?? "—"}</td>
                    <td className="text-muted-foreground">{fmtDate(t.last_used_at)}</td>
                    <td className="text-muted-foreground">{fmtDate(t.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </State>
        </CardContent>
      </Card>
    </div>
  );
}

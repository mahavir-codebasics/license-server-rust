"use client";

import { use, useState } from "react";
import { api, type Product } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui";
import { fmtDate } from "@/lib/utils";

export default function ProductsPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading, refresh } = useApi(
    () => api.listProducts(accountId),
    [accountId],
  );
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      await api.createProduct(accountId, name.trim());
      setName("");
      refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    } finally {
      setCreating(false);
    }
  };

  const rows: Product[] = data?.data ?? [];
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Products</h1>

      <Card className="mb-6">
        <CardHeader><CardTitle className="text-base">New product</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={create} className="flex gap-2 items-end">
            <label className="flex-1 text-sm">
              <span className="text-muted-foreground">Name</span>
              <Input value={name} onChange={(e) => setName(e.target.value)} className="mt-1" required />
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
                <tr><th className="py-2">Name</th><th>ID</th><th>Created</th></tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((p) => (
                  <tr key={p.id}>
                    <td className="py-2 font-medium">{p.name}</td>
                    <td className="font-mono text-xs">{p.id.slice(0, 12)}…</td>
                    <td className="text-muted-foreground">{fmtDate(p.created_at)}</td>
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

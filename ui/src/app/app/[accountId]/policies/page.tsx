"use client";

import { use, useState } from "react";
import { api, type Policy, type Product } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input, Select, Badge } from "@/components/ui";
import { fmtDate } from "@/lib/utils";

const SCHEMES = ["ED25519_SIGN", "ECDSA_P256_SHA256", "RSA_2048_PSS_SHA256", "RSA_2048_PKCS1V15_SHA256", "JWT_RS256", "JWT_EDDSA"];

export default function PoliciesPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading, refresh } = useApi(
    () => api.listPolicies(accountId),
    [accountId],
  );
  const products = useApi(() => api.listProducts(accountId), [accountId]);

  const [productId, setProductId] = useState("");
  const [name, setName] = useState("");
  const [scheme, setScheme] = useState("ED25519_SIGN");
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      await api.createPolicy(accountId, productId, name.trim(), scheme);
      setName("");
      refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    } finally {
      setCreating(false);
    }
  };

  const rows: Policy[] = data?.data ?? [];
  const prods: Product[] = products.data?.data ?? [];
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Policies</h1>

      <Card className="mb-6">
        <CardHeader><CardTitle className="text-base">New policy</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={create} className="grid grid-cols-2 gap-3 items-end">
            <label className="text-sm">
              <span className="text-muted-foreground">Product</span>
              <Select value={productId} onChange={(e) => setProductId(e.target.value)} className="mt-1" required>
                <option value="">Select…</option>
                {prods.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </Select>
            </label>
            <label className="text-sm">
              <span className="text-muted-foreground">Name</span>
              <Input value={name} onChange={(e) => setName(e.target.value)} className="mt-1" required />
            </label>
            <label className="text-sm">
              <span className="text-muted-foreground">Signing scheme</span>
              <Select value={scheme} onChange={(e) => setScheme(e.target.value)} className="mt-1">
                {SCHEMES.map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
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
                <tr><th className="py-2">Name</th><th>Scheme</th><th>Max machines</th><th>Created</th></tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((p) => (
                  <tr key={p.id}>
                    <td className="py-2 font-medium">{p.name}</td>
                    <td><Badge tone="blue">{p.scheme}</Badge></td>
                    <td>{p.max_machines ?? "—"}</td>
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

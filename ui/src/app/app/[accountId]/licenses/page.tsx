"use client";

import { use, useState } from "react";
import { api, type License, type Policy, type Product, type ValidateResponse } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Button, Card, CardContent, CardHeader, CardTitle, Select, Badge, stateTone } from "@/components/ui";
import { fmtDate, short } from "@/lib/utils";
import { CheckCircle2, XCircle, Loader2 } from "lucide-react";

export default function LicensesPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading, refresh } = useApi(
    () => api.listLicenses(accountId),
    [accountId],
  );
  const policies = useApi(() => api.listPolicies(accountId), [accountId]);
  const products = useApi(() => api.listProducts(accountId), [accountId]);

  const [productId, setProductId] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [issuedKey, setIssuedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [validating, setValidating] = useState<string | null>(null);
  const [validation, setValidation] = useState<Record<string, ValidateResponse>>({});

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      const { data } = await api.createLicense(accountId, productId, policyId);
      setIssuedKey(data.key ?? null);
      refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    } finally {
      setCreating(false);
    }
  };

  const validate = async (id: string) => {
    setValidating(id);
    try {
      const { data } = await api.validateLicense(accountId, id);
      setValidation((v) => ({ ...v, [id]: data }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "validate failed");
    } finally {
      setValidating(null);
    }
  };

  const rows: License[] = data?.data ?? [];
  const pols: Policy[] = policies.data?.data ?? [];
  const prods: Product[] = products.data?.data ?? [];
  const productName = (id: string) => prods.find((p) => p.id === id)?.name ?? short(id);
  const policyName = (id: string) => pols.find((p) => p.id === id)?.name ?? short(id);

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Licenses</h1>

      {/* Issued-key banner (the signed key is shown ONCE after creation). */}
      {issuedKey && (
        <Card className="mb-6 border-emerald-300 bg-emerald-50">
          <CardContent className="pt-6">
            <p className="text-sm font-medium text-emerald-800 mb-2">
              License created — copy the signed key now (shown once):
            </p>
            <code className="block bg-white border border-emerald-200 rounded-md p-3 text-xs font-mono break-all">
              {issuedKey}
            </code>
            <div className="mt-2 flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  navigator.clipboard.writeText(issuedKey);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
              >
                {copied ? "Copied!" : "Copy"}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setIssuedKey(null)}>
                Dismiss
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="mb-6">
        <CardHeader><CardTitle className="text-base">Issue a license</CardTitle></CardHeader>
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
              <span className="text-muted-foreground">Policy</span>
              <Select value={policyId} onChange={(e) => setPolicyId(e.target.value)} className="mt-1" required>
                <option value="">Select…</option>
                {pols.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </Select>
            </label>
            <Button type="submit" disabled={creating} className="col-span-2">
              {creating ? "Issuing…" : "Issue license"}
            </Button>
          </form>
          {err && <p className="text-sm text-rose-600 mt-2">{err}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="pt-6">
          <State loading={loading} error={error} empty={rows.length === 0}>
            <table className="w-full text-sm">
              <thead className="text-left text-muted-foreground">
                <tr>
                  <th className="py-2">ID</th><th>Product</th><th>Policy</th><th>State</th>
                  <th>Uses</th><th>Expiry</th><th></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((l) => {
                  const v = validation[l.id];
                  return (
                    <tr key={l.id}>
                      <td className="py-2 font-mono text-xs">{short(l.id)}</td>
                      <td>{productName(l.product_id)}</td>
                      <td>{policyName(l.policy_id)}</td>
                      <td><Badge tone={stateTone(l.state)}>{l.state}</Badge></td>
                      <td>{l.uses}{l.max_uses ? `/${l.max_uses}` : ""}</td>
                      <td className="text-muted-foreground">{fmtDate(l.expiry)}</td>
                      <td className="text-right">
                        <Button variant="ghost" size="sm" onClick={() => validate(l.id)} disabled={validating === l.id}>
                          {validating === l.id ? <Loader2 className="h-4 w-4 animate-spin" /> : "Validate"}
                        </Button>
                        {v && (
                          <span className="ml-2">
                            {v.valid ? <CheckCircle2 className="h-4 w-4 inline text-emerald-600" /> : <XCircle className="h-4 w-4 inline text-rose-600" />}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </State>
        </CardContent>
      </Card>
    </div>
  );
}

"use client";

import { use, useState } from "react";
import { api, type WebhookEndpoint } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Button, Card, CardContent, CardHeader, CardTitle, Input, Badge } from "@/components/ui";
import { fmtDate } from "@/lib/utils";

export default function WebhooksPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading, refresh } = useApi(
    () => api.listWebhooks(accountId),
    [accountId],
  );
  const [url, setUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      const { data } = await api.createWebhook(accountId, url.trim());
      setSecret(data.secret);
      setUrl("");
      refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    } finally {
      setCreating(false);
    }
  };

  const rows: WebhookEndpoint[] = data?.data ?? [];
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Webhooks</h1>

      {secret && (
        <Card className="mb-6 border-sky-300 bg-sky-50">
          <CardContent className="pt-6">
            <p className="text-sm font-medium text-sky-800 mb-2">
              Webhook created — copy the HMAC signing secret now (shown once):
            </p>
            <code className="block bg-white border border-sky-200 rounded-md p-3 text-xs font-mono break-all">
              {secret}
            </code>
            <Button variant="ghost" size="sm" className="mt-2" onClick={() => setSecret(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <Card className="mb-6">
        <CardHeader><CardTitle className="text-base">New endpoint</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={create} className="flex gap-2 items-end">
            <label className="flex-1 text-sm">
              <span className="text-muted-foreground">URL</span>
              <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/hook" className="mt-1" required />
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
                <tr><th className="py-2">URL</th><th>Status</th><th>Created</th></tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((w) => (
                  <tr key={w.id}>
                    <td className="py-2 font-mono text-xs">{w.url}</td>
                    <td><Badge tone={w.status === "active" ? "green" : "gray"}>{w.status}</Badge></td>
                    <td className="text-muted-foreground">{fmtDate(w.created_at)}</td>
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

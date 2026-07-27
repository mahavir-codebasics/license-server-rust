"use client";

import { use } from "react";
import { api, type EventLog } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Card, CardContent, Badge } from "@/components/ui";
import { fmtDate, short } from "@/lib/utils";

const sevTone = (s: string) => ({ info: "blue", warning: "amber", critical: "red" }[s] ?? "gray");

export default function EventsPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading } = useApi(
    () => api.listEvents(accountId),
    [accountId],
  );
  const rows: EventLog[] = data?.data ?? [];
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Event Log</h1>
      <Card>
        <CardContent className="pt-6">
          <State loading={loading} error={error} empty={rows.length === 0}>
            <table className="w-full text-sm">
              <thead className="text-left text-muted-foreground">
                <tr>
                  <th className="py-2">Event</th><th>Severity</th><th>Resource</th><th>When</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="py-2 font-mono text-xs">{e.event_type}</td>
                    <td><Badge tone={sevTone(e.severity)}>{e.severity}</Badge></td>
                    <td className="text-muted-foreground">
                      {e.resource_type ? `${e.resource_type} ${short(e.resource_id)}` : "—"}
                    </td>
                    <td className="text-muted-foreground">{fmtDate(e.created_at)}</td>
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

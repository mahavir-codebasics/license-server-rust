"use client";

import { useCallback, useEffect, useState } from "react";

/** Simple data-fetching hook with refresh support. */
export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await fetcher();
      setData(d);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    run();
  }, [run]);

  return { data, error, loading, refresh: run };
}

/** Empty-state + loading + error UI. */
export function State({
  loading,
  error,
  empty,
  children,
}: {
  loading: boolean;
  error: string | null;
  empty: boolean;
  children: React.ReactNode;
}) {
  if (loading) return <p className="text-sm text-muted-foreground py-8">Loading…</p>;
  if (error) return <p className="text-sm text-rose-600 py-8">{error}</p>;
  if (empty) return <p className="text-sm text-muted-foreground py-8">Nothing here yet.</p>;
  return <>{children}</>;
}

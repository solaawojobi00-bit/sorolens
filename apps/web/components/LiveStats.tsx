"use client";

import { useCallback, useEffect, useState } from "react";
import { getGlobalStats, getWatchdogStats } from "@/lib/api";
import type { GlobalStats, WatchdogStats } from "@/lib/types";
import { ErrorState } from "@/components/ErrorState";

interface Props {
  className?: string;
}

interface Combined {
  global: GlobalStats | null;
  watchdog: WatchdogStats | null;
  /** Which requests failed, so a failure is never shown as a zero count. */
  globalFailed: boolean;
  watchdogFailed: boolean;
}

const EMPTY: Combined = {
  global: null,
  watchdog: null,
  globalFailed: false,
  watchdogFailed: false,
};

export function LiveStats({ className }: Props) {
  const [data, setData] = useState<Combined>(EMPTY);
  const [reload, setReload] = useState(0);
  const [retrying, setRetrying] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const [g, w] = await Promise.allSettled([
        getGlobalStats(),
        getWatchdogStats(),
      ]);
      if (!cancelled) {
        setData({
          global: g.status === "fulfilled" ? g.value : null,
          watchdog: w.status === "fulfilled" ? w.value : null,
          globalFailed: g.status === "rejected",
          watchdogFailed: w.status === "rejected",
        });
        setRetrying(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [reload]);

  const retry = useCallback(() => {
    setRetrying(true);
    setReload((n) => n + 1);
  }, []);

  const failed = data.globalFailed || data.watchdogFailed;

  const items: Array<{ label: string; value: string | number }> = [
    {
      label: "Contracts indexed",
      value: stat(data.global?.tracked_contracts, data.globalFailed),
    },
    {
      label: "Events tracked",
      value: stat(data.global?.total_events, data.globalFailed),
    },
    {
      label: "Invocations traced",
      value: stat(data.global?.total_invocations, data.globalFailed),
    },
    {
      label: "Contracts monitored",
      value: stat(data.watchdog?.total_monitored, data.watchdogFailed),
    },
  ];

  return (
    <div className={className}>
      {failed && (
        <ErrorState
          compact
          className="mb-3"
          title="Couldn't load live stats."
          message="Some figures below are unavailable, not zero."
          onRetry={retry}
          retrying={retrying}
        />
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {items.map((it) => (
          <div
            key={it.label}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-4 text-center"
          >
            <div className="text-2xl font-bold tabular-nums">{it.value}</div>
            <div className="mt-1 text-xs uppercase tracking-wider text-[var(--color-text-secondary)]">
              {it.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// A failed request renders as an em dash; only a successful response may show 0.
function stat(n: number | undefined, failed: boolean): string {
  if (failed) return "—";
  return formatNum(n ?? 0);
}

function formatNum(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

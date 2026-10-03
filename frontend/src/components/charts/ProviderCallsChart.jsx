import { useState } from "react";

const LABELS = {
  VIRUSTOTAL: "VirusTotal",
  SAFE_BROWSING: "Safe Browsing",
  URLSCAN: "URLScan.io",
  ABUSEIPDB: "AbuseIPDB",
};
const ORDER = ["VIRUSTOTAL", "SAFE_BROWSING", "URLSCAN", "ABUSEIPDB"];

/** Provider activity as an expandable list.
 *
 * Each row shows a provider and how many times it was called, with a bar
 * underneath sized against the busiest provider. Opening a row shows how
 * many calls were answered and the average response time.
 */
export default function ProviderCallsChart({ providerCalls }) {
  const [open, setOpen] = useState(null);

  const byProvider = Object.fromEntries((providerCalls || []).map((row) => [row.provider, row]));
  const rows = ORDER.map((provider) => ({
    provider,
    label: LABELS[provider],
    total: byProvider[provider]?.total_calls || 0,
    successful: byProvider[provider]?.successful_calls || 0,
    avgMs: byProvider[provider]?.avg_duration_ms ?? null,
  }));

  const grandTotal = rows.reduce((sum, r) => sum + r.total, 0);
  if (grandTotal === 0) {
    return <p className="text-small text-muted">No provider calls logged yet.</p>;
  }

  const busiest = Math.max(...rows.map((r) => r.total));

  return (
    <ul className="space-y-1">
      {rows.map((row) => {
        const isOpen = open === row.provider;

        return (
          <li key={row.provider} className={`rounded-xl transition-colors ${isOpen ? "bg-paper/[0.05]" : ""}`}>
            <button
              type="button"
              onClick={() => setOpen((o) => (o === row.provider ? null : row.provider))}
              aria-expanded={isOpen}
              disabled={row.total === 0}
              className="group w-full rounded-xl px-3 py-3 text-left hover:bg-paper/[0.035] disabled:cursor-default disabled:hover:bg-transparent"
            >
              <div className="flex items-baseline gap-4">
                <span
                  className={`flex-1 text-small font-medium ${row.total === 0 ? "text-faint" : "text-paper"}`}
                >
                  {row.label}
                </span>
                <span className="tabular text-right text-small text-muted">
                  {row.total} {row.total === 1 ? "call" : "calls"}
                </span>
              </div>

              {/* Bar sized against the busiest provider. */}
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-paper/[0.08]">
                <div
                  className="h-full rounded-full bg-muted transition-[width,background-color] duration-700 ease-spring group-hover:bg-paper"
                  style={{ width: `${busiest ? (row.total / busiest) * 100 : 0}%` }}
                />
              </div>
            </button>

            {isOpen && (
              <dl className="motion-safe:animate-surface grid grid-cols-[auto,1fr] gap-x-6 gap-y-1.5 px-3 pb-4 text-small">
                <dt className="text-muted">Answered</dt>
                <dd className="tabular text-paper">
                  {row.successful} of {row.total}
                </dd>
                <dt className="text-muted">Average response</dt>
                <dd className="tabular text-paper">
                  {row.avgMs === null ? "Not recorded" : `${row.avgMs.toFixed(0)} ms`}
                </dd>
              </dl>
            )}
          </li>
        );
      })}
    </ul>
  );
}

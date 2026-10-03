import { useState } from "react";
import { downloadFile } from "../services/api";

/** The last 12 months, newest first. */
function recentMonths(count = 12) {
  const now = new Date();
  return Array.from({ length: count }, (_, i) => {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    return {
      value: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`,
      label: d.toLocaleString(undefined, { month: "long", year: "numeric" }),
    };
  });
}

export default function MonthlyReportPanel() {
  const months = recentMonths();
  const [month, setMonth] = useState(months[0].value);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState(null);

  const onDownload = async () => {
    setError(null);
    setDownloading(true);
    try {
      await downloadFile(`/admin/report?month=${month}`, `redflag-report-${month}.pdf`);
    } catch (err) {
      setError(err.message || "The report could not be generated.");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <section aria-labelledby="report-heading" className="surface mt-6 p-5 sm:p-6">
      <h2 id="report-heading" className="text-title font-semibold text-paper">
        Monthly report
      </h2>
      <p className="mt-2 max-w-prose text-muted">
        A PDF summary of one month: how many emails were scanned, what the verdicts were,
        what was found and how the providers performed.
      </p>

      <div className="mt-6 flex flex-wrap items-end gap-4">
        <div>
          <label htmlFor="report-month" className="block text-small font-medium text-muted">
            Month
          </label>
          <select
            id="report-month"
            value={month}
            onChange={(e) => setMonth(e.target.value)}
            disabled={downloading}
            className="mt-1.5 rounded-xl bg-paper/[0.06] px-3.5 py-2.5 text-base text-paper transition-colors hover:bg-paper/[0.09] disabled:opacity-50"
          >
            {months.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={onDownload}
          disabled={downloading}
          className="btn-primary"
        >
          {downloading ? "Generating" : "Download PDF"}
        </button>
      </div>

      {error && (
        <p role="alert" className="callout-danger mt-4">
          {error}
        </p>
      )}

      <p className="mt-4 text-micro text-faint">
        Totals only. No sender addresses or subject lines appear in the report.
      </p>
    </section>
  );
}

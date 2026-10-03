import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../services/api";
import RiskPill from "../components/RiskPill.jsx";
import Spinner from "../components/Spinner.jsx";
import useDocumentTitle from "../hooks/useDocumentTitle";
import { parseServerTime } from "../utils/time";

function formatWhen(value) {
  const parsed = parseServerTime(value);
  if (!parsed) return "Unknown date";
  return parsed.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function HistoryPage() {
  useDocumentTitle("Scan history");
  const [scans, setScans] = useState(null);
  const [error, setError] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api
      .get("/history")
      .then((data) => !cancelled && setScans(data))
      .catch((err) => !cancelled && setError(err.message || "The server did not respond."));
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  return (
    <main className="mx-auto max-w-3xl px-5 pb-24 pt-14 sm:px-6 sm:pt-20">
      <h1 className="text-display font-bold text-paper">Scan history</h1>
      <p className="mt-3 max-w-prose text-lead text-muted">
        Emails you have scanned from this browser. Reports stay available here so you can
        return to the advice later.
      </p>

      {error && (
        <p role="alert" className="callout-danger mt-8 items-center justify-between">
          <span className="text-paper">{error}</span>{" "}
          <button
            type="button"
            onClick={() => setReloadKey((k) => k + 1)}
            className="btn-secondary shrink-0 px-3.5 py-1.5"
          >
            Try again
          </button>
        </p>
      )}

      {!error && scans === null && (
        <div className="mt-10">
          <Spinner label="Loading your history" />
        </div>
      )}

      {!error && scans?.length === 0 && (
        <div className="surface mt-10 flex flex-col items-center px-6 py-12 text-center">
          <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-paper/[0.06] text-muted">
            <svg
              viewBox="0 0 24 24"
              className="h-6 w-6"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3" />
              <path d="M4.5 4.5v3h3" />
              <path d="M12 8v4l2.5 2" />
            </svg>
          </span>
          <p className="mt-4 font-semibold text-paper">Nothing scanned yet</p>
          <p className="mt-1.5 max-w-prose text-muted">
            Once you scan an email it will appear here with its verdict.
          </p>
          <Link to="/" className="btn-primary mt-6">
            Scan an email
          </Link>
        </div>
      )}

      {!error && scans?.length > 0 && (
        <ul className="surface mt-10 overflow-hidden">
          {scans.map((scan, index) => (
            <li
              key={scan.scan_id}
              className="motion-safe:animate-surface relative"
              // Rows appear in order. The delay stops growing after 12 rows
              // so a long history doesn't take ages to show.
              style={{ animationDelay: `${Math.min(index, 12) * 40}ms` }}
            >
              {/* Hairline between rows, inset to where the text starts. */}
              {index > 0 && (
                <span aria-hidden="true" className="absolute left-5 right-0 top-0 h-px bg-ink-edge/70" />
              )}
              <Link
                to={`/scan/${scan.scan_id}`}
                className="group flex items-center gap-4 px-5 py-3.5 transition-colors hover:bg-paper/[0.035] active:bg-paper/[0.06] sm:gap-5"
              >
                <span className="tabular hidden w-24 shrink-0 text-small text-faint sm:block">
                  {formatWhen(scan.created_at)}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-semibold text-paper">
                    {scan.email_subject || "Message with no subject"}
                  </span>
                  <span className="mt-0.5 block truncate text-small text-muted">
                    {scan.sender_address || "Sender not identified"}
                  </span>
                  {/* On a phone the date moves under the sender. */}
                  <span className="tabular mt-0.5 block text-micro text-faint sm:hidden">
                    {formatWhen(scan.created_at)}
                  </span>
                </span>
                <RiskPill level={scan.risk_level} status={scan.status} />
                <svg
                  viewBox="0 0 16 16"
                  className="h-4 w-4 shrink-0 text-faint transition-[color,transform] duration-200 group-hover:translate-x-0.5 group-hover:text-muted group-focus-visible:translate-x-0.5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M6 3.5 10.5 8 6 12.5" />
                </svg>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}

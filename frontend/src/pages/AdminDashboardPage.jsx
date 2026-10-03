import { useCallback, useEffect, useRef, useState } from "react";
import api from "../services/api";
import LoginMascot from "../components/LoginMascot.jsx";
import RiskLevelChart from "../components/charts/RiskLevelChart.jsx";
import ProviderCallsChart from "../components/charts/ProviderCallsChart.jsx";
import MonthlyReportPanel from "../components/MonthlyReportPanel.jsx";
import Spinner from "../components/Spinner.jsx";
import useDocumentTitle from "../hooks/useDocumentTitle";

export default function AdminDashboardPage() {
  useDocumentTitle("Admin");
  const [checkingSession, setCheckingSession] = useState(true);
  const [username, setUsername] = useState(null);

  useEffect(() => {
    api
      .get("/admin/me")
      .then((data) => setUsername(data.username))
      .catch(() => setUsername(null))
      .finally(() => setCheckingSession(false));
  }, []);

  if (checkingSession) {
    return (
      <main className="mx-auto max-w-3xl px-5 py-24 sm:px-6">
        <Spinner label="Checking your session" />
      </main>
    );
  }

  if (!username) return <AdminLoginForm onLoggedIn={setUsername} />;
  return <AdminDashboard username={username} onLoggedOut={() => setUsername(null)} />;
}

// How long after the last password keystroke the mascot opens its eyes.
const TYPING_IDLE_MS = 1500;

function AdminLoginForm({ onLoggedIn }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [typing, setTyping] = useState(false);
  const typingTimer = useRef(null);

  useEffect(() => () => clearTimeout(typingTimer.current), []);

  const noteTyping = () => {
    setTyping(true);
    clearTimeout(typingTimer.current);
    typingTimer.current = setTimeout(() => setTyping(false), TYPING_IDLE_MS);
  };

  // Only the password makes the mascot look away. The username isn't secret.
  const updateField = (name) => (value) => {
    setForm((f) => ({ ...f, [name]: value }));
    if (name === "password") noteTyping();
  };

  const onSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const data = await api.post("/admin/login", form);
      onLoggedIn(data.username);
    } catch (err) {
      setError(err.message || "The server did not respond.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="mx-auto max-w-4xl px-5 py-14 sm:px-6 sm:py-20">
      {/* Mascot on the left and the form on the right, centred together.
          Stacked on narrow screens. */}
      <div className="flex flex-col items-center gap-10 md:flex-row md:justify-center md:gap-16">
        <div className="motion-safe:animate-surface shrink-0">
          <LoginMascot eyesClosed={typing} />
        </div>

        <div
          className="surface motion-safe:animate-surface w-full max-w-[24rem] !rounded-3xl p-7 sm:p-8"
          style={{ animationDelay: "90ms" }}
        >
          <h1 className="text-display font-bold text-paper">Sign in</h1>
          <p className="mt-2 text-muted">This area is for administrators.</p>

          <form onSubmit={onSubmit} className="mt-8 space-y-4">
            <Field
              id="username"
              label="Username"
              type="text"
              autoComplete="username"
              value={form.username}
              onChange={updateField("username")}
            />
            <Field
              id="password"
              label="Password"
              type="password"
              autoComplete="current-password"
              value={form.password}
              onChange={updateField("password")}
            />

            {error && (
              <p role="alert" className="callout-danger">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="btn-primary !mt-6 w-full py-3"
            >
              {submitting ? "Signing in" : "Sign in"}
            </button>
          </form>
        </div>
      </div>
    </main>
  );
}

function Field({ id, label, type, autoComplete, value, onChange }) {
  return (
    <div>
      <label htmlFor={id} className="block text-small font-medium text-muted">
        {label}
      </label>
      <input
        id={id}
        type={type}
        required
        autoComplete={autoComplete}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        className="mt-1.5 w-full rounded-xl bg-paper/[0.06] px-3.5 py-3 text-base text-paper transition-[background-color,box-shadow] placeholder:text-faint hover:bg-paper/[0.08] focus:bg-ink-raised focus:shadow-[inset_0_0_0_1.5px_rgb(var(--paper)/0.6)] focus:outline-none"
      />
    </div>
  );
}

function AdminDashboard({ username, onLoggedOut }) {
  const [analytics, setAnalytics] = useState(null);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    try {
      setAnalytics(await api.get("/admin/analytics"));
    } catch (err) {
      setError(err.message || "Analytics could not be loaded.");
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const logout = async () => {
    try {
      await api.post("/admin/logout");
    } finally {
      onLoggedOut();
    }
  };

  const totalCalls = analytics?.provider_calls.reduce((sum, p) => sum + p.total_calls, 0) ?? 0;

  return (
    <main className="mx-auto max-w-4xl px-5 pb-24 pt-14 sm:px-6 sm:pt-20">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-display font-bold text-paper">Dashboard</h1>
        <p className="flex items-center gap-3 text-small text-muted">
          <span>Signed in as {username}.</span>{" "}
          <button type="button" onClick={logout} className="btn-secondary px-3.5 py-1.5">
            Sign out
          </button>
        </p>
      </div>

      {error && (
        <p role="alert" className="callout-danger mt-8 items-center justify-between">
          <span className="text-paper">{error}</span>{" "}
          <button type="button" onClick={load} className="btn-secondary shrink-0 px-3.5 py-1.5">
            Try again
          </button>
        </p>
      )}

      {!error && !analytics && (
        <div className="mt-12">
          <Spinner label="Loading activity" />
        </div>
      )}

      {analytics && (
        <>
          <section aria-labelledby="totals-heading" className="mt-10">
            <div className="flex items-center justify-between gap-4">
              <h2
                id="totals-heading"
                className="text-micro font-semibold uppercase tracking-[0.06em] text-faint"
              >
                Activity so far
              </h2>
              <button
                type="button"
                onClick={load}
                disabled={refreshing}
                className="btn-secondary px-3.5 py-1.5 disabled:opacity-50"
              >
                <svg
                  viewBox="0 0 16 16"
                  className={`h-3.5 w-3.5 ${refreshing ? "motion-safe:animate-spin" : ""}`}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9" />
                  <path d="M13.5 2.5v3h-3" />
                </svg>
                {refreshing ? "Refreshing" : "Refresh"}
              </button>
            </div>
            <dl className="mt-3 grid gap-4 sm:grid-cols-2">
              <Metric label="Emails scanned" value={analytics.scan_stats.total_scans} />
              <Metric label="Provider calls" value={totalCalls} />
            </dl>
          </section>

          <section aria-labelledby="verdicts-heading" className="surface mt-6 p-5 sm:p-6">
            <h2 id="verdicts-heading" className="text-title font-semibold text-paper">
              Verdicts
            </h2>
            <p className="mt-1.5 max-w-prose text-small text-muted">
              Select a verdict to see its exact share.
            </p>
            <div className="mt-6">
              <RiskLevelChart byRiskLevel={analytics.scan_stats.by_risk_level} />
            </div>
          </section>

          <section aria-labelledby="providers-heading" className="surface mt-6 p-5 sm:p-6">
            <h2 id="providers-heading" className="text-title font-semibold text-paper">
              Providers
            </h2>
            <p className="mt-1.5 max-w-prose text-small text-muted">
              How many times each service was called. Open a row for detail.
            </p>
            <div className="mt-5">
              <ProviderCallsChart providerCalls={analytics.provider_calls} />
            </div>
          </section>

          <MonthlyReportPanel />
        </>
      )}
    </main>
  );
}

function Metric({ label, value }) {
  return (
    <div className="surface px-5 py-4">
      <dt className="text-small font-medium text-muted">{label}</dt>
      <dd className="tabular mt-1 text-display font-bold text-paper">{value}</dd>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import api from "../services/api";
import useScanPolling from "../hooks/useScanPolling";
import useDocumentTitle from "../hooks/useDocumentTitle";
import useSectionShown from "../hooks/useSectionShown";
import ScanProgress from "../components/ScanProgress.jsx";
import Spinner from "../components/Spinner.jsx";
import CollapsiblePanel from "../components/CollapsiblePanel.jsx";
import ReportSection from "../components/ReportSection.jsx";
import VerdictScale from "../components/VerdictScale.jsx";
import AdvisoryPanel from "../components/AdvisoryPanel.jsx";
import IndicatorCard from "../components/IndicatorCard.jsx";
import SeverityLegend from "../components/SeverityLegend.jsx";
import TechnicalDetails from "../components/TechnicalDetails.jsx";
import { groupSignalsByCategory, sourceForSignal, titleForSignal } from "../utils/signals";

const CATEGORIES = [
  { key: "headers", label: "Sender" },
  { key: "url", label: "Links" },
  { key: "attachment", label: "Attachments" },
];

export default function ReportPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { status, errorMessage, elapsedMs, timedOut } = useScanPolling(scanId);
  const [report, setReport] = useState(null);
  const [reportError, setReportError] = useState(null);
  useDocumentTitle(
    status === "COMPLETE" && report ? `${report.scan.risk_level} scan report` : "Scanning"
  );

  useEffect(() => {
    if (status !== "COMPLETE") return undefined;
    let cancelled = false;
    api
      .get(`/scan/${scanId}`)
      .then((data) => !cancelled && setReport(data))
      .catch((err) => !cancelled && setReportError(err.message || "The report could not be loaded."));
    return () => {
      cancelled = true;
    };
  }, [status, scanId]);

  if (status !== "COMPLETE" || !report) {
    return (
      <main className="mx-auto max-w-3xl px-5 pb-24 pt-14 sm:px-6 sm:pt-20">
        <h1 className="text-display font-bold text-paper">Examining the email</h1>
        <div className="mt-10">
          <ScanProgress
            status={status}
            elapsedMs={elapsedMs}
            errorMessage={errorMessage || reportError}
            timedOut={timedOut}
            onRetry={() => navigate("/")}
          />
          {status === "COMPLETE" && !reportError && (
            <div className="mt-8">
              <Spinner label="Preparing the report" />
            </div>
          )}
        </div>
      </main>
    );
  }

  const {
    scan,
    header_result: headerResult,
    url_results: urlResults,
    attachment_results: attachmentResults,
    advisory,
  } = report;
  const grouped = groupSignalsByCategory(scan.signals);
  const findingCount = (scan.signals || []).length;

  return (
    <main className="mx-auto max-w-5xl px-5 pb-24 pt-10 sm:px-6 sm:pt-14">
      {/* Verdict first, since everyone needs it. */}
      <div className="motion-safe:animate-surface">
        <VerdictScale
          level={scan.risk_level}
          score={scan.risk_score}
          checksDone={4 - (scan.unavailable_providers || []).length}
        />
      </div>

      {/* Findings on the left and advice on the right, stacked on narrow
          screens. Both panels can be minimised. */}
      <div className="mt-6 grid items-start gap-6 lg:grid-cols-2">
        <CollapsiblePanel
          title="Findings"
          aside={`${findingCount} ${findingCount === 1 ? "finding" : "findings"}`}
        >
          <p className="max-w-prose text-small text-muted">
            Each finding adds to the score. Open one to read the full explanation.
          </p>
          <div className="mt-6 space-y-7">
            {CATEGORIES.map(({ key, label }) => (
              <FindingsGroup key={key} title={label} signals={grouped[key]} />
            ))}
          </div>
        </CollapsiblePanel>

        <CollapsiblePanel title="Security Advice" delay={90}>
          <AdvisoryPanel steps={advisory} />
        </CollapsiblePanel>
      </div>

      <div className="mt-6">
        <TechnicalDetails
          headerResult={headerResult}
          urlResults={urlResults}
          attachmentResults={attachmentResults}
        />
      </div>

      <ReportSection
        title="How the score is banded"
        headingId="section-bands"
        className="surface mt-6 p-5 sm:p-6"
      >
        <SeverityLegend level={scan.risk_level} score={scan.risk_score} />
      </ReportSection>

      <nav className="mt-12 flex flex-wrap justify-center gap-3">
        <Link to="/" className="btn-primary">
          Scan another email
        </Link>
        <Link to="/history" className="btn-secondary">
          View history
        </Link>
      </nav>
    </main>
  );
}

function FindingsGroup({ title, signals }) {
  const shown = useSectionShown();
  const count = signals?.length || 0;

  return (
    <section>
      <h3 className="flex items-center gap-2 text-micro font-semibold uppercase tracking-[0.06em] text-faint">
        {title}
        <span className="tabular rounded-full bg-paper/[0.07] px-1.5 py-px text-micro font-semibold normal-case tracking-normal text-muted">
          {count}
        </span>
      </h3>
      {count === 0 ? (
        <p className="mt-2 flex items-center gap-2.5 rounded-xl bg-paper/[0.035] px-4 py-3 text-small text-faint">
          <svg
            viewBox="0 0 16 16"
            className="h-3.5 w-3.5 shrink-0 text-risk-safe"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="m3.5 8.5 3 3 6-7" />
          </svg>
          Nothing of concern here.
        </p>
      ) : (
        <div className="mt-2 space-y-1">
          {signals.map((signal, index) => (
            <div
              key={`${signal.category}-${signal.signal}-${JSON.stringify(signal.evidence)}`}
              className={shown ? "motion-safe:animate-surface" : "opacity-0"}
              style={{ animationDelay: `${index * 60}ms` }}
            >
              <IndicatorCard
                title={titleForSignal(signal.signal)}
                explanation={signal.explanation}
                source={sourceForSignal(signal.signal)}
                points={signal.points}
              />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

const STEPS = [
  { key: "parsing", label: "Reading the message", detail: "Opening the file safely" },
  { key: "headers", label: "Checking the sender", detail: "Is the address genuine?" },
  { key: "urls", label: "Inspecting links", detail: "Where do they really lead?" },
  { key: "attachments", label: "Scanning attachments", detail: "Looking for malware" },
  { key: "scoring", label: "Weighing the evidence", detail: "Working out the risk" },
];

/** The three middle checks run at the same time on the server, so they
 * all show as active together. Stepping through them one by one would
 * suggest something that isn't happening. */
function stepState(stepKey, status) {
  if (stepKey === "parsing") {
    if (status === "PARSING") return "active";
    return ["ANALYZING_HEADERS", "SCORING", "COMPLETE"].includes(status) ? "done" : "waiting";
  }
  if (["headers", "urls", "attachments"].includes(stepKey)) {
    if (status === "ANALYZING_HEADERS") return "active";
    return ["SCORING", "COMPLETE"].includes(status) ? "done" : "waiting";
  }
  if (status === "SCORING") return "active";
  return status === "COMPLETE" ? "done" : "waiting";
}

function formatElapsed(ms) {
  const total = Math.floor(ms / 1000);
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
}

export default function ScanProgress({ status, elapsedMs, errorMessage, timedOut, onRetry }) {
  if (status === "FAILED" || timedOut) {
    return (
      <div role="alert" className="surface motion-safe:animate-surface p-6">
        <span className="flex h-10 w-10 items-center justify-center rounded-full bg-risk-danger/[0.12] text-risk-danger">
          <svg
            viewBox="0 0 20 20"
            className="h-5 w-5"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            aria-hidden="true"
          >
            <path d="M10 5.5v5.2" />
            <path d="M10 14.2h.01" strokeWidth="2.4" />
          </svg>
        </span>
        <h2 className="mt-4 text-title font-semibold text-paper">This scan did not finish</h2>
        <p className="mt-2 max-w-prose text-muted">
          {timedOut
            ? "The scan is taking longer than expected. Nothing has been saved."
            : errorMessage || "Something went wrong while examining this email."}
        </p>
        <button type="button" onClick={onRetry} className="btn-primary mt-6">
          Start again
        </button>
      </div>
    );
  }

  const states = STEPS.map((step) => stepState(step.key, status));
  const done = states.filter((s) => s === "done").length;

  return (
    <div>
      <div className="flex items-baseline justify-between">
        <p className="text-muted">This usually takes under a minute.</p>
        <p className="tabular rounded-full bg-paper/[0.07] px-2.5 py-0.5 text-small font-medium text-muted">
          {formatElapsed(elapsedMs)}
        </p>
      </div>

      {/* Overall progress. It only moves when a stage actually finishes,
          so it never gets ahead of the server. */}
      <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-paper/[0.08]" aria-hidden="true">
        <div
          className="h-full rounded-full bg-paper transition-[width] duration-700 ease-spring"
          style={{ width: `${Math.max(4, (done / STEPS.length) * 100)}%` }}
        />
      </div>

      <p className="sr-only" aria-live="polite">
        {done} of {STEPS.length} checks complete
      </p>

      <ol className="surface mt-8 overflow-hidden">
        {STEPS.map((step, index) => {
          const state = states[index];
          return (
            <li
              key={step.key}
              className={`relative overflow-hidden px-5 py-4 transition-colors duration-300 ${
                state === "active" ? "bg-paper/[0.03]" : ""
              }`}
            >
              {/* Hairline between rows, starting where the text starts. */}
              {index > 0 && (
                <span aria-hidden="true" className="absolute left-[3.75rem] right-0 top-0 h-px bg-ink-edge/70" />
              )}
              {/* A light sweeps along the row while that check is running. */}
              {state === "active" && (
                <span
                  aria-hidden="true"
                  className="motion-safe:animate-sweep absolute inset-y-0 left-0 w-1/3 bg-gradient-to-r from-transparent via-paper/[0.05] to-transparent"
                />
              )}
              <div className="relative flex items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <StepMark state={state} />
                  <div>
                    <p
                      className={
                        state === "waiting" ? "text-faint" : "font-semibold text-paper"
                      }
                    >
                      {step.label}
                    </p>
                    <p className={`mt-0.5 text-small ${state === "waiting" ? "text-faint/70" : "text-muted"}`}>
                      {step.detail}
                    </p>
                  </div>
                </div>
                <p
                  className={`shrink-0 text-micro font-medium ${
                    state === "done" ? "text-risk-safe" : "text-muted"
                  }`}
                >
                  {state === "done" ? "Done" : state === "active" ? "Working" : ""}
                </p>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/** Status icon for one step: a dot while waiting, a spinning arc while
 * running, and a tick that draws itself when done. */
function StepMark({ state }) {
  return (
    <span className="relative flex h-6 w-6 shrink-0 items-center justify-center" aria-hidden="true">
      {state === "waiting" && <span className="h-2 w-2 rounded-full bg-paper/[0.15]" />}
      {state === "active" && (
        <svg viewBox="0 0 24 24" className="h-6 w-6 motion-safe:animate-spin" fill="none">
          <circle cx="12" cy="12" r="9" className="stroke-paper/15" strokeWidth="2.4" />
          <path d="M12 3a9 9 0 0 1 9 9" className="stroke-paper" strokeWidth="2.4" strokeLinecap="round" />
        </svg>
      )}
      {state === "done" && (
        <svg viewBox="0 0 24 24" className="h-6 w-6 animate-pop" fill="none">
          <circle cx="12" cy="12" r="11" className="fill-risk-safe" />
          <path
            d="m7.5 12.3 3 3 6-6.3"
            pathLength="1"
            stroke="white"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="stroke-draw animate-draw"
            style={{ animationDelay: "120ms" }}
          />
        </svg>
      )}
    </span>
  );
}

import { useState } from "react";
import useSectionShown from "../hooks/useSectionShown";

// The backend always sends both the prevention step and its "already
// happened" version. The question below decides which ones are shown.
const AFTER_THE_FACT = new Set([
  "MALICIOUS_ATTACHMENT_ALREADY_OPENED",
  "MALICIOUS_URL_ALREADY_CLICKED",
]);

/** The security advice for a scan, as numbered cards.
 *
 * The heading comes from the panel around it. The steps appear one after
 * another when the panel scrolls into view. Each one can be ticked off;
 * the ticks are kept in state for this visit only and never saved.
 */
export default function AdvisoryPanel({ steps }) {
  const [alreadyInteracted, setAlreadyInteracted] = useState(null);
  const [completed, setCompleted] = useState(() => new Set());
  const shown = useSectionShown();

  if (!steps || steps.length === 0) {
    return <p className="text-muted">No advice was recorded for this scan.</p>;
  }

  const hasConditional = steps.some((s) => AFTER_THE_FACT.has(s.triggered_by));
  const visible = steps.filter(
    (step) => !AFTER_THE_FACT.has(step.triggered_by) || alreadyInteracted === true
  );
  const doneCount = visible.filter((step) => completed.has(step.step_order)).length;

  const toggle = (order) =>
    setCompleted((prev) => {
      const next = new Set(prev);
      if (next.has(order)) next.delete(order);
      else next.add(order);
      return next;
    });

  return (
    <div>
      {hasConditional && (
        <fieldset className="mb-6 rounded-xl bg-paper/[0.04] p-4">
          <legend className="sr-only">Have you already opened or clicked anything?</legend>
          <p className="font-medium text-paper">
            Have you already opened the attachment or clicked a link in this email?
          </p>
          <div className="segment-track mt-3 w-fit">
            {[
              { label: "Yes", value: true },
              { label: "No", value: false },
            ].map((option) => (
              <label
                key={option.label}
                className={`relative cursor-pointer rounded-lg px-6 py-1.5 text-small transition-[color,background-color,box-shadow] duration-200 has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-paper/75 ${
                  alreadyInteracted === option.value
                    ? "font-semibold text-paper [background-color:rgb(var(--segment-thumb))] [box-shadow:var(--segment-shadow)]"
                    : "font-medium text-muted hover:text-paper"
                }`}
              >
                <input
                  type="radio"
                  name="already-interacted"
                  className="peer sr-only"
                  checked={alreadyInteracted === option.value}
                  onChange={() => setAlreadyInteracted(option.value)}
                />
                {option.label}
              </label>
            ))}
          </div>
          {alreadyInteracted === true && (
            <p className="motion-safe:animate-surface mt-3 text-small text-muted">
              Recovery steps have been added below.
            </p>
          )}
        </fieldset>
      )}

      <div className="mb-4 flex items-center gap-3">
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-paper/[0.08]" aria-hidden="true">
          <div
            className="h-full rounded-full bg-risk-safe transition-[width] duration-700 ease-spring"
            style={{ width: `${visible.length ? (doneCount / visible.length) * 100 : 0}%` }}
          />
        </div>
        <p className="tabular shrink-0 text-micro font-medium text-muted" aria-live="polite">
          {doneCount} of {visible.length} done
        </p>
      </div>

      <ol className="space-y-2">
        {visible.map((step, index) => {
          const done = completed.has(step.step_order);
          return (
            <li
              key={step.step_order}
              className={`rounded-xl bg-paper/[0.04] transition-colors hover:bg-paper/[0.06] ${
                shown ? "motion-safe:animate-surface" : "opacity-0"
              }`}
              style={{ animationDelay: `${index * 80}ms` }}
            >
              <label
                className={`press flex cursor-pointer gap-4 rounded-xl p-4 active:scale-[0.99] ${
                  done ? "opacity-60" : ""
                }`}
              >
                <input
                  type="checkbox"
                  className="peer sr-only"
                  checked={done}
                  onChange={() => toggle(step.step_order)}
                  aria-label={`Mark step ${index + 1} as done: ${step.step_title}`}
                />
                <StepCheck number={index + 1} done={done} />
                <div className="min-w-0">
                  <p
                    className={`font-semibold text-paper decoration-muted/70 decoration-1 transition-colors ${
                      done ? "line-through" : ""
                    }`}
                  >
                    {step.step_title}
                  </p>
                  <p className="mt-1.5 max-w-prose text-muted [text-wrap:pretty]">{step.step_detail}</p>
                </div>
              </label>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/** The step number. It turns into a tick when the step is done, and takes
 * its focus ring from the hidden checkbox before it (`peer`). */
function StepCheck({ number, done }) {
  return (
    <span
      aria-hidden="true"
      className={`tabular relative flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-micro font-semibold transition-[background-color,color,box-shadow] duration-300 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-paper/75 ${
        done
          ? "bg-risk-safe text-white"
          : "text-muted shadow-[inset_0_0_0_1.5px_rgb(var(--ink-edge))]"
      }`}
    >
      {done ? (
        <svg viewBox="0 0 24 24" className="h-4 w-4 animate-pop" fill="none">
          <path
            d="m6 12.5 4 4 8-9"
            pathLength="1"
            stroke="currentColor"
            strokeWidth="2.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="stroke-draw animate-draw"
          />
        </svg>
      ) : (
        number
      )}
    </span>
  );
}

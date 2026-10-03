import { useState } from "react";

/** One finding. Closed, it shows a title and one line of explanation.
 * Opened, it shows the full explanation and where the finding came from.
 *
 * The body opens by animating its grid row from 0fr to 1fr, as in
 * CollapsiblePanel. It's set to invisible when closed so nothing inside
 * can be tabbed to.
 */
export default function IndicatorCard({ title, explanation, source, points }) {
  const [open, setOpen] = useState(false);

  return (
    <div
      className={`rounded-xl transition-colors duration-200 ${
        open ? "bg-paper/[0.05]" : "hover:bg-paper/[0.035]"
      }`}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="group flex w-full items-start gap-4 rounded-xl py-3 pl-4 pr-3 text-left"
      >
        <span className="min-w-0 flex-1">
          <span className="flex items-baseline gap-3">
            <span className="font-medium text-paper">{title}</span>
            {typeof points === "number" && (
              <span className="tabular shrink-0 rounded-full bg-paper/[0.07] px-1.5 py-px text-micro font-semibold text-muted">
                +{points}
              </span>
            )}
          </span>
          {/* Hidden from screen readers while the full text is open, so the
              explanation isn't read out twice. */}
          <span
            aria-hidden={open}
            className={`mt-1 block truncate text-small text-muted transition-opacity duration-200 ${
              open ? "h-0 opacity-0" : "opacity-100"
            }`}
          >
            {explanation}
          </span>
        </span>
        <span className="flex shrink-0 items-center gap-1.5 pt-0.5 text-small text-muted transition-colors group-hover:text-paper">
          {open ? "Less" : "More"}
          <svg
            viewBox="0 0 16 16"
            className={`h-3.5 w-3.5 transition-transform duration-500 ease-spring ${open ? "rotate-180" : ""}`}
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M3.5 6 8 10.5 12.5 6" />
          </svg>
        </span>
      </button>

      <div
        className={`grid transition-[grid-template-rows,opacity,visibility] duration-500 ease-spring ${
          open ? "visible grid-rows-[1fr] opacity-100" : "invisible grid-rows-[0fr] opacity-0"
        }`}
      >
        <div className="min-h-0 overflow-hidden">
          <div className="pb-4 pl-4 pr-3">
            <p className="max-w-prose text-muted [text-wrap:pretty]">{explanation}</p>
            {source && <p className="mt-2 text-micro text-faint">Reported by {source}</p>}
          </div>
        </div>
      </div>
    </div>
  );
}

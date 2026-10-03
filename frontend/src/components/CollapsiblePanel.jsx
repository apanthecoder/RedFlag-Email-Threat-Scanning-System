import { useId, useState } from "react";
import useInView from "../hooks/useInView";
import { SectionShownContext } from "../hooks/useSectionShown";

/** A report card that can be minimised and expanded.
 *
 * The whole header is the toggle: a button inside the heading, with
 * aria-expanded. The body animates its grid row between 0fr and 1fr,
 * which opens it to its natural height without measuring anything. It's
 * a transition rather than a keyframe animation, so a second click
 * halfway through reverses it from where it is. When collapsed it's also
 * invisible, so its controls can't be tabbed to.
 *
 * The panel animates in when scrolled into view and passes that on through
 * SectionShownContext, so the list inside can follow.
 */
export default function CollapsiblePanel({ title, aside, defaultOpen = true, delay = 0, children }) {
  const [open, setOpen] = useState(defaultOpen);
  const [ref, shown] = useInView({ threshold: 0.1 });
  const id = useId();
  const headingId = `${id}-heading`;
  const contentId = `${id}-content`;

  return (
    <section
      ref={ref}
      aria-labelledby={headingId}
      className={`surface ${shown ? "motion-safe:animate-surface" : "opacity-0"}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <h2 id={headingId}>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={contentId}
          onClick={() => setOpen((o) => !o)}
          className="group flex w-full items-center gap-3 rounded-2xl px-5 py-4 text-left"
        >
          <span className="text-title font-semibold text-paper">{title}</span>
          {aside && (
            <span className="tabular rounded-full bg-paper/[0.07] px-2.5 py-0.5 text-micro font-medium text-muted">
              {aside}
            </span>
          )}
          <span className="ml-auto flex shrink-0 items-center gap-1.5 text-small text-muted transition-colors group-hover:text-paper">
            {open ? "Minimise" : "Expand"}
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-paper/[0.07] transition-colors group-hover:bg-paper/[0.12]">
              <svg
                viewBox="0 0 16 16"
                className={`h-3 w-3 transition-transform duration-500 ease-spring ${open ? "rotate-180" : ""}`}
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M3.5 6 8 10.5 12.5 6" />
              </svg>
            </span>
          </span>
        </button>
      </h2>

      <div
        id={contentId}
        className={`grid transition-[grid-template-rows,opacity,visibility] duration-500 ease-spring ${
          open ? "visible grid-rows-[1fr] opacity-100" : "invisible grid-rows-[0fr] opacity-0"
        }`}
      >
        <div className="min-h-0 overflow-hidden">
          <div className="mx-5 border-t border-ink-edge/70 pb-5 pt-4">
            <SectionShownContext.Provider value={shown}>{children}</SectionShownContext.Provider>
          </div>
        </div>
      </div>
    </section>
  );
}

import useInView from "../hooks/useInView";
import { SectionShownContext } from "../hooks/useSectionShown";

/** A titled section of the report.
 *
 * When it scrolls into view, the line under the heading draws from left
 * to right and the content fades in. Items inside can call
 * useSectionShown() to animate in at the same moment. Pass a class like
 * "surface p-5" in className to put it on a card.
 */
export default function ReportSection({ title, headingId, className = "", children }) {
  const [ref, shown] = useInView({ threshold: 0.15 });

  return (
    <section ref={ref} aria-labelledby={headingId} className={className}>
      <h2 id={headingId} className="text-title font-semibold text-paper">
        {title}
      </h2>

      <div className="mt-3 h-px bg-ink-edge/70" aria-hidden="true">
        <div
          className="h-px origin-left bg-muted/60 transition-transform duration-700 ease-spring"
          style={{ transform: `scaleX(${shown ? 1 : 0})` }}
        />
      </div>

      <SectionShownContext.Provider value={shown}>
        <div
          className={`mt-6 transition-[opacity,transform] duration-500 ease-spring ${
            shown ? "opacity-100" : "translate-y-2 opacity-0"
          }`}
        >
          {children}
        </div>
      </SectionShownContext.Provider>
    </section>
  );
}

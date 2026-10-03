import useInView from "../hooks/useInView";

/** Scroll-in animation. As the section comes into view, a vertical line
 * draws down its left edge and the content fades in beside it.
 *
 * Left-hand lines are how this interface groups content anyway, so
 * stacked sections look like one line being drawn down the page.
 *
 * Pass rule={false} for the fade without the line.
 */
export default function Reveal({ children, rule = true, delay = 0, className = "" }) {
  const [ref, inView] = useInView();

  return (
    <div ref={ref} className={`relative ${rule ? "pl-6" : ""} ${className}`}>
      {rule && (
        <span
          aria-hidden="true"
          className="absolute left-0 top-0 w-px origin-top bg-ink-edge transition-transform duration-700 ease-spring"
          style={{
            height: "100%",
            transform: `scaleY(${inView ? 1 : 0})`,
            transitionDelay: `${delay}ms`,
          }}
        />
      )}
      <div
        className="transition-[opacity,transform] duration-700 ease-spring"
        style={{
          opacity: inView ? 1 : 0,
          transform: inView ? "none" : "translateY(12px)",
          transitionDelay: `${delay + (rule ? 120 : 0)}ms`,
        }}
      >
        {children}
      </div>
    </div>
  );
}

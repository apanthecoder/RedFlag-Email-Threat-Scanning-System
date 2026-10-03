const LEVELS = {
  SAFE: { chip: "bg-risk-safe/[0.12] text-risk-safe", dot: "bg-risk-safe" },
  SUSPICIOUS: { chip: "bg-risk-caution/[0.12] text-risk-caution", dot: "bg-risk-caution" },
  DANGEROUS: { chip: "bg-risk-danger/[0.12] text-risk-danger", dot: "bg-risk-danger" },
};

/** Small verdict label for list rows.
 *
 * It has a minimum width so the verdicts in a list line up in one column.
 * The word gives the meaning and the colour backs it up.
 *
 * A scan that didn't finish has no verdict, so it gets a plain dashed
 * label with no risk colour.
 */
const CHIP =
  "inline-flex min-w-[6.5rem] shrink-0 items-center justify-center gap-1.5 rounded-full px-2.5 py-1 text-micro font-semibold";

export default function RiskPill({ level, status }) {
  if (status && status !== "COMPLETE") {
    const failed = status === "FAILED";
    return (
      <span
        className={`${CHIP} border border-dashed font-medium ${
          failed ? "border-muted/50 text-muted" : "border-ink-edge text-faint"
        }`}
      >
        {failed ? "Error" : "Scanning"}
      </span>
    );
  }

  const style = LEVELS[level] || { chip: "bg-paper/[0.06] text-faint", dot: "bg-faint" };
  const label = level ? level.charAt(0) + level.slice(1).toLowerCase() : "Unknown";

  return (
    <span className={`${CHIP} ${style.chip}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} aria-hidden="true" />
      {label}
    </span>
  );
}

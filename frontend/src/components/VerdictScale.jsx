import { useEffect, useState } from "react";
import useCountUp from "../hooks/useCountUp";
import useDecode from "../hooks/useDecode";

/** Top of the report: the 0-100 risk score, placed on the scale of bands
 * that decided the verdict.
 *
 * A badge would only give the verdict. The scale also shows where the
 * score landed and how close it was to the next band. The bands match
 * backend/config.py (0-24, 25-59, 60-100); change both together.
 *
 * Most of the page's animation is here. The verdict word decodes, the
 * marker glides to the score and settles without overshooting, and one
 * ring pulses where it stops. It all runs once, on load. Each verdict also
 * has its own icon, so the meaning never rests on colour alone.
 */
const BANDS = [
  {
    level: "SAFE",
    from: 0,
    to: 24,
    color: "bg-risk-safe",
    text: "text-risk-safe",
    ring: "border-risk-safe",
    glow: "from-risk-safe/[0.14]",
  },
  {
    level: "SUSPICIOUS",
    from: 25,
    to: 59,
    color: "bg-risk-caution",
    text: "text-risk-caution",
    ring: "border-risk-caution",
    glow: "from-risk-caution/[0.14]",
  },
  {
    level: "DANGEROUS",
    from: 60,
    to: 100,
    color: "bg-risk-danger",
    text: "text-risk-danger",
    ring: "border-risk-danger",
    glow: "from-risk-danger/[0.14]",
  },
];

const NEEDLE_MS = 1000;

const HEADLINE = {
  SAFE: "No threats detected",
  SUSPICIOUS: "Verify before you act",
  DANGEROUS: "Do not interact with this email",
};

const CHECKS_TOTAL = 4;

export default function VerdictScale({ level, score, checksDone = CHECKS_TOTAL }) {
  const band = BANDS.find((b) => b.level === level) || BANDS[1];
  const [needle, setNeedle] = useState(0);
  const [landed, setLanded] = useState(false);
  // The number counts up while the marker moves, so both finish together.
  const shownScore = useCountUp(score ?? 0, true, { duration: NEEDLE_MS });
  const decodedLevel = useDecode(level);

  useEffect(() => {
    // Under reduced motion there's no glide: the marker starts at the
    // score, like the number does.
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      setNeedle(score ?? 0);
      setLanded(true);
      return undefined;
    }
    // Render one frame at zero, then move to the real score.
    setLanded(false);
    const id = requestAnimationFrame(() => setNeedle(score ?? 0));
    const done = setTimeout(() => setLanded(true), NEEDLE_MS);
    return () => {
      cancelAnimationFrame(id);
      clearTimeout(done);
    };
  }, [score]);

  return (
    <section
      aria-labelledby="verdict-heading"
      className="surface relative isolate overflow-hidden !rounded-3xl px-6 pb-7 pt-7 sm:px-9 sm:pt-9"
    >
      {/* A wash of the verdict colour from the top of the card. */}
      <div
        aria-hidden="true"
        className={`pointer-events-none absolute inset-x-0 top-0 -z-10 h-56 bg-gradient-to-b ${band.glow} to-transparent`}
      />

      <p
        className={`flex items-center gap-2 font-mono text-small font-semibold tracking-wider ${band.text}`}
        aria-label={level}
      >
        <VerdictIcon level={band.level} />
        <span aria-hidden="true">{decodedLevel || " "}</span>
      </p>
      <h1 id="verdict-heading" className="mt-3 text-display font-bold text-paper">
        {HEADLINE[level] || HEADLINE.SUSPICIOUS}
      </h1>

      <div className="mt-10">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-2">
          <span className={`tabular text-score font-bold ${band.text}`}>{shownScore}</span>
          <span className="text-muted">out of 100</span>
          {/* Only shown when a check couldn't run. A low score then means
              the email wasn't fully checked, which is why the verdict is
              held at Suspicious. */}
          {checksDone < CHECKS_TOTAL && (
            <span className="tabular rounded-full bg-paper/[0.07] px-2.5 py-0.5 text-micro font-medium text-muted">
              {checksDone} of {CHECKS_TOTAL} checks ran
            </span>
          )}
        </div>

        {/* The track: three bands sized to their ranges, with the marker
            at the score. The numbers carry the meaning; colour helps. */}
        <div className="mt-6">
          <div className="relative">
            <div className="relative flex h-2.5 w-full gap-[3px]">
              {BANDS.map((b) => (
                <div
                  key={b.level}
                  className={`h-full rounded-full ${b.color} ${
                    b.level === level ? "opacity-100" : "opacity-25"
                  } transition-opacity duration-500`}
                  style={{ width: `${b.to - b.from + 1}%` }}
                />
              ))}
            </div>

            {/* The marker sits across the track and glides to the score. */}
            <div
              className="absolute top-1/2 transition-[left] ease-spring"
              style={{ left: `${needle}%`, transitionDuration: `${NEEDLE_MS}ms` }}
            >
              <div className="relative -translate-x-1/2 -translate-y-1/2">
                {landed && (
                  <span
                    aria-hidden="true"
                    className={`absolute left-1/2 top-1/2 -ml-2.5 -mt-2.5 h-5 w-5 rounded-full border-2 ${band.ring} motion-safe:animate-ping-once motion-reduce:hidden`}
                  />
                )}
                <div className="h-[22px] w-[22px] rounded-full bg-white shadow-[0_0_0_0.5px_rgb(0_0_0/0.08),0_2px_6px_rgb(0_0_0/0.25),0_6px_14px_rgb(0_0_0/0.12)]" />
              </div>
            </div>
          </div>

          <div className="h-4" />

          <div className="flex justify-between text-micro text-faint">
            {BANDS.map((b) => (
              <span key={b.level} className={b.level === level ? `font-semibold ${band.text}` : undefined}>
                {b.level === "SAFE" ? `0` : b.from}
                {b.level === "DANGEROUS" ? "–100" : `–${b.to}`} {b.level.toLowerCase()}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/** A tick in a shield for safe, a triangle for suspicious, a cross in an
 * octagon for dangerous: the shapes people already read as OK, caution
 * and stop. */
function VerdictIcon({ level }) {
  const common = {
    viewBox: "0 0 20 20",
    className: "h-[18px] w-[18px] shrink-0",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.7,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };

  if (level === "SAFE") {
    return (
      <svg {...common}>
        <path d="M10 2.2 3.8 4.6v4.6c0 4 2.6 7 6.2 8.6 3.6-1.6 6.2-4.6 6.2-8.6V4.6L10 2.2Z" />
        <path d="m7.2 10 2 2 3.8-4.2" />
      </svg>
    );
  }
  if (level === "DANGEROUS") {
    return (
      <svg {...common}>
        <path d="M6.9 2.5h6.2l4.4 4.4v6.2l-4.4 4.4H6.9l-4.4-4.4V6.9l4.4-4.4Z" />
        <path d="m7.6 7.6 4.8 4.8m0-4.8-4.8 4.8" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <path d="M8.6 3.3a1.6 1.6 0 0 1 2.8 0l6.1 10.9a1.6 1.6 0 0 1-1.4 2.4H3.9a1.6 1.6 0 0 1-1.4-2.4L8.6 3.3Z" />
      <path d="M10 8v3.4" />
      <path d="M10 14.1h.01" strokeWidth="2.2" />
    </svg>
  );
}

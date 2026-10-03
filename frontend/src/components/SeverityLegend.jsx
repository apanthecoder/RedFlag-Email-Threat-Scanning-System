import { useState } from "react";
import useSectionShown from "../hooks/useSectionShown";

/** The three score bands as boxes you can select.
 *
 * Each box shows its band's part of the 0-100 scale with this email's
 * score marked, so you can see where the score sits against every band.
 * Selecting a box shows what the band means and what to do. The email's
 * own band is selected first and labelled "This email".
 *
 * The ranges copy backend/config.py (RISK_BAND_SAFE_MAX = 24,
 * RISK_BAND_SUSPICIOUS_MAX = 59), and the advice sums up the verdict steps
 * in backend/services/advisory.py. Change them together.
 */
const BANDS = [
  {
    level: "SAFE",
    name: "Safe",
    from: 0,
    to: 24,
    dot: "bg-risk-safe",
    text: "text-risk-safe",
    selected: "bg-risk-safe/[0.08] shadow-[inset_0_0_0_1.5px_rgb(var(--risk-safe))]",
    meaning: "Nothing of concern was found.",
    advice:
      "Handle the email as normal, but stay cautious with unexpected payment or sign-in requests. A clean result is not a guarantee.",
  },
  {
    level: "SUSPICIOUS",
    name: "Suspicious",
    from: 25,
    to: 59,
    dot: "bg-risk-caution",
    text: "text-risk-caution",
    selected: "bg-risk-caution/[0.08] shadow-[inset_0_0_0_1.5px_rgb(var(--risk-caution))]",
    meaning: "Something needs a person to check it before you act.",
    advice:
      "Do not pay, sign in or download anything from it until you have confirmed the sender through contact details you already hold.",
  },
  {
    level: "DANGEROUS",
    name: "Dangerous",
    from: 60,
    to: 100,
    dot: "bg-risk-danger",
    text: "text-risk-danger",
    selected: "bg-risk-danger/[0.08] shadow-[inset_0_0_0_1.5px_rgb(var(--risk-danger))]",
    meaning: "Strong evidence of phishing or malware.",
    advice:
      "Do not open its attachments or click its links. Report it to your IT contact and do not forward it to colleagues.",
  },
];

export default function SeverityLegend({ level, score }) {
  const shown = useSectionShown();
  const verdictBand = BANDS.find((b) => b.level === level);
  const [selected, setSelected] = useState(verdictBand ? verdictBand.level : "SAFE");
  const active = BANDS.find((b) => b.level === selected) || BANDS[0];
  const hasScore = typeof score === "number";

  return (
    <div>
      <p className="max-w-prose text-muted">
        Every finding adds points to a score out of 100, and the score falls into one of three
        bands. Select a band to see what it means.
      </p>

      <div role="group" aria-label="Score bands" className="mt-6 grid gap-3 sm:grid-cols-3">
        {BANDS.map((band, index) => {
          const isSelected = band.level === selected;
          return (
            // The entrance animation goes on this wrapper, not the button.
            // On the button, the animation's last frame would cancel the
            // press feedback.
            <div
              key={band.level}
              className={shown ? "motion-safe:animate-surface" : "opacity-0"}
              style={{ animationDelay: `${index * 90}ms` }}
            >
              <button
                type="button"
                onClick={() => setSelected(band.level)}
                aria-pressed={isSelected}
                className={`press h-full w-full rounded-xl p-4 text-left ${
                  isSelected ? band.selected : "bg-paper/[0.04] hover:bg-paper/[0.07]"
                }`}
              >
                <span className="flex items-center gap-2">
                  <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${band.dot}`} aria-hidden="true" />
                  <span className="font-semibold text-paper">{band.name}</span>
                  {band.level === level && (
                    <span className={`ml-auto rounded-full px-2 py-px text-micro font-semibold ${band.text} shadow-[inset_0_0_0_1px_currentColor]`}>
                      This email
                    </span>
                  )}
                </span>
                <span className="tabular mt-1 block text-micro text-faint">
                  Score {band.from}–{band.to}
                </span>

                {/* The full 0-100 scale, with this band highlighted and the
                    email's score marked. */}
                <span className="relative mt-4 block h-1.5 rounded-full bg-paper/[0.1]" aria-hidden="true">
                  <span
                    className={`absolute inset-y-0 rounded-full ${band.dot}`}
                    style={{ left: `${band.from}%`, width: `${band.to - band.from + 1}%` }}
                  />
                  {hasScore && (
                    <span
                      className="absolute -top-1 h-3.5 w-0.5 -translate-x-1/2 rounded-full bg-paper"
                      style={{ left: `${Math.min(Math.max(score, 0), 100)}%` }}
                    />
                  )}
                </span>
              </button>
            </div>
          );
        })}
      </div>

      {/* Keyed on the selection so the panel animates in again. */}
      <div
        key={active.level}
        aria-live="polite"
        className="motion-safe:animate-surface mt-3 rounded-xl bg-paper/[0.04] p-4"
      >
        <p className={`text-small font-semibold ${active.text}`}>
          {active.name} · score {active.from}–{active.to}
        </p>
        <p className="mt-1 text-paper">{active.meaning}</p>
        <p className="mt-2 text-small text-muted">{active.advice}</p>
        {active.level === level && hasScore && (
          <p className="mt-3 text-micro text-faint">
            This email scored {score}
            {score < active.from || score > active.to
              ? ". Its verdict was set by a conclusive check rather than by the score alone."
              : "."}
          </p>
        )}
      </div>
    </div>
  );
}

import { useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";

// Same verdict colours as the rest of the interface. The classes carry the
// theme colour (light or dark); the hex values are only a fallback.
const COLORS = { SAFE: "#30D158", SUSPICIOUS: "#FF9F0A", DANGEROUS: "#FF453A" };
const FILL = { SAFE: "fill-risk-safe", SUSPICIOUS: "fill-risk-caution", DANGEROUS: "fill-risk-danger" };
const TEXT = { SAFE: "text-risk-safe", SUSPICIOUS: "text-risk-caution", DANGEROUS: "text-risk-danger" };
const DOT = { SAFE: "bg-risk-safe", SUSPICIOUS: "bg-risk-caution", DANGEROUS: "bg-risk-danger" };
const ORDER = ["SAFE", "SUSPICIOUS", "DANGEROUS"];

/** Scans by verdict, as a donut chart with a legend.
 *
 * Clicking a slice or a legend row shows that verdict's exact count and
 * share in the middle. It's a click, not a hover, so it works on touch
 * screens and with a keyboard.
 */
export default function RiskLevelChart({ byRiskLevel }) {
  const [selected, setSelected] = useState(null);

  const data = ORDER.map((level) => ({ name: level, value: byRiskLevel?.[level] || 0 })).filter(
    (d) => d.value > 0
  );
  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return <p className="text-small text-muted">No completed scans yet.</p>;
  }

  const active = data.find((d) => d.name === selected) || null;
  const headline = active ? active.value : total;
  const caption = active
    ? `${active.name.toLowerCase()} · ${((active.value / total) * 100).toFixed(0)}%`
    : total === 1
      ? "scan"
      : "scans";

  return (
    <div className="flex flex-col items-center gap-8 sm:flex-row sm:items-center">
      <div className="relative h-52 w-52 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={64}
              outerRadius={88}
              paddingAngle={3}
              cornerRadius={6}
              stroke="none"
              isAnimationActive={false}
              onClick={(entry) => setSelected((s) => (s === entry.name ? null : entry.name))}
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={COLORS[entry.name]}
                  opacity={!selected || selected === entry.name ? 1 : 0.25}
                  className={`${FILL[entry.name]} cursor-pointer transition-opacity duration-300`}
                />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={`tabular text-display font-bold ${active ? TEXT[active.name] : "text-paper"}`}
          >
            {headline}
          </span>
          <span className="mt-0.5 text-micro text-muted">{caption}</span>
        </div>
      </div>

      {/* The legend does the same selection, and can be read as a list
          and used with a keyboard. */}
      <ul className="w-full min-w-0 flex-1 space-y-1">
        {ORDER.filter((level) => byRiskLevel?.[level]).map((level) => {
          const value = byRiskLevel[level];
          const isSelected = selected === level;
          return (
            <li key={level}>
              <button
                type="button"
                onClick={() => setSelected((s) => (s === level ? null : level))}
                aria-pressed={isSelected}
                className={`press flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left ${
                  isSelected ? "bg-paper/[0.07] text-paper" : "text-muted hover:bg-paper/[0.04] hover:text-paper"
                }`}
              >
                <span
                  className={`h-2.5 w-2.5 shrink-0 rounded-full transition-opacity ${DOT[level]}`}
                  style={{ opacity: !selected || isSelected ? 1 : 0.3 }}
                  aria-hidden="true"
                />
                <span className="flex-1 text-small font-medium">
                  {level.charAt(0) + level.slice(1).toLowerCase()}
                </span>
                <span className="tabular text-small">{value}</span>
                <span className="tabular w-12 text-right text-micro text-faint">
                  {((value / total) * 100).toFixed(0)}%
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

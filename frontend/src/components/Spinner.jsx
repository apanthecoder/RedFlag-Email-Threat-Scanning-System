/** Loading indicator: the familiar eight-spoke activity wheel, with a label
 * that says what's happening. Under reduced motion the wheel holds still
 * and the label carries the meaning. */
const SPOKES = Array.from({ length: 8 }, (_, i) => i);

export default function Spinner({ label = "Loading" }) {
  return (
    <div className="flex items-center gap-3 text-small text-muted">
      <svg
        viewBox="0 0 24 24"
        className="h-5 w-5 shrink-0 motion-safe:animate-spokes"
        aria-hidden="true"
      >
        {SPOKES.map((i) => (
          <line
            key={i}
            x1="12"
            y1="3"
            x2="12"
            y2="7.5"
            className="stroke-current"
            strokeWidth="2.2"
            strokeLinecap="round"
            // Each spoke is fainter than the one before it, so the wheel
            // looks like it trails as it turns.
            opacity={1 - i * 0.11}
            transform={`rotate(${-i * 45} 12 12)`}
          />
        ))}
      </svg>
      <span>{label}</span>
    </div>
  );
}

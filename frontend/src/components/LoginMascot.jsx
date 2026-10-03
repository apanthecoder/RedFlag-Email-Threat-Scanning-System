import { useEffect, useRef, useState } from "react";

/** The little guard on the admin sign-in page.
 *
 * It carries the RedFlag flag, its eyes follow the pointer around the
 * page, and it shuts them while you type your password. That's the joke:
 * even the mascot won't watch you type a password.
 *
 * It's decoration only, so screen readers skip it. The eyes only move
 * when the user moves the pointer, and it leans a little toward the
 * pointer too, so its movement always answers something you did rather
 * than looping on its own. The lean and the blinking are turned off under
 * reduced motion.
 *
 * The visor stays dark and the eyes stay white in both light and dark
 * mode, so the face always reads the same way.
 */
const VIEW_W = 200;
const VIEW_H = 230;
const EYES = [
  { id: "left", cx: 80, cy: 112 },
  { id: "right", cx: 120, cy: 112 },
];
const EYE_RADIUS = 14;
const PUPIL_RADIUS = 6;
const PUPIL_TRAVEL = 6; // how far a pupil may move from the eye's centre
const FULL_TRAVEL_DISTANCE_PX = 140; // pointer distance at which the pupil reaches its edge
const MAX_LEAN_DEG = 4;
const FULL_LEAN_DISTANCE_PX = 500; // sideways pointer distance for the full lean
const EYE_WHITE = "#F5F5F7";
const PUPIL = "#0A0A0C";

export default function LoginMascot({ eyesClosed = false }) {
  const svgRef = useRef(null);
  const [pupils, setPupils] = useState({ left: { x: 0, y: 0 }, right: { x: 0, y: 0 } });
  const [blinking, setBlinking] = useState(false);
  const [lean, setLean] = useState(0);

  // Follow the pointer. Positions are worked out in the SVG's own units,
  // so it works at any size.
  useEffect(() => {
    let frame = null;
    let pointer = null;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    const update = () => {
      frame = null;
      const svg = svgRef.current;
      if (!svg || !pointer) return;
      const rect = svg.getBoundingClientRect();
      const scale = rect.width / VIEW_W;

      const next = {};
      EYES.forEach((eye) => {
        const dx = pointer.x - (rect.left + eye.cx * scale);
        const dy = pointer.y - (rect.top + eye.cy * scale);
        // Close to the eye, the pupil moves less, so it doesn't jump to the
        // edge when the cursor crosses the face.
        const reach = Math.min(1, Math.hypot(dx, dy) / FULL_TRAVEL_DISTANCE_PX);
        const angle = Math.atan2(dy, dx);
        next[eye.id] = {
          x: Math.cos(angle) * PUPIL_TRAVEL * reach,
          y: Math.sin(angle) * PUPIL_TRAVEL * reach,
        };
      });
      setPupils(next);

      if (!reducedMotion) {
        const centreX = rect.left + rect.width / 2;
        const sideways = Math.max(-1, Math.min(1, (pointer.x - centreX) / FULL_LEAN_DISTANCE_PX));
        setLean(sideways * MAX_LEAN_DEG);
      }
    };

    const onMove = (event) => {
      pointer = { x: event.clientX, y: event.clientY };
      if (!frame) frame = requestAnimationFrame(update);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      window.removeEventListener("pointermove", onMove);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  // Blink now and then so it doesn't look frozen.
  useEffect(() => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return undefined;

    let waitTimer;
    let openTimer;
    const schedule = () => {
      waitTimer = setTimeout(() => {
        setBlinking(true);
        openTimer = setTimeout(() => {
          setBlinking(false);
          schedule();
        }, 140);
      }, 3000 + Math.random() * 3000);
    };
    schedule();
    return () => {
      clearTimeout(waitTimer);
      clearTimeout(openTimer);
    };
  }, []);

  const closed = eyesClosed || blinking;

  return (
    <div className="relative w-40 md:w-56" aria-hidden="true">
      {/* Speech bubble, shown only while typing (not during a blink). */}
      <div
        className={`surface absolute -top-2 right-0 !rounded-xl px-3 py-1.5 text-micro font-medium text-muted transition-[opacity,transform] duration-300 ease-spring md:-right-4 ${
          eyesClosed ? "translate-y-0 scale-100 opacity-100" : "translate-y-1 scale-95 opacity-0"
        }`}
        style={{ transformOrigin: "bottom left" }}
      >
        Not looking.
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        className="h-auto w-full"
      >
        {/* Ground shadow */}
        <ellipse cx="100" cy="218" rx="46" ry="6" className="fill-paper" opacity="0.08" />

        {/* Everything above the ground leans from the feet. */}
        <g
          style={{
            transform: `rotate(${lean}deg)`,
            transformBox: "view-box",
            transformOrigin: "100px 205px",
            transition: "transform 700ms cubic-bezier(0.32, 0.72, 0, 1)",
          }}
        >
          {/* The flag: same mark as the logo, on an antenna */}
          <path d="M100 62V20" className="stroke-muted" strokeWidth="3" strokeLinecap="round" />
          <path d="M100 21h30l-6 9 6 9h-30z" className="fill-risk-danger" />

          {/* Body */}
          <rect
            x="40"
            y="60"
            width="120"
            height="140"
            rx="58"
            className="fill-ink-raised stroke-ink-edge"
            strokeWidth="3"
          />
          {/* Visor: a lighter band the eyes sit in */}
          <rect x="56" y="90" width="88" height="44" rx="22" style={{ fill: "rgb(var(--visor))" }} />

          {/* Feet */}
          <ellipse cx="78" cy="203" rx="14" ry="7" className="fill-ink-edge" />
          <ellipse cx="122" cy="203" rx="14" ry="7" className="fill-ink-edge" />

          {/* Eyes */}
          {EYES.map((eye) => {
            const pupil = pupils[eye.id];
            return (
              <g key={eye.id}>
                <g
                  style={{
                    transform: closed ? "scaleY(0.08)" : "scaleY(1)",
                    transformBox: "fill-box",
                    transformOrigin: "center",
                    transition: "transform 140ms ease-out",
                  }}
                >
                  <circle cx={eye.cx} cy={eye.cy} r={EYE_RADIUS} fill={EYE_WHITE} />
                  <circle
                    cx={eye.cx}
                    cy={eye.cy}
                    r={PUPIL_RADIUS}
                    fill={PUPIL}
                    style={{
                      transform: `translate(${pupil.x}px, ${pupil.y}px)`,
                      transition: "transform 60ms linear",
                    }}
                  />
                </g>
                {/* Closed-eye curve, faded in as the eye shuts */}
                <path
                  d={`M${eye.cx - 12} ${eye.cy} q12 8 24 0`}
                  fill="none"
                  stroke={EYE_WHITE}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  style={{ opacity: closed ? 1 : 0, transition: "opacity 120ms ease-out" }}
                />
              </g>
            );
          })}

          {/* Mouth */}
          <path
            d="M90 152q10 8 20 0"
            fill="none"
            className="stroke-muted"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
        </g>
      </svg>
    </div>
  );
}

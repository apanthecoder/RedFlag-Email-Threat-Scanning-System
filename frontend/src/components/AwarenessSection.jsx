import { useCallback, useEffect, useRef, useState } from "react";
import useInView from "../hooks/useInView";
import useCountUp from "../hooks/useCountUp";
import Reveal from "./Reveal.jsx";

/** The "Why this matters" slider on the upload page.
 *
 * Every figure comes from a named published report, and its source and
 * period are shown with it so anyone can check it. A security tool
 * quoting numbers nobody can trace would undercut itself.
 *
 * Malaysian figures come first. The client is a Selangor SME, and national
 * incident data fits their situation better than global breach reports.
 *
 * One box with one idea per slide, moved with the arrow buttons, arrow
 * keys, a swipe or the progress bar. Slides never advance on their own,
 * because people read at different speeds.
 *
 * The slides sit side by side on one strip that a spring moves. On a touch
 * screen the strip follows the finger exactly, resists at the first and
 * last slide, and on release carries on at the finger's speed to whichever
 * slide the flick was heading for. The spring always starts from where the
 * strip is on screen, so it can be caught and turned around mid-flight.
 */
const FACTS = [
  {
    figure: "68% to 86%",
    label: "Phishing as a share of reported fraud in Malaysia, rising each quarter through 2025.",
    source: "MyCERT quarterly summaries, Q1 to Q4 2025",
  },
  {
    figure: "78%",
    label:
      "Of all cyber incidents recorded in Malaysia that quarter were fraud, far ahead of data breaches and intrusions.",
    source: "MyCERT, Q4 2025",
  },
  {
    figure: "US$3.0bn",
    label:
      "Lost to business email compromise in 2025 across 24,768 reports, roughly US$123,000 per incident. These attacks target invoices and payment details.",
    source: "FBI Internet Crime Complaint Center, Internet Crime Report 2025",
  },
  {
    figure: "60%",
    label:
      "Of data breaches involved a person being deceived or making a mistake, rather than a purely technical failure.",
    source: "Verizon Data Breach Investigations Report 2025",
  },
];

const PRECAUTIONS = [
  {
    title: "Check the address, not the name",
    detail:
      "The sender name is free text and anyone can set it to anything. The address after it is far harder to fake. A message signed by a supplier you know, sent from an address you do not recognise, is worth stopping for.",
  },
  {
    title: "Treat urgency as the warning sign it is",
    detail:
      "Deadlines, threats of closure and requests to act before checking are how an attacker stops you thinking. A genuine supplier will wait while you confirm.",
  },
  {
    title: "Verify on a number you already have",
    detail:
      "If a message asks you to pay, sign in, or open something unexpected, confirm it through contact details you already hold. Never use a phone number or link contained in the message itself.",
  },
  {
    title: "Report it, even when you are not sure",
    detail:
      "A low bar for reporting is what stops one opened attachment becoming an office-wide problem. Nobody is blamed for flagging a message that turns out to be genuine.",
  },
];

const HABIT_SOURCE =
  "Guidance published by the UK National Cyber Security Centre and the US Cybersecurity and Infrastructure Security Agency for small organisations.";

const SLIDES = [
  { kind: "stat", group: "The numbers" },
  ...FACTS.map((fact) => ({ kind: "fact", group: "What the reporting shows", ...fact })),
  ...PRECAUTIONS.map((habit, i) => ({
    kind: "habit",
    group: `Four habits that stop most of it · ${i + 1} of ${PRECAUTIONS.length}`,
    ...habit,
  })),
  { kind: "cta", group: "Before you act" },
];

const LAST = SLIDES.length - 1;

// How far a finger must move before the strip commits to a horizontal drag.
// Below it the touch could still be the start of a vertical scroll.
const DRAG_THRESHOLD_PX = 10;
// Spring settings, in Apple's terms. Response is roughly how long the move
// takes, in seconds. Damping 1 settles with no overshoot; a flick gets a
// little bounce because the finger threw it.
const RESPONSE_S = 0.42;
const FLICK_DAMPING = 0.86;
const FLICK_SPEED_PX_S = 300;
// How far a flick coasts, the same way scrolling slows down.
const DECELERATION = 0.998;
const VELOCITY_WINDOW_MS = 100;

/** Resistance past the first or last slide. The further you pull, the less
 * the strip follows. */
function rubberband(overshoot, dimension, constant = 0.55) {
  return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
}

function prefersReducedMotion() {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

export default function AwarenessSection() {
  const [index, setIndex] = useState(0);
  const indexRef = useRef(0);
  const [boxRef, boxInView] = useInView({ threshold: 0.4 });
  const viewportRef = useRef(null);
  const trackRef = useRef(null);
  // The strip's live position and speed, in px and px/s. Kept outside React
  // state so a moving strip doesn't re-render the page every frame.
  const spring = useRef({ x: 0, v: 0, target: 0, damping: 1, frame: null });
  const drag = useRef(null);

  // Counts up each time the first slide is on screen, including when you
  // come back to it.
  const phishingShare = useCountUp(85.6, boxInView && index === 0, { decimals: 1 });

  const slideWidth = () => viewportRef.current?.clientWidth || 1;

  const paint = (x) => {
    if (trackRef.current) trackRef.current.style.transform = `translate3d(${x}px, 0, 0)`;
  };

  const stop = () => {
    const s = spring.current;
    if (s.frame) cancelAnimationFrame(s.frame);
    s.frame = null;
  };

  // Moves the strip to `target`. If it's already moving, only the target
  // changes, so the current speed carries into the new move instead of
  // stopping dead.
  const animateTo = useCallback((target, { velocity, damping = 1 } = {}) => {
    const s = spring.current;
    s.target = target;
    s.damping = damping;
    if (velocity !== undefined) s.v = velocity;

    if (prefersReducedMotion()) {
      stop();
      s.x = target;
      s.v = 0;
      paint(target);
      return;
    }
    if (s.frame) return;

    let last = performance.now();
    const tick = (now) => {
      const dt = Math.min((now - last) / 1000, 1 / 30);
      last = now;
      const stiffness = ((2 * Math.PI) / RESPONSE_S) ** 2;
      const friction = (4 * Math.PI * s.damping) / RESPONSE_S;
      const substeps = 4;
      const h = dt / substeps;
      for (let i = 0; i < substeps; i += 1) {
        const accel = -stiffness * (s.x - s.target) - friction * s.v;
        s.v += accel * h;
        s.x += s.v * h;
      }
      if (Math.abs(s.x - s.target) < 0.4 && Math.abs(s.v) < 8) {
        s.x = s.target;
        s.v = 0;
        s.frame = null;
        paint(s.x);
        return;
      }
      paint(s.x);
      s.frame = requestAnimationFrame(tick);
    };
    s.frame = requestAnimationFrame(tick);
  }, []);

  const goTo = useCallback(
    (target, options) => {
      const clamped = Math.max(0, Math.min(LAST, target));
      indexRef.current = clamped;
      setIndex(clamped);
      animateTo(-clamped * slideWidth(), options);
    },
    [animateTo]
  );

  // Keep the strip lined up when the box changes width.
  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return undefined;
    const observer = new ResizeObserver(() => {
      if (drag.current?.active) return;
      const s = spring.current;
      const target = -indexRef.current * slideWidth();
      if (s.frame) {
        s.target = target;
      } else {
        s.x = target;
        s.target = target;
        paint(target);
      }
    });
    observer.observe(viewport);
    return () => {
      observer.disconnect();
      stop();
    };
  }, []);

  const step = (delta) => {
    const target = indexRef.current + delta;
    if (target < 0 || target > LAST) return;
    goTo(target);
  };

  const onKeyDown = (event) => {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      step(1);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      step(-1);
    }
  };

  // Dragging is for touch and pen. With a mouse, pressing and moving
  // selects text as usual, and the arrows do the navigating.
  const onPointerDown = (event) => {
    if (event.pointerType === "mouse" || !event.isPrimary) return;
    // Catch the strip wherever it is, mid-flight included.
    stop();
    drag.current = {
      id: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: spring.current.x,
      active: false,
      history: [{ x: event.clientX, t: event.timeStamp }],
    };
  };

  const onPointerMove = (event) => {
    const d = drag.current;
    if (!d || d.id !== event.pointerId) return;
    const dx = event.clientX - d.startX;
    const dy = event.clientY - d.startY;

    if (!d.active) {
      if (Math.abs(dy) > DRAG_THRESHOLD_PX && Math.abs(dy) > Math.abs(dx)) {
        // A vertical scroll. Let the page have it and settle the strip.
        drag.current = null;
        animateTo(spring.current.target);
        return;
      }
      if (Math.abs(dx) < DRAG_THRESHOLD_PX) return;
      d.active = true;
      // Track from here, so the strip doesn't jump by the threshold.
      d.startX = event.clientX;
      d.originX = spring.current.x;
      d.history = [{ x: event.clientX, t: event.timeStamp }];
      event.currentTarget.setPointerCapture?.(event.pointerId);
      return;
    }

    const width = slideWidth();
    const min = -LAST * width;
    let x = d.originX + (event.clientX - d.startX);
    if (x > 0) x = rubberband(x, width);
    else if (x < min) x = min - rubberband(min - x, width);

    spring.current.x = x;
    paint(x);
    d.history.push({ x: event.clientX, t: event.timeStamp });
    while (d.history.length > 2 && event.timeStamp - d.history[0].t > VELOCITY_WINDOW_MS) {
      d.history.shift();
    }
  };

  const onPointerEnd = (event) => {
    const d = drag.current;
    if (!d || d.id !== event.pointerId) return;
    drag.current = null;

    if (!d.active) {
      // A tap, not a drag. Finish whatever move was under way.
      animateTo(spring.current.target);
      return;
    }

    const first = d.history[0];
    const last = d.history[d.history.length - 1];
    const elapsed = last.t - first.t;
    const velocity = elapsed > 0 ? ((last.x - first.x) / elapsed) * 1000 : 0;

    // Where the strip would coast to, then the slide nearest that point,
    // at most one away from the current one.
    const projection = ((velocity / 1000) * DECELERATION) / (1 - DECELERATION);
    const nearest = Math.round(-(spring.current.x + projection) / slideWidth());
    const current = indexRef.current;
    const target = Math.max(current - 1, Math.min(current + 1, nearest));

    goTo(target, {
      velocity,
      damping: Math.abs(velocity) > FLICK_SPEED_PX_S ? FLICK_DAMPING : 1,
    });
  };

  const slide = SLIDES[index];

  return (
    <Reveal rule={false} className="mt-16">
      <section
        ref={boxRef}
        aria-roledescription="carousel"
        aria-labelledby="why-heading"
        tabIndex={0}
        onKeyDown={onKeyDown}
        className="surface overflow-hidden"
      >
        <header className="mx-5 flex items-start justify-between gap-4 border-b border-ink-edge/70 py-4">
          <div>
            <h2 id="why-heading" className="text-small font-semibold text-paper">
              Why this matters
            </h2>
            <p className="mt-0.5 max-w-prose text-micro text-muted">
              Phishing is not a rare event that happens to other companies. It is the most
              reported kind of online fraud in Malaysia, and its share has risen every quarter.
            </p>
          </div>

          <div className="flex shrink-0 items-center gap-1.5">
            <span className="tabular mr-1.5 text-micro text-faint" aria-hidden="true">
              {index + 1} / {SLIDES.length}
            </span>
            <ArrowButton direction="prev" disabled={index === 0} onClick={() => step(-1)} />
            <ArrowButton direction="next" disabled={index === LAST} onClick={() => step(1)} />
          </div>
        </header>

        <div
          ref={viewportRef}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerEnd}
          onPointerCancel={onPointerEnd}
          className="touch-pan-y overflow-hidden"
        >
          <div ref={trackRef} className="flex will-change-transform">
            {SLIDES.map((s, i) => (
              <div
                key={i}
                role="group"
                aria-roledescription="slide"
                aria-label={`${i + 1} of ${SLIDES.length}`}
                aria-hidden={i !== index}
                className={`w-full shrink-0 px-5 py-5 transition-opacity duration-300 ${
                  i === index ? "opacity-100" : "opacity-40"
                }`}
              >
                <p className="text-micro font-medium text-faint">{s.group}</p>
                <SlideBody slide={s} phishingShare={phishingShare} />
              </div>
            ))}
          </div>
        </div>

        {/* Progress bar that also jumps to any slide. Each segment is a
            tall button so it's easy to hit, with a thin bar inside. */}
        <div className="flex gap-1 px-5 pb-3">
          {SLIDES.map((s, i) => (
            <button
              key={i}
              type="button"
              onClick={() => goTo(i)}
              aria-label={`Go to slide ${i + 1}: ${s.group}`}
              aria-current={i === index ? "step" : undefined}
              className="group flex-1 py-2.5"
            >
              <span
                className={`block h-1 rounded-full transition-colors duration-300 ${
                  i === index
                    ? "bg-paper"
                    : i < index
                      ? "bg-paper/35"
                      : "bg-paper/[0.12] group-hover:bg-paper/30"
                }`}
              />
            </button>
          ))}
        </div>

        <p className="sr-only" aria-live="polite">
          Slide {index + 1} of {SLIDES.length}: {slide.group}
        </p>
      </section>
    </Reveal>
  );
}

function SlideBody({ slide, phishingShare }) {
  if (slide.kind === "stat") {
    return (
      <figure className="mt-2 max-w-prose">
        <p className="tabular text-score font-bold text-risk-caution">
          {phishingShare}
          <span className="text-display font-semibold">%</span>
        </p>
        <figcaption className="mt-3 text-muted">
          of fraud incidents reported to Malaysia&rsquo;s national response team in the last
          quarter of 2025 were phishing: 1,259 cases out of 1,471.
        </figcaption>
        <p className="mt-2 text-micro text-faint">
          MyCERT, CyberSecurity Malaysia. Cyber Incident Quarterly Summary Report, Q4 2025.
        </p>
      </figure>
    );
  }

  if (slide.kind === "fact") {
    return (
      <div className="mt-2 max-w-prose">
        <p className="tabular text-display font-bold text-paper">{slide.figure}</p>
        <p className="mt-3 text-muted">{slide.label}</p>
        <p className="mt-2 text-micro text-faint">{slide.source}</p>
      </div>
    );
  }

  if (slide.kind === "habit") {
    return (
      <div className="mt-2 max-w-prose">
        <p className="text-title font-semibold text-paper">{slide.title}</p>
        <p className="mt-2 text-muted">{slide.detail}</p>
        <p className="mt-3 text-micro text-faint">{HABIT_SOURCE}</p>
      </div>
    );
  }

  return (
    <div className="mt-2 max-w-prose">
      <p className="text-title font-semibold text-paper">Check before you act, not after</p>
      <p className="mt-2 text-muted">
        If a message asks you to pay, sign in, or open a file you were not expecting, scan it
        here first. You will get the findings and the steps to take, written plainly.
      </p>
    </div>
  );
}

/** Uses aria-disabled instead of disabled. A disabled button loses focus,
 * so a keyboard user pressing Next on the last slide would be thrown back
 * to the top of the page. */
function ArrowButton({ direction, disabled, onClick }) {
  const isPrev = direction === "prev";
  return (
    <button
      type="button"
      onClick={disabled ? undefined : onClick}
      aria-disabled={disabled}
      aria-label={isPrev ? "Previous slide" : "Next slide"}
      className="press flex h-8 w-8 items-center justify-center rounded-full bg-paper/[0.07] text-paper hover:bg-paper/[0.12] aria-disabled:cursor-default aria-disabled:opacity-30 aria-disabled:hover:bg-paper/[0.07] aria-disabled:active:scale-100"
    >
      <svg
        viewBox="0 0 16 16"
        className="h-3.5 w-3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d={isPrev ? "M10 3.5 5.5 8l4.5 4.5" : "M6 3.5 10.5 8 6 12.5"} />
      </svg>
    </button>
  );
}

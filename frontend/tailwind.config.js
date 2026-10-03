/** @type {import('tailwindcss').Config} */

// Every colour is a CSS variable holding "R G B" channels, set in
// src/index.css. The variables change with the system light/dark setting,
// so one class (bg-ink, text-paper) works in both appearances and opacity
// modifiers like bg-paper/10 still work.
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

// Apple's sheet curve. It starts fast and settles without overshoot, which
// is the closest a CSS curve gets to a critically damped spring.
const SPRING = "cubic-bezier(0.32, 0.72, 0, 1)";

export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  future: {
    // Hover styles only apply on devices that can really hover, so a tap
    // on a phone doesn't leave a button stuck in its hover state.
    hoverOnlyWhenSupported: true,
  },
  theme: {
    extend: {
      colors: {
        // ink is the background family, paper the text. In dark mode ink is
        // near black and paper near white; in light mode they swap. The
        // three risk colours stay the only strong colours on screen.
        ink: {
          DEFAULT: token("ink"),
          raised: token("ink-raised"),
          edge: token("ink-edge"),
          hover: token("ink-hover"),
        },
        paper: token("paper"),
        muted: token("muted"),
        faint: token("faint"),
        // Verdict colours. Used for risk and nothing else.
        risk: {
          safe: token("risk-safe"),
          caution: token("risk-caution"),
          danger: token("risk-danger"),
        },
      },
      fontFamily: {
        // The platform's own UI font: SF Pro on Apple devices, Segoe UI on
        // Windows, Roboto on Android. It ships tuned spacing for every size.
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "'SF Pro Text'",
          "'Segoe UI Variable Text'",
          "'Segoe UI'",
          "system-ui",
          "Roboto",
          "'Helvetica Neue'",
          "Arial",
          "sans-serif",
        ],
        mono: ["ui-monospace", "'SF Mono'", "'Cascadia Mono'", "Consolas", "monospace"],
      },
      fontSize: {
        // Letter spacing changes with size: slightly open on small text,
        // tighter as text grows. Line height gets tighter as size grows.
        micro: ["0.75rem", { lineHeight: "1.1rem", letterSpacing: "0.01em" }],
        small: ["0.875rem", { lineHeight: "1.35rem", letterSpacing: "-0.003em" }],
        base: ["1rem", { lineHeight: "1.55rem", letterSpacing: "-0.006em" }],
        lead: ["1.125rem", { lineHeight: "1.7rem", letterSpacing: "-0.01em" }],
        title: ["1.375rem", { lineHeight: "1.75rem", letterSpacing: "-0.017em" }],
        display: [
          "clamp(2rem, 1.4rem + 2.4vw, 2.75rem)",
          { lineHeight: "1.08", letterSpacing: "-0.025em" },
        ],
        score: ["4rem", { lineHeight: "1", letterSpacing: "-0.04em" }],
      },
      maxWidth: {
        prose: "68ch",
      },
      borderRadius: {
        // Cards use 2xl. Rows and controls inside them use xl or lg, so
        // nested corners stay roughly concentric.
        "4xl": "2rem",
      },
      transitionTimingFunction: {
        spring: SPRING,
      },
      keyframes: {
        sweep: {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(100%)" },
        },
        surface: {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        // A line moving down the drop zone while the file uploads, like a
        // page going through a scanner.
        scanline: {
          "0%": { top: "0%", opacity: "0" },
          "10%": { opacity: "1" },
          "90%": { opacity: "1" },
          "100%": { top: "100%", opacity: "0" },
        },
        // Draws an SVG stroke from nothing; paired with pathLength="1".
        draw: {
          from: { strokeDashoffset: "1" },
          to: { strokeDashoffset: "0" },
        },
        // One ring that pulses where the score marker stops.
        "ping-once": {
          "0%": { transform: "scale(0.6)", opacity: "0.9" },
          "100%": { transform: "scale(3.2)", opacity: "0" },
        },
        wave: {
          "0%, 100%": { transform: "skewY(0deg) scaleX(1)" },
          "30%": { transform: "skewY(-5deg) scaleX(0.94)" },
          "65%": { transform: "skewY(3deg) scaleX(0.98)" },
        },
        // Opacity only. A transform here would break position: fixed
        // elements inside the page.
        fade: {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        // Settles straight into place. No overshoot, because nothing the
        // user did threw it there.
        pop: {
          from: { transform: "scale(0.7)", opacity: "0" },
          to: { transform: "scale(1)", opacity: "1" },
        },
        // The activity indicator turns in eight steps, one per spoke.
        spokes: {
          to: { transform: "rotate(360deg)" },
        },
      },
      animation: {
        sweep: "sweep 1.6s cubic-bezier(0.4, 0, 0.2, 1) infinite",
        surface: `surface 520ms ${SPRING} both`,
        scanline: "scanline 1.4s cubic-bezier(0.4, 0, 0.2, 1) infinite",
        draw: "draw 420ms cubic-bezier(0.65, 0, 0.35, 1) both",
        "ping-once": "ping-once 900ms cubic-bezier(0, 0, 0.2, 1) both",
        wave: "wave 900ms ease-in-out",
        fade: "fade 260ms ease-out both",
        pop: `pop 420ms ${SPRING} both`,
        spokes: "spokes 0.9s steps(8) infinite",
      },
    },
  },
  plugins: [],
};
